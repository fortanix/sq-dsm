//! Fortanix Self-Defending KMS
//!
//! This module implements the necessary logic to use secrets stored inside
//! Fortanix DSM for low-level signing and decryption operations, given proper
//! credentials.
//!
//! # Env variables for authentication with DSM
//!
//! - `FORTANIX_API_ENDPOINT`
//! - `FORTANIX_API_KEY`
//! - `FORTANIX_PKCS12_ID`, absolute path for a PKCS12 file (.pfx or .p12)
//! - `FORTANIX_APP_UUID`, required for certificate-based authentication
//!
//! # Proxy configuration
//!
//! The connection with DSM can be set through an http proxy. This crate
//! follows the `http_proxy` / `no_proxy` environment variables convention,
//! i.e., if `http_proxy` is set and the DSM API endpoint is not in
//! `no_proxy`, then a connection through said proxy is established.

use core::fmt::Display;
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Error, Result};
use http::uri::Uri;
use hyper::client::{Client as HyperClient, ProxyConfig};
use hyper::net::HttpsConnector;
use hyper_native_tls::native_tls::{Identity, TlsConnector};
use hyper_native_tls::NativeTlsClient;
use ipnetwork::IpNetwork;
use log::info;
use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, ApprovalStatus, DecryptRequest,
    DecryptResponse, DigestAlgorithm, EllipticCurve as ApiCurve, KeyLinks,
    KeyOperations, ObjectType, RsaEncryptionPaddingPolicy, RsaEncryptionPolicy,
    RsaOptions, RsaSignaturePaddingPolicy, RsaSignaturePolicy, SignRequest,
    SignResponse, Sobject, SobjectDescriptor, SobjectRequest,
};
use sdkms::operations::Operation;
use sdkms::{Error as DsmError, PendingApproval, SdkmsClient as DsmClient};
use semver::{Version, VersionReq};
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::mpi::{
    Ciphertext as MpiCiphertext, ProtectedMPI, PublicKey as MpiPublic,
    SecretKeyMaterial as MpiSecret, Signature as MpiSignature, MPI,
};
use sequoia_openpgp::crypto::{ecdh, Decryptor, SessionKey, Signer};
use sequoia_openpgp::packet::key::{
    Key4, KeyRole as SequoiaKeyRole, PrimaryRole, PublicParts, SecretParts,
    SubordinateRole, UnspecifiedRole,
};
use sequoia_openpgp::packet::prelude::SecretKeyMaterial;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Key, UserID};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{
    Curve as SequoiaCurve, Features, HashAlgorithm, KeyFlags,
    PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm, Timestamp,
};
use sequoia_openpgp::{Cert, Packet};
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

mod der;

/// DsmAgent implements [Signer] and [Decryptor] with secrets stored inside
/// Fortanix DSM.
///
///   [Decryptor]: ../../crypto/trait.Decryptor.html
///   [Signer]: ../../crypto/trait.Signer.html
pub struct DsmAgent {
    credentials: Credentials,
    descriptor:  SobjectDescriptor,
    public:      Key<PublicParts, UnspecifiedRole>,
    role:        Role,
}

/// The version of this crate.
pub const SQ_DSM_VERSION: &str = env!("CARGO_PKG_VERSION");
const DSM_LABEL_PGP:      &str = "sq_dsm";
const ENV_API_KEY:        &str = "FORTANIX_API_KEY";
const ENV_API_ENDPOINT:   &str = "FORTANIX_API_ENDPOINT";
const ENV_APP_UUID:       &str = "FORTANIX_APP_UUID";
const ENV_HTTP_PROXY:     &str = "http_proxy";
const ENV_NO_PROXY:       &str = "no_proxy";
const ENV_P12:            &str = "FORTANIX_PKCS12_ID";
const MIN_DSM_VERSION:    &str = "4.2.0";
// As seen on sdkms-client-rust/blob/master/examples/approval_request.rs
const OP_APPROVAL_MSG:    &str = "This operation requires approval";

#[derive(Clone)]
pub enum Auth {
    ApiKey(String),
    // App UUID and PKCS12 identity
    Cert(Uuid, Identity),
}

impl Auth {
    pub fn from_options_or_env(
        cli_api_key: Option<&str>,
        cli_client_cert: Option<&str>,
        cli_app_uuid: Option<&str>,
    ) -> Result<Self> {
        // Try API key
        let api_key = match (cli_api_key, env::var(ENV_API_KEY).ok()) {
            (Some(api_key), None) => Some(api_key.to_string()),
            (None, Some(api_key)) => Some(api_key),
            (Some(api_key), Some(_)) => {
                println!(
                    "API key both in parameters and env; ignoring env"
                );
                Some(api_key.to_string())
            },
            (None, None) => None,
        };

        // Try client cert
        let cert_based = {
            let client_cert = match (cli_client_cert, env::var(ENV_P12).ok()) {
                (Some(cert), None) => Some(cert.to_string()),
                (None, Some(cert)) => Some(cert),
                (Some(cert), Some(_)) => {
                    println!(
                        "P12 cert both in parameters and env; ignoring env"
                    );
                    Some(cert.to_string())
                },
                (None, None) => None,
            };

            let app_uuid = match (cli_app_uuid, env::var(ENV_APP_UUID).ok()) {
                (Some(id), None) => Some(id.to_string()),
                (None, Some(id)) => Some(id),
                (Some(id), Some(_)) => {
                    println!(
                        "APP UUID both in parameters and env; ignoring env"
                    );
                    Some(id.to_string())
                },
                (None, None) => None,
            };

            match (client_cert, app_uuid) {
                (Some(cert), Some(uuid)) => Some((cert, uuid)),
                _ => None,
            }
        };

        match (api_key, cert_based) {
            (Some(api_key), None) => Ok(Auth::ApiKey(api_key)),
            (Some(api_key), Some(_)) => {
                println!(
                    "Multiple auth methods found. Using API key"
                );

                Ok(Auth::ApiKey(api_key))
            },
            (None, Some((client_cert, app_uuid))) => {
                let p12_id = try_unlock_p12(client_cert)?;

                let uuid = Uuid::parse_str(&app_uuid)
                    .context("bad app UUID")?;
                Ok(Auth::Cert(uuid, p12_id))
            }
            (None, None) => Err(Error::msg("no auth credentials found")),
        }
    }
}

#[derive(Clone)]
pub struct Credentials {
    api_endpoint: String,
    auth:         Auth,
}

trait OperateOrAskApproval<S: Into<Cow<'static, str>> + Display> {
    fn __retry_until_resolved<O: Operation>(&self, pa: &PendingApproval<O>, desc: S)
        -> Result<O::Output>;

    fn __update_sobject(&self, uuid: &Uuid, req: &SobjectRequest, desc: S)
        -> Result<Sobject>;

    fn __sign(&self, req: &SignRequest, desc: S)
        -> Result<SignResponse>;

    fn __decrypt(&self, req: &DecryptRequest, desc: S)
        -> Result<DecryptResponse>;

    fn __export_sobject(&self, descriptor: &SobjectDescriptor, desc: S)
        -> Result<Sobject>;

    // Currently unsupported due to backend constraints.
    fn __agree(&self, req: &AgreeKeyRequest, desc: S)
        -> Result<Sobject>;
}

impl <S: Into<Cow<'static, str>> + Display> OperateOrAskApproval<S> for DsmClient {
    fn __retry_until_resolved<O: Operation>(
        &self, pa: &PendingApproval<O>, desc: S
    ) -> Result<O::Output> {
        let id = pa.request_id();
        while pa.status(self)? == ApprovalStatus::Pending {
            println!(
                "Approval request {} ({}) pending. Press Enter to check status",
                id, desc
            );
            std::io::stdin().read_line(&mut String::new())?;
        }
        match pa.result(self) {
            Ok(output) => {
                println!("Approval request {} approved", id);
                output.map_err(|e|e.into())
            }
            Err(e) => {
                println!("Approval request {} denied", id);
                Err(e.into())
            }
        }
    }

    fn __update_sobject(
        &self, uuid: &Uuid, req: &SobjectRequest, desc: S
    ) -> Result<Sobject> {
        match self.update_sobject(uuid, req) {
            Err(DsmError::Forbidden(ref msg)) if msg == OP_APPROVAL_MSG => {
                info!("Creating UPDATE approval request: {}", desc);
                let pa = self.request_approval_to_update_sobject(
                    uuid, req, Some(format!("sq-dsm: {}", desc))
                )?;
                self.__retry_until_resolved(&pa, desc)
            }
            Err(err) => Err(err.into()),
            Ok(resp) => Ok(resp)
        }
    }

    fn __sign(&self, req: &SignRequest, desc: S) -> Result<SignResponse> {
        match self.sign(req) {
            Err(DsmError::Forbidden(ref msg)) if msg == OP_APPROVAL_MSG => {
                info!("Creating SIGN approval request: {}", desc);
                let pa = self.request_approval_to_sign(
                    req, Some(format!("sq-dsm: {}", desc))
                )?;
                self.__retry_until_resolved(&pa, desc)
            }
            Err(err) => Err(err.into()),
            Ok(resp) => Ok(resp)
        }
    }

    fn __decrypt(
        &self, req: &DecryptRequest, desc: S
    ) -> Result<DecryptResponse> {
        match self.decrypt(req) {
            Err(DsmError::Forbidden(ref msg)) if msg == OP_APPROVAL_MSG => {
                info!("Creating DECRYPT approval request: {}", desc);
                let pa = self.request_approval_to_decrypt(
                    req, Some(format!("sq-dsm: {}", desc))
                )?;
                self.__retry_until_resolved(&pa, desc)
            }
            Err(err) => Err(err.into()),
            Ok(resp) => Ok(resp)
        }
    }

    fn __export_sobject(
        &self, descriptor: &SobjectDescriptor, desc: S
    ) -> Result<Sobject> {
        match self.export_sobject(descriptor) {
            Err(DsmError::Forbidden(ref msg)) if msg == OP_APPROVAL_MSG => {
                info!("Creating EXPORT approval request: {}", desc);
                let pa = self.request_approval_to_export_sobject(
                    descriptor, Some(format!("sq-dsm: {}", desc))
                )?;
                self.__retry_until_resolved(&pa, desc)
            }
            Err(err) => Err(err.into()),
            Ok(resp) => Ok(resp)
        }
    }

    fn __agree(&self, req: &AgreeKeyRequest, _desc: S) -> Result<Sobject> {
        match self.agree(req) {
            Err(DsmError::Forbidden(ref msg)) if msg == OP_APPROVAL_MSG => {
                // FIXME: In DSM, AGREEKEY results in a transient key which
                // cannot be retrieved with the DSM client.
                Err(Error::msg("Quorum approval for EC decryption unsupported"))
            }
            Err(err) => Err(err.into()),
            Ok(resp) => Ok(resp)
        }
    }
}

impl Credentials {
    pub fn new(auth: Auth) -> Result<Self> {
        let api_endpoint = env::var(ENV_API_ENDPOINT)
            .with_context(|| format!("{} absent", ENV_API_ENDPOINT))?;

        Ok(Self { api_endpoint, auth })
    }

    fn dsm_client(&self) -> Result<DsmClient> {
        let builder = DsmClient::builder()
            .with_api_endpoint(&self.api_endpoint);

        let cli = match &self.auth {
            Auth::ApiKey(api_key) => {
                let tls_conn = TlsConnector::builder()
                    .build()?;
                let ssl = NativeTlsClient::from(tls_conn);
                let hyper_client = maybe_proxied(&self.api_endpoint, ssl)?;
                let cli = builder
                    .with_hyper_client(Arc::new(hyper_client))
                    .build()
                    .context("could not initiate a DSM client")?;
                cli.authenticate_with_api_key(api_key)?
            },
            Auth::Cert(app_uuid, identity) => {
                let tls_conn = TlsConnector::builder()
                    .identity(identity.clone())
                    .build()?;
                let ssl = NativeTlsClient::from(tls_conn);
                let hyper_client = maybe_proxied(&self.api_endpoint, ssl)?;
                let cli = builder
                    .with_hyper_client(Arc::new(hyper_client))
                    .build()
                    .context("could not initiate a DSM client")?;
                cli.authenticate_with_cert(Some(app_uuid))?
            }
        };

        let min = VersionReq::parse(&(">=".to_string() + MIN_DSM_VERSION))?;
        let ver = Version::parse(&cli.version()?.version)?;
        if min.matches(&ver) {
            Ok(cli)
        } else {
            Err(Error::msg(format!(
                        "Incompatible DSM version: ({} < {})",
                        ver,
                        MIN_DSM_VERSION
            )))
        }
    }
}

#[derive(PartialEq)]
enum Role {
    Signer,
    Decryptor,
}

impl DsmAgent {
    /// Returns a DsmAgent with certifying capabilities, corresponding to the
    /// primary key (flag "C").
    fn new_certifier(credentials: Credentials, key_name: &str) -> Result<Self> {
        let dsm_client = credentials.dsm_client()?;

        let descriptor = SobjectDescriptor::Name(key_name.to_string());
        let prim_sob = dsm_client
            .get_sobject(None, &descriptor)
            .context(format!("could not get primary key {}", key_name))?;
        // Initialize Signer with primary key
        let key = PublicKey::from_sobject(prim_sob, KeyRole::Primary)?;
        Ok(DsmAgent {
            credentials,
            descriptor,
            public: key.sequoia_key.context("key is not loaded")?,
            role: Role::Signer,
        })
    }

    /// Returns a DsmAgent with signing capabilities, corresponding to the first
    /// key with key flag "S" found in DSM.
    pub fn new_signer(credentials: Credentials, key_name: &str) -> Result<Self> {
        let dsm_client = credentials.dsm_client()?;

        // Check if primary is "S"
        let descriptor = SobjectDescriptor::Name(key_name.to_string());
        let prim_sob = dsm_client
            .get_sobject(None, &descriptor)
            .context(format!("could not get primary key {}", key_name))?;
        if let Some(flags) = KeyMetadata::from_sobject(&prim_sob)?.key_flags {
            if KeyFlags::custom_deserialize(flags).for_signing() {
                // Initialize Signer with primary key
                let key = PublicKey::from_sobject(prim_sob, KeyRole::Primary)?;
                return Ok(DsmAgent {
                    credentials,
                    descriptor,
                    public: key.sequoia_key.context("key is not loaded")?,
                    role: Role::Signer,
                });
            }
        }

        // Loop through subkeys
        let KeyLinks { subkeys, .. }
        = prim_sob.links.ok_or(Error::msg("no subkeys found"))?;
        for uid in subkeys {
            let descriptor = SobjectDescriptor::Kid(uid);
            let sub_sob = dsm_client
                .get_sobject(None, &descriptor)?;
            if let Some(flags) = KeyMetadata::from_sobject(&sub_sob)?.key_flags {
                if KeyFlags::custom_deserialize(flags).for_signing() {
                    // Initialize Signer with subkey
                    let key = PublicKey::from_sobject(sub_sob, KeyRole::Subkey)?;
                    return Ok(DsmAgent {
                        credentials,
                        descriptor,
                        public: key.sequoia_key.context("key is not loaded")?,
                        role: Role::Signer,
                    })
                }
            }
        }

        Err(anyhow::anyhow!(format!("Found no suitable signing key in DSM")))
    }

    /// Returns several DsmAgents with decryption capabilities, corresponding to
    /// all subkeys with key flag "Et" or "Er" found in DSM.
    /// We assume that the primary key is ONLY "C" or "CS", so it will never be
    /// used as a decryptor.
    ///
    /// NOTE: From RFC4880bis "[...] it is a thorny issue to determine what is
    /// "communications" and what is "storage". This decision is left wholly up
    /// to the implementation".
    pub fn new_decryptors(credentials: Credentials, key_name: &str) -> Result<Vec<Self>> {
        let mut decryptors = Vec::<DsmAgent>::new();

        let dsm_client = credentials.dsm_client()?;
        let prim_descriptor = SobjectDescriptor::Name(key_name.to_string());
        let prim_sobject = dsm_client
            .get_sobject(None, &prim_descriptor)
            .context(format!("could not get primary key {}", key_name))?;

        if let Some(KeyLinks { subkeys, .. }) = prim_sobject.links {
            for uid in subkeys {
                let descriptor = SobjectDescriptor::Kid(uid);
                let sobject = dsm_client
                    .get_sobject(None, &descriptor)
                    .context("could not get subkey".to_string())?;
                if let Some(flags) = KeyMetadata::from_sobject(&sobject)?.key_flags {
                    let kf = KeyFlags::custom_deserialize(flags);
                    if kf.for_storage_encryption() | kf.for_transport_encryption() {
                        let key = PublicKey::from_sobject(sobject, KeyRole::Subkey)?;
                        decryptors.push(DsmAgent {
                            credentials: credentials.clone(),
                            descriptor,
                            public: key.sequoia_key.context("key is not loaded")?,
                            role: Role::Decryptor,
                        });
                    }
                }
            }
        }

        Ok(decryptors)
    }
}

#[derive(Clone)]
struct PublicKey {
    role:        KeyRole,
    descriptor:  SobjectDescriptor,
    sequoia_key: Option<Key<PublicParts, UnspecifiedRole>>,
}

enum SupportedPkAlgo {
    Rsa(u32),
    Ec(ApiCurve),
    Curve25519,
}

#[derive(Clone, Debug, PartialEq)]
enum KeyRole {
    Primary,
    Subkey,
}

#[derive(Serialize, Deserialize)]
struct KeyMetadata {
    sq_dsm_version:              String,
    fingerprint:                 String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_flags:                   Option<[u8; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate:                 Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_creation_timestamp: Option<u32>,
}

impl KeyMetadata {
    fn from_sobject(sob: &Sobject) -> Result<Self> {
        match &sob.custom_metadata {
            Some(dict) => {
                if !dict.contains_key(DSM_LABEL_PGP) {
                    return Err(anyhow::anyhow!("malformed metadata"));
                }
                let key_md: KeyMetadata =
                    serde_json::from_str(&dict[DSM_LABEL_PGP])?;
                Ok(key_md)
            }
            None => Err(anyhow::anyhow!("no metadata found on {:?}", sob.kid))
        }
    }
}

/// Generates an OpenPGP key with secrets stored in DSM. At the OpenPGP
/// level, this method produces a key consisting of
///
/// - A primary signing key (flags C + S),
/// - a transport and storage encryption subkey (flags Et + Er).
///
/// At the DSM level, this method creates the two corresponding Sobjects.
/// The encryption key's KID is stored as a custom metadata field of the
/// signing key.
///
/// The public certificate (Transferable Public Key) is computed, stored as
/// an additional custom metadata field on the primary key, and returned.
pub fn generate_key(
    key_name: &str,
    validity_period: Option<Duration>,
    user_id: Option<&str>,
    algo: Option<&str>,
    exportable: bool,
    credentials: Credentials,
) -> Result<()> {
    // User ID
    let uid: UserID = match user_id {
        Some(id) => id.into(),
        None => return Err(Error::msg("no User ID")),
    };

    // Cipher Suite
    let algorithm = match algo {
        Some("rsa2k") => SupportedPkAlgo::Rsa(2048),
        Some("rsa3k") => SupportedPkAlgo::Rsa(3072),
        Some("rsa4k") => SupportedPkAlgo::Rsa(4096),
        Some("cv25519") => SupportedPkAlgo::Curve25519,
        Some("nistp256") => SupportedPkAlgo::Ec(ApiCurve::NistP256),
        Some("nistp384") => SupportedPkAlgo::Ec(ApiCurve::NistP384),
        Some("nistp521") => SupportedPkAlgo::Ec(ApiCurve::NistP521),
        _ => unreachable!("argument has a default value"),
    };

    let dsm_client = credentials.dsm_client()?;

    info!("create primary key");
    let primary = PublicKey::create(
        &dsm_client,
        key_name.to_string(),
        KeyRole::Primary,
        &algorithm,
        exportable,
    )
    .context("could not create primary key")?;

    info!("create decryption subkey");
    let subkey = PublicKey::create(
        &dsm_client,
        key_name.to_string(),
        KeyRole::Subkey,
        &algorithm,
        exportable,
    )?;

    info!("bind subkey to primary key in DSM");
    let links = KeyLinks {
        parent: Some(primary.uid()?),
        ..Default::default()
    };
    let link_update_req = SobjectRequest {
        links: Some(links),
        ..Default::default()
    };
    dsm_client.__update_sobject(
        &subkey.uid()?, &link_update_req, "bind subkey to primary key"
    )?;

    // Primary + sig, UserID + sig, subkey + sig
    let mut packets = Vec::<Packet>::with_capacity(6);

    // Self-sign primary key
    info!("generate certificate - self-sign primary key");
    let prim: Key<PublicParts, PrimaryRole> = primary
        .sequoia_key
        .clone()
        .context("unloaded primary key")?
        .into();
    let prim_fingerprint = prim.fingerprint().to_hex();
    let prim_id = prim.keyid().to_hex();
    let prim_creation_time = prim.creation_time();

    let mut prim_signer = DsmAgent::new_certifier(credentials, key_name)?;

    let prim_flags = KeyFlags::empty().set_certification().set_signing();

    let prim_sig_builder = SignatureBuilder::new(SignatureType::DirectKey)
        .set_features(Features::sequoia())?
        .set_key_flags(prim_flags.clone())?
        .set_key_validity_period(validity_period)?
        .set_signature_creation_time(prim_creation_time)?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA256,
        ])?
        .set_hash_algo(HashAlgorithm::SHA512);

    // A direct key signature is always over the primary key.
    let prim_sig = prim_sig_builder.sign_direct_key(&mut prim_signer, None)?;

    packets.push(prim.into());
    packets.push(prim_sig.into());

    let mut cert = Cert::try_from(packets)?;

    // User ID + signature
    info!("sign user ID");
    let builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_primary_userid(true)?
        .set_features(Features::sequoia())?
        .set_key_flags(prim_flags.clone())?
        .set_key_validity_period(validity_period)?
        .set_signature_creation_time(prim_creation_time)?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA256,
        ])?;
    let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

    cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

    // Subkey + signature
    info!("sign subkey");
    let subkey_public: Key<PublicParts, SubordinateRole> = subkey
        .sequoia_key
        .as_ref()
        .context("unloaded subkey")?
        .clone()
        .into();
    let subkey_creation_time = subkey_public.creation_time();

    let subkey_flags = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_key_validity_period(validity_period)?
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_signature_creation_time(subkey_creation_time)?
        .set_key_flags(subkey_flags.clone())?;
    let subkey_fingerprint = subkey_public.fingerprint().to_hex();
    let subkey_id = subkey_public.keyid().to_hex();

    let signature = subkey_public.bind(&mut prim_signer, &cert, builder)?;
    cert = cert
        .insert_packets(vec![Packet::from(subkey_public), signature.into()])?;


    info!("Generation: store primary metadata");
    {
        let primary_desc = format!(
            "PGP primary, {}, {}", prim_id, prim_flags.to_human()
        );
        let key_json = serde_json::to_string(&KeyMetadata {
            sq_dsm_version: SQ_DSM_VERSION.to_string(),
            fingerprint: prim_fingerprint,
            key_flags: Some(prim_flags.custom_serialize()),
            certificate: Some(String::from_utf8(cert.armored().to_vec()?)?),
            external_creation_timestamp: None,
        })?;
        let mut prim_metadata = HashMap::<String, String>::new();
        prim_metadata.insert(DSM_LABEL_PGP.to_string(), key_json);
        let update_req = SobjectRequest {
            description: Some(primary_desc),
            custom_metadata: Some(prim_metadata),
            ..Default::default()
        };
        dsm_client.__update_sobject(
            &primary.uid()?, &update_req, "store PGP certificate as metadata"
        )?;
    }

    info!("Generation: rename subkey and store metadata");
    {
        let subkey_name = format!(
            "{} {}/{}", key_name, prim_id, subkey_id
        );
        let subkey_desc = format!(
            "PGP subkey, {}", subkey_flags.to_human()
        );
        let key_json = serde_json::to_string(&KeyMetadata {
            sq_dsm_version: SQ_DSM_VERSION.to_string(),
            fingerprint: subkey_fingerprint,
            key_flags: Some(subkey_flags.custom_serialize()),
            certificate: None,
            external_creation_timestamp: None,
        })?;
        let mut sub_metadata = HashMap::<String, String>::new();
        sub_metadata.insert(DSM_LABEL_PGP.to_string(), key_json);
        let update_req = SobjectRequest {
            name: Some(subkey_name),
            description: Some(subkey_desc),
            custom_metadata: Some(sub_metadata),
            ..Default::default()
        };
        dsm_client.__update_sobject(
            &subkey.uid()?, &update_req, "store PGP certificate as metadata"
        )?;
    }

    Ok(())
}

/// Extracts the certificate of the corresponding PGP key. Note that this
/// certificate, created at key-generation time, is stored in the custom
/// metadata of the Security Object representing the primary key.
pub fn extract_cert(key_name: &str, cred: Credentials) -> Result<Cert> {
    info!("dsm extract_cert");
    let dsm_client = cred.dsm_client()?;

    let sobject = dsm_client
        .get_sobject(None, &SobjectDescriptor::Name(key_name.to_string()))
        .context(format!("could not get primary key {}", key_name))?;

    Cert::from_str(
        &KeyMetadata::from_sobject(&sobject)?.certificate
        .ok_or(anyhow::anyhow!("no certificate in DSM custom metadata"))?
    )
}

pub fn extract_tsk_from_dsm(key_name: &str, cred: Credentials) -> Result<Cert> {
    // Extract all secrets as packets
    let dsm_client = cred.dsm_client()?;

    let mut packets = Vec::<Packet>::with_capacity(2);

    // Primary key
    let prim_sob = dsm_client
        .__export_sobject(
            &SobjectDescriptor::Name(key_name.to_string()),
            "export primary key",
        )
        .context(format!("could not export primary secret {}", key_name))?;
    let key_md = KeyMetadata::from_sobject(&prim_sob)?;
    let packet = secret_packet_from_sobject(&prim_sob, KeyRole::Primary)?;
    packets.push(packet);

    // Subkeys
    if let Some(KeyLinks { subkeys, .. }) = prim_sob.links {
        for uid in &subkeys {
            let sob = dsm_client
                .__export_sobject(
                    &SobjectDescriptor::Kid(*uid),
                    "export subkey",
                )
                .context(format!("could not export subkey secret {}", key_name))?;
            let packet = secret_packet_from_sobject(&sob, KeyRole::Subkey)?;
            packets.push(packet);
        }
    } else {
        return Err(Error::msg("could not find subkeys"));
    }

    // Merge with the known public certificate
    let priv_cert = Cert::try_from(packets)?;
    let cert = Cert::from_str(
        &key_md.certificate
        .ok_or(anyhow::anyhow!("no certificate in DSM custom metadata"))?
    )?;
    let merged = cert
        .merge_public_and_secret(priv_cert)
        .context("Could not merge public and private certificates")?;

    Ok(merged)
}

/// Imports a given Transferable Secret Key to DSM.
pub fn import_tsk_to_dsm(
    tsk:        ValidCert,
    key_name:   &str,
    cred:       Credentials,
    exportable: bool,
) -> Result<()> {

    fn get_hazardous_material<R: SequoiaKeyRole>(key: &Key<SecretParts, R>)
    -> MpiSecret {
        // HAZMAT: Decrypt MPIs from protected memory and form DER
        if let SecretKeyMaterial::Unencrypted(mpis) = key.secret() {
            mpis.map::<_, MpiSecret>(|crypt| {crypt.clone()})
        } else {
            unreachable!("mpis are encrypted")
        }
    }

    fn get_operations(
        key_flags:  Option<KeyFlags>,
        pk_algo:    PublicKeyAlgorithm,
        exportable: bool,
    ) -> KeyOperations {
        let mut ops = KeyOperations::APPMANAGEABLE;

        if exportable {
            ops |= KeyOperations::EXPORT;
        }

        if let Some(f) = key_flags {
            if f.for_signing() | f.for_certification() {
                ops |= KeyOperations::SIGN;
            }

            if f.for_transport_encryption() | f.for_storage_encryption() {
                if pk_algo == PublicKeyAlgorithm::ECDH {
                    ops |= KeyOperations::AGREEKEY;
                } else {
                    ops |= KeyOperations::DECRYPT;
                }
            }
        }

        ops
    }

    let prim_key = tsk.primary_key();
    let primary_ops = get_operations(
        prim_key.key_flags(),
        prim_key.pk_algo(),
        exportable
    );
    let primary = prim_key.key().clone().parts_into_secret()?;
    let prim_id = prim_key.keyid().to_hex();
    let prim_flags = tsk.primary_key()
        .key_flags()
        .ok_or_else(||anyhow::anyhow!("Bad input: primary has no key flags"))?;
    let primary_desc = format!(
        "PGP primary, {}, {}", prim_id, prim_flags.to_human()
    );

    let metadata = {
        let armored = String::from_utf8(tsk.cert().armored().to_vec()?)?;
        let creation_time = Timestamp::try_from(primary.creation_time())?;
        let key_json = serde_json::to_string(&KeyMetadata {
            sq_dsm_version:              SQ_DSM_VERSION.to_string(),
            fingerprint:                 prim_key.fingerprint().to_hex(),
            key_flags:                   Some(prim_flags.custom_serialize()),
            certificate:                 Some(armored),
            external_creation_timestamp: Some(creation_time.into()),
        })?;

        let mut metadata = HashMap::<String, String>::new();
        metadata.insert(DSM_LABEL_PGP.to_string(), key_json);
        metadata
    };

    let prim_hazmat = get_hazardous_material(&primary);
    // TODO: don't double the following code
    let prim_req = match (primary.mpis(), prim_hazmat) {
        (MpiPublic::RSA{ e, n }, MpiSecret::RSA { d, p, q, u }) => {
            let value = der::serialize::rsa_private(n, e, &d, &p, &q, &u);
            let key_size = n.bits() as u32;
            let rsa_opts = if primary_ops.contains(KeyOperations::SIGN) {
                let sig_policy = RsaSignaturePolicy {
                    padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                };
                Some(RsaOptions {
                    signature_policy: vec![sig_policy],
                    ..Default::default()
                })
            } else if primary_ops.contains(KeyOperations::DECRYPT) {
                // Unreachable
                let enc_policy = RsaEncryptionPolicy {
                    padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                };
                Some(RsaOptions {
                    encryption_policy: vec![enc_policy],
                    ..Default::default()
                })
            } else {
                None
            };

            SobjectRequest {
                custom_metadata: Some(metadata),
                description:     Some(primary_desc),
                name:            Some(key_name.to_string()),
                obj_type:        Some(ObjectType::Rsa),
                key_ops:         Some(primary_ops),
                key_size:        Some(key_size),
                rsa:             rsa_opts,
                value:           Some(value.into()),
                ..Default::default()
            }
        },
        (MpiPublic::EdDSA { curve, .. }, MpiSecret::EdDSA { scalar }) => {
            let value = der::serialize::ec_private(&curve, &scalar)?;
            SobjectRequest {
                custom_metadata: Some(metadata),
                description:     Some(primary_desc),
                name:            Some(key_name.to_string()),
                obj_type:        Some(ObjectType::Ec),
                key_ops:         Some(primary_ops),
                value:           Some(value.into()),
                ..Default::default()
            }
        },
        (MpiPublic::ECDSA { curve, .. }, MpiSecret::ECDSA { scalar }) => {
            let value = der::serialize::ec_private(&curve, &scalar)?;
            SobjectRequest {
                custom_metadata: Some(metadata),
                description:     Some(primary_desc),
                name:            Some(key_name.to_string()),
                obj_type:        Some(ObjectType::Ec),
                key_ops:         Some(primary_ops),
                value:           Some(value.into()),
                ..Default::default()
            }
        },
        x => unimplemented!("DER of {:?}", x)
    };

    let dsm_client = cred.dsm_client()?;
    let primary_uuid = dsm_client
        .import_sobject(&prim_req)
        .context(format!("could not import primary secret {}", key_name))?
        .kid;

    for subkey in tsk.keys().subkeys().unencrypted_secret() {
        let subkey_flags = subkey.key_flags().unwrap_or(KeyFlags::empty());
        let subkey_id = subkey.keyid().to_hex();
        let subkey_name = format!(
            "{} {}/{}", key_name, prim_id, subkey_id,
        );
        let subkey_desc = format!(
            "PGP subkey, {}", subkey_flags.to_human()
        );
        let metadata = {
            let creation_time = Timestamp::try_from(subkey.creation_time())?;
            let key_md = KeyMetadata {
                certificate:                 None,
                sq_dsm_version:              SQ_DSM_VERSION.to_string(),
                external_creation_timestamp: Some(creation_time.into()),
                fingerprint:                 subkey.fingerprint().to_hex(),
                key_flags:                   Some(subkey_flags.custom_serialize()),
            };

            let key_json = serde_json::to_string(&key_md)?;
            let mut metadata = HashMap::<String, String>::new();
            metadata.insert(DSM_LABEL_PGP.to_string(), key_json);
            metadata
        };
        let subkey_hazmat = get_hazardous_material(&subkey);
        let subkey_ops = get_operations(
            subkey.key_flags(),
            subkey.pk_algo(),
            exportable
        );
        let subkey_req = match (subkey.mpis(), subkey_hazmat) {
            (MpiPublic::RSA{ e, n }, MpiSecret::RSA { d, p, q, u }) => {
                let value = der::serialize::rsa_private(n, e, &d, &p, &q, &u);
                let key_size = n.bits() as u32;
                let rsa_options = if subkey_ops.contains(KeyOperations::SIGN) {
                    let sig_policy = RsaSignaturePolicy {
                        padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                    };
                    Some(RsaOptions {
                        signature_policy: vec![sig_policy],
                        ..Default::default()
                    })
                } else if subkey_ops.contains(KeyOperations::DECRYPT) {
                    let enc_policy = RsaEncryptionPolicy {
                        padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                    };
                    Some(RsaOptions {
                        encryption_policy: vec![enc_policy],
                        ..Default::default()
                    })
                } else {
                    None
                };

                SobjectRequest {
                    name: Some(subkey_name.to_string()),
                    custom_metadata: Some(metadata),
                    description: Some(subkey_desc),
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(subkey_ops),
                    key_size: Some(key_size),
                    rsa: rsa_options,
                    value: Some(value.into()),
                    ..Default::default()
                }
            },
            (MpiPublic::EdDSA { curve, .. }, MpiSecret::EdDSA { scalar }) => {
                let value = der::serialize::ec_private(&curve, &scalar)?;
                SobjectRequest {
                    name:            Some(subkey_name.to_string()),
                    custom_metadata: Some(metadata),
                    description:     Some(subkey_desc),
                    obj_type:        Some(ObjectType::Ec),
                    key_ops:         Some(subkey_ops),
                    value:           Some(value.into()),
                    ..Default::default()
                }
            },
            (MpiPublic::ECDH { curve, q, hash, sym }, MpiSecret::ECDH { scalar }) => {
                let value = der::serialize::ec_private(&curve, &scalar)?;
                SobjectRequest {
                    name:            Some(subkey_name.to_string()),
                    custom_metadata: Some(metadata),
                    description:     Some(subkey_desc),
                    obj_type:        Some(ObjectType::Ec),
                    key_ops:         Some(subkey_ops),
                    value:           Some(value.into()),
                    ..Default::default()
                }
            },
            (x, y) => unimplemented!("{:?}, {:?}", x, y)
        };

        // Import subkey
        let subkey_uuid = dsm_client
            .import_sobject(&subkey_req)
            .context(format!("could not import subkey secret {}", key_name))?
            .kid;

        info!("bind subkey to primary key in DSM");
        let link_req = SobjectRequest {
            links: Some(KeyLinks {
                parent: primary_uuid,
                ..Default::default()
            }),
            ..Default::default()
        };
        dsm_client.__update_sobject(
            &subkey_uuid.expect("uuid"), &link_req, "bind subkey to primary key"
        )?;
    }

    Ok(())
}

impl PublicKey {
    fn create(
        client: &DsmClient,
        name: String,
        role: KeyRole,
        algo: &SupportedPkAlgo,
        exportable: bool,
    ) -> Result<Self> {
        let mut sobject_request = match (&role, algo) {
            (KeyRole::Primary, SupportedPkAlgo::Rsa(key_size)) => {
                let sig_policy = RsaSignaturePolicy {
                    padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                };
                let rsa_options = Some(RsaOptions {
                    signature_policy: vec![sig_policy],
                    ..Default::default()
                });

                SobjectRequest {
                    name: Some(name),
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(
                        KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
                    ),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            }
            (KeyRole::Subkey, SupportedPkAlgo::Rsa(key_size)) => {
                let enc_policy = RsaEncryptionPolicy {
                    padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                };
                let rsa_options = Some(RsaOptions {
                    encryption_policy: vec![enc_policy],
                    ..Default::default()
                });

                SobjectRequest {
                    name: Some(name + " (PGP: decryption subkey)"),
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(
                        KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE,
                    ),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            }
            (KeyRole::Primary, SupportedPkAlgo::Curve25519) => SobjectRequest {
                name: Some(name),
                obj_type: Some(ObjectType::Ec),
                key_ops: Some(
                    KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
                ),
                elliptic_curve: Some(ApiCurve::Ed25519),
                ..Default::default()
            },
            (KeyRole::Subkey, SupportedPkAlgo::Curve25519) => {
                let name = name + " (PGP: decryption subkey)";

                SobjectRequest {
                    name: Some(name),
                    obj_type: Some(ObjectType::Ec),
                    key_ops: Some(
                        KeyOperations::AGREEKEY | KeyOperations::APPMANAGEABLE,
                    ),
                    elliptic_curve: Some(ApiCurve::X25519),
                    ..Default::default()
                }
            }
            (KeyRole::Primary, SupportedPkAlgo::Ec(curve)) => SobjectRequest {
                name: Some(name),
                obj_type: Some(ObjectType::Ec),
                key_ops: Some(
                    KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
                ),
                elliptic_curve: Some(*curve),
                ..Default::default()
            },
            (KeyRole::Subkey, SupportedPkAlgo::Ec(curve)) => SobjectRequest {
                name: Some(name + " (PGP: decryption subkey)"),
                obj_type: Some(ObjectType::Ec),
                key_ops: Some(
                    KeyOperations::AGREEKEY | KeyOperations::APPMANAGEABLE,
                ),
                elliptic_curve: Some(*curve),
                ..Default::default()
            },
        };

        if exportable {
            sobject_request.key_ops =
                Some(sobject_request.key_ops.unwrap() | KeyOperations::EXPORT)
        }

        let sobject = client.create_sobject(&sobject_request)
            .context("dsm client could not create sobject")?;

        PublicKey::from_sobject(sobject, role)
    }

    fn from_sobject(sob: Sobject, role: KeyRole) -> Result<Self> {
        let descriptor = SobjectDescriptor::Kid(sob.kid.context("no kid")?);

        let time: SystemTime = if let Some(KeyMetadata {
            external_creation_timestamp: Some(secs), ..
        }) = KeyMetadata::from_sobject(&sob).ok() {
            Timestamp::from(secs).into()
        } else {
            sob.created_at.to_datetime().into()
        };

        let raw_pk = sob.pub_key.context("public bits of sobject missing")?;

        let (pk_algo, pk_material, role) = match sob.obj_type {
            ObjectType::Ec => match sob.elliptic_curve {
                Some(ApiCurve::Ed25519) => {
                    let pk_algo = PublicKeyAlgorithm::EdDSA;
                    let curve = SequoiaCurve::Ed25519;

                    // Strip the leading OID
                    let point = MPI::new_compressed_point(&raw_pk[12..]);

                    let ec_pk = MpiPublic::EdDSA { curve, q: point };
                    (pk_algo, ec_pk, role)
                }
                Some(ApiCurve::X25519) => {
                    let pk_algo = PublicKeyAlgorithm::ECDH;
                    let curve = SequoiaCurve::Cv25519;

                    // Strip the leading OID
                    let point = MPI::new_compressed_point(&raw_pk[12..]);

                    // TODO: NOT HARDCODE
                    let ec_pk = MpiPublic::ECDH {
                        curve,
                        q: point,
                        hash: HashAlgorithm::SHA256,
                        sym: SymmetricAlgorithm::AES256,
                    };

                    (pk_algo, ec_pk, KeyRole::Subkey)
                }
                Some(curve @ ApiCurve::NistP256)
                | Some(curve @ ApiCurve::NistP384)
                | Some(curve @ ApiCurve::NistP521) => {
                    let curve = sequoia_curve_from_api_curve(curve)?;
                    let (x, y) = der::parse::ec_point_x_y(&raw_pk)?;
                    let bits_field = curve.bits()
                        .ok_or_else(|| Error::msg("bad curve"))?;

                    let point = MPI::new_point(&x, &y, bits_field);
                    let (pk_algo, ec_pk) = match role {
                        KeyRole::Primary => (
                            PublicKeyAlgorithm::ECDSA,
                            MpiPublic::ECDSA { curve, q: point },
                        ),
                        KeyRole::Subkey => (
                            PublicKeyAlgorithm::ECDH,
                            MpiPublic::ECDH {
                                curve,
                                q: point,
                                hash: HashAlgorithm::SHA512,
                                sym: SymmetricAlgorithm::AES256,
                            },
                        ),
                    };
                    (pk_algo, ec_pk, role)
                }
                Some(curve) => {
                    return Err(Error::msg(format!(
                        "unimplemented curve: {:?}",
                        curve
                    )))
                }
                None => {
                    return Err(Error::msg("Sobject has no curve attribute"))
                }
            },
            ObjectType::Rsa => {
                let pk = der::parse::rsa_n_e(&raw_pk)?;
                let pk_material = MpiPublic::RSA {
                    e: pk.e.into(),
                    n: pk.n.into()
                };
                let pk_algo = PublicKeyAlgorithm::RSAEncryptSign;

                (pk_algo, pk_material, role)
            },
            t => { return Err(Error::msg(format!("unknown object: {:?}", t))); }
        };

        let key = Key::V4(
            Key4::new(time, pk_algo, pk_material)
            .context("cannot import RSA key into Sequoia")?,
        );

        Ok(PublicKey {
            descriptor,
            role,
            sequoia_key: Some(key),
        })
    }

    fn uid(&self) -> Result<Uuid> {
        match self.descriptor {
            SobjectDescriptor::Kid(x) => Ok(x),
            _ => Err(Error::msg("bad descriptor")),
        }
    }
}

impl Signer for DsmAgent {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<MpiSignature> {
        if self.role != Role::Signer {
            return Err(Error::msg("bad role for DSM agent"));
        }
        let dsm_client = self.credentials.dsm_client()
            .context("could not initialize the http client")?;

        let hash_alg = match hash_algo {
            HashAlgorithm::SHA1 => DigestAlgorithm::Sha1,
            HashAlgorithm::SHA512 => DigestAlgorithm::Sha512,
            HashAlgorithm::SHA256 => DigestAlgorithm::Sha256,
            hash => panic!("unimplemented: {}", hash),
        };

        match self.public.pk_algo() {
            PublicKeyAlgorithm::RSAEncryptSign => {
                let sign_req = SignRequest {
                    key: Some(self.descriptor.clone()),
                    hash_alg,
                    hash: Some(digest.to_vec().into()),
                    data: None,
                    mode: None,
                    deterministic_signature: None,
                };
                let sign_resp = dsm_client.__sign(&sign_req, "signature")
                    .context("bad response for signature request")?;

                let plain: Vec<u8> = sign_resp.signature.into();
                Ok(MpiSignature::RSA { s: plain.into() })
            }
            PublicKeyAlgorithm::EdDSA => {
                let sign_req = SignRequest {
                    key: Some(self.descriptor.clone()),
                    hash_alg,
                    data: Some(digest.to_vec().into()),
                    hash: None,
                    mode: None,
                    deterministic_signature: None,
                };
                let sign_resp = dsm_client.__sign(&sign_req, "signature")
                    .context("bad response for signature request")?;

                let plain: Vec<u8> = sign_resp.signature.into();
                Ok(MpiSignature::EdDSA {
                    r: MPI::new(&plain[..32]),
                    s: MPI::new(&plain[32..]),
                })
            }
            PublicKeyAlgorithm::ECDSA => {
                let sign_req = SignRequest {
                    key: Some(self.descriptor.clone()),
                    hash_alg,
                    hash: Some(digest.to_vec().into()),
                    data: None,
                    mode: None,
                    deterministic_signature: None,
                };
                let sign_resp = dsm_client.__sign(&sign_req, "signature")
                    .context("bad response for signature request")?;

                let plain: Vec<u8> = sign_resp.signature.into();
                let (r, s) = der::parse::ecdsa_r_s(&plain)
                    .context("could not decode ECDSA der")?;

                Ok(MpiSignature::ECDSA {
                    r: r.to_vec().into(),
                    s: s.to_vec().into(),
                })
            }
            algo => Err(Error::msg(format!("unknown algo: {}", algo)))
        }
    }
}

impl Decryptor for DsmAgent {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn decrypt(
        &mut self,
        ciphertext: &MpiCiphertext,
        _plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        if self.role != Role::Decryptor {
            return Err(Error::msg("bad role for DSM agent"));
        }

        let cli = self.credentials.dsm_client()
            .context("could not initialize the http client")?;

        match ciphertext {
            MpiCiphertext::RSA { c } => {
                let decrypt_req = DecryptRequest {
                    cipher: c.value().to_vec().into(),
                    alg:    Some(Rsa),
                    iv:     None,
                    key:    Some(self.descriptor.clone()),
                    mode:   None,
                    ad:     None,
                    tag:    None,
                };

                Ok(
                    cli.__decrypt(&decrypt_req, "decrypt session key")
                    .context("failed RSA decryption")?
                    .plain.to_vec().into()
                )
            }
            MpiCiphertext::ECDH { e, .. } => {
                let curve = match &self.public.mpis() {
                    MpiPublic::ECDH { curve, .. } => curve,
                    _ => panic!("inconsistent pk algo"),
                };

                let ephemeral_der = der::serialize::spki_ecdh(curve, e);

                // Import ephemeral public key
                let e_descriptor = {
                    let api_curve = api_curve_from_sequoia_curve(curve.clone())
                        .context("bad curve")?;
                    let req = SobjectRequest {
                        elliptic_curve: Some(api_curve),
                        key_ops: Some(KeyOperations::AGREEKEY),
                        obj_type: Some(ObjectType::Ec),
                        transient: Some(true),
                        value: Some(ephemeral_der.into()),
                        ..Default::default()
                    };
                    let e_tkey = cli
                        .import_sobject(&req)
                        .context("failed import ephemeral public key into DSM")?
                        .transient_key
                        .context("could not retrieve DSM transient key \
                                 (representing ECDH ephemeral public key)")?;

                    SobjectDescriptor::TransientKey(e_tkey)
                };

                // Agree on a ECDH secret between the recipient private key, and
                // the ephemeral public key.
                let secret: Protected = {
                    let agree_req = AgreeKeyRequest {
                        activation_date:   None,
                        deactivation_date: None,
                        private_key:       self.descriptor.clone(),
                        public_key:        e_descriptor,
                        mechanism:         AgreeKeyMechanism::DiffieHellman,
                        name:              None,
                        group_id:          None,
                        key_type:          ObjectType::Secret,
                        key_size:          curve_key_size(curve).context("size")?,
                        enabled:           true,
                        description:       None,
                        custom_metadata:   None,
                        key_ops:           Some(KeyOperations::EXPORT),
                        state:             None,
                        transient:         true,
                    };

                    let agreed_tkey = cli
                        .__agree(&agree_req, "ECDH exchange")
                        .context("ECDH exchange")?
                        .transient_key
                        .context("could not retrieve agreed key")?;

                    let desc = SobjectDescriptor::TransientKey(agreed_tkey);

                    cli.export_sobject(&desc)
                        .context("could not export transient key")?
                        .value
                        .context("could not retrieve secret from sobject")?
                        .to_vec()
                        .into()
                };

                Ok(ecdh::decrypt_unwrap(&self.public, &secret, ciphertext)
                    .context("could not unwrap the session key")?
                    .to_vec()
                    .into())
            }
            _ => Err(Error::msg("unsupported/unknown algorithm")),
        }
    }
}

fn secret_packet_from_sobject(
    sobject: &Sobject,
    role: KeyRole,
) -> Result<Packet> {
    let time: SystemTime = if let KeyMetadata {
        external_creation_timestamp: Some(secs), ..
    } = KeyMetadata::from_sobject(sobject)? {
        Timestamp::from(secs).into()
    } else {
        sobject.created_at.to_datetime().into()
    };
    let raw_secret = sobject.value.as_ref()
        .context("secret bits missing in Sobject")?;
    let raw_public = sobject.pub_key.as_ref()
        .context("public bits missing in Sobject")?;
    let is_signer =
        (sobject.key_ops & KeyOperations::SIGN) == KeyOperations::SIGN;
    match sobject.obj_type {
        ObjectType::Ec => match sobject.elliptic_curve {
            Some(ApiCurve::Ed25519) => {
                if raw_secret.len() < 16 {
                    return Err(anyhow::anyhow!("malformed Ed25519 secret"));
                }
                let secret = &raw_secret[16..];
                match role {
                    KeyRole::Primary => Ok(Key::V4(
                        Key4::<_, PrimaryRole>::import_secret_ed25519(
                            secret, time,
                        )?,
                    )
                    .into()),
                    KeyRole::Subkey => Ok(Key::V4(
                        Key4::<_, SubordinateRole>::import_secret_ed25519(
                            secret, time,
                        )?,
                    )
                    .into()),
                }
            }
            Some(ApiCurve::X25519) => {
                if raw_secret.len() < 16 {
                    return Err(anyhow::anyhow!("malformed X25519 secret"));
                }
                let secret = &raw_secret[16..];
                match role {
                    // TODO: unreachable
                    KeyRole::Primary => Ok(Key::V4(
                        Key4::<_, PrimaryRole>::import_secret_cv25519(
                            secret, None, None, time,
                        )?,
                    )
                    .into()),
                    KeyRole::Subkey => Ok(Key::V4(
                        Key4::<_, SubordinateRole>::import_secret_cv25519(
                            secret, None, None, time,
                        )?,
                    )
                    .into()),
                }
            }
            Some(curve @ ApiCurve::NistP256)
            | Some(curve @ ApiCurve::NistP384)
            | Some(curve @ ApiCurve::NistP521) => {
                // Public key point
                let curve = sequoia_curve_from_api_curve(curve)?;
                let bits_field = curve.bits()
                    .ok_or_else(|| Error::msg("bad curve"))?;
                let (x, y) = der::parse::ec_point_x_y(raw_public)?;
                let point = MPI::new_point(&x, &y, bits_field);

                // Secret
                let scalar: ProtectedMPI = der::parse::ec_priv_scalar(
                    raw_secret
                )?.into();
                let algo: PublicKeyAlgorithm;
                let secret: SecretKeyMaterial;
                let public: MpiPublic;
                if is_signer {
                    algo = PublicKeyAlgorithm::ECDSA;
                    secret = MpiSecret::ECDSA { scalar }.into();
                    public = MpiPublic::ECDSA { curve, q: point };
                } else {
                    algo = PublicKeyAlgorithm::ECDH;
                    secret = MpiSecret::ECDH { scalar }.into();
                    public = MpiPublic::ECDH {
                        curve,
                        q: point,
                        hash: HashAlgorithm::SHA512,
                        sym: SymmetricAlgorithm::AES256,
                    };
                };
                match role {
                    KeyRole::Primary => {
                        Ok(Key::V4(Key4::<_, PrimaryRole>::with_secret(
                            time, algo, public, secret,
                        )?)
                        .into())
                    }
                    KeyRole::Subkey => {
                        Ok(Key::V4(Key4::<_, SubordinateRole>::with_secret(
                            time, algo, public, secret,
                        )?)
                        .into())
                    }
                }
            }
            _ => unimplemented!(),
        },
        ObjectType::Rsa => {
            let sk = der::parse::rsa_private_edpq(raw_secret)?;
            match role {
                KeyRole::Primary => Ok(Key::V4(
                    Key4::<_, PrimaryRole>::import_secret_rsa_unchecked_e(
                        &sk.e,
                        &sk.d,
                        &sk.p,
                        &sk.q,
                        time
                    )?
                ).into()),
                KeyRole::Subkey => Ok(Key::V4(
                    Key4::<_, SubordinateRole>::import_secret_rsa_unchecked_e(
                        &sk.e,
                        &sk.d,
                        &sk.p,
                        &sk.q,
                        time
                    )?
                ).into()),
            }
        },
        _ => unimplemented!(),
    }
}

/// Struct with information of hostnames that should not be accessed through a
/// proxy.
#[derive(Clone, Debug)]
pub struct NoProxy(Vec<NoProxyEntry>);

impl NoProxy {
    /// Parse a comma separated list of no proxy hostnames
    ///
    /// Valid format of entries:
    ///     - hostnames
    ///     - ip
    ///     - CIDR
    pub fn parse(no_proxy: &str) -> Self {
        Self(
            no_proxy
                .split(',')
                .filter_map(|no_proxy| no_proxy.parse().ok())
                .collect(),
        )
    }

    /// Check is a host is in the no proxy list
    pub fn is_no_proxy(&self, host: &str, port: u16) -> bool {
        self.0
            .iter()
            .any(|no_proxy| Self::is_no_proxy_match(no_proxy, host, port))
    }

    ///  Check if a host matches a NoProxyEntry
    fn is_no_proxy_match(
        no_proxy: &NoProxyEntry,
        host: &str,
        port: u16,
    ) -> bool {
        // check for CIDR
        match (&no_proxy.ipnetwork, IpAddr::from_str(host)) {
            (Some(cidr), Ok(ip)) if cidr.contains(ip) => return true,
            _ => {}
        }

        // match host fragments
        let matching_hosts = host
            .split('.')
            .rev()
            .take(no_proxy.split_hostname.len())
            .cmp(no_proxy.split_hostname.iter().rev().map(|val| val.as_ref()))
            == std::cmp::Ordering::Equal;

        match (matching_hosts, no_proxy.port) {
            (false, _) => false,
            (true, None) => true,
            (true, Some(no_proxy_port)) => port == no_proxy_port,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NoProxyEntry {
    pub ipnetwork:      Option<IpNetwork>,
    pub split_hostname: Vec<String>,
    pub port:           Option<u16>,
}

impl FromStr for NoProxyEntry {
    type Err = ();

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        // split host and port from no_proxy

        let mut no_proxy_splits = s.trim().splitn(2, ':');
        let no_proxy_host = no_proxy_splits.next().ok_or(())?;
        let no_proxy_port =
            no_proxy_splits.next().and_then(|port| port.parse().ok());

        // remove leading dot
        let no_proxy_host = no_proxy_host.trim_start_matches('.');

        Ok(NoProxyEntry {
            ipnetwork:      IpNetwork::from_str(no_proxy_host).ok(),
            split_hostname: no_proxy_host
                .split('.')
                .map(String::from)
                .collect(),
            port:           no_proxy_port,
        })
    }
}

fn maybe_proxied(endpoint: &str, ssl: NativeTlsClient) -> Result<HyperClient> {
    fn decide_proxy_from_env(endpoint: &str) -> Option<(String, u16)> {
        let uri = endpoint.parse::<Uri>().ok()?;
        let endpoint_host = uri.host()?;
        let endpoint_port = uri.port().map_or(80, |p| p.as_u16());
        if let Ok(proxy) = env::var(ENV_HTTP_PROXY) {
            let uri = proxy.parse::<Uri>().ok()?;
            let proxy_host = uri.host()?;
            let proxy_port = uri.port().map_or(80, |p| p.as_u16());

            //  If host is in no_proxy, then don't use the proxy
            let no_proxy = env::var(ENV_NO_PROXY)
                .map(|list| NoProxy::parse(&list));
            if let Ok(s) = no_proxy {
                if s.is_no_proxy(endpoint_host, endpoint_port) {
                    return None
                }
            }

            Some((proxy_host.to_string(), proxy_port))
        } else {
            None
        }
    }

    let https_conn = HttpsConnector::new(ssl);
    if let Some((proxy_host, proxy_port)) = decide_proxy_from_env(endpoint) {
        Ok(HyperClient::with_proxy_config(ProxyConfig::new(
                    "http",
                    proxy_host,
                    proxy_port,
                    https_conn,
                    NativeTlsClient::new()?,
        )))
    } else {
        Ok(HyperClient::with_connector(https_conn))
    }
}

fn curve_key_size(curve: &SequoiaCurve) -> Result<u32> {
    match curve {
        SequoiaCurve::Cv25519  => Ok(253),
        SequoiaCurve::NistP256 => Ok(256),
        SequoiaCurve::NistP384 => Ok(384),
        SequoiaCurve::NistP521 => Ok(521),
        curve  => Err(Error::msg(format!("unsupported curve {}", curve))),
    }
}

fn sequoia_curve_from_api_curve(curve: ApiCurve) -> Result<SequoiaCurve> {
    match curve {
        ApiCurve::X25519   => Ok(SequoiaCurve::Cv25519),
        ApiCurve::Ed25519  => Ok(SequoiaCurve::Ed25519),
        ApiCurve::NistP256 => Ok(SequoiaCurve::NistP256),
        ApiCurve::NistP384 => Ok(SequoiaCurve::NistP384),
        ApiCurve::NistP521 => Ok(SequoiaCurve::NistP521),
        _ => Err(Error::msg("cannot convert curve")),
    }
}

fn api_curve_from_sequoia_curve(curve: SequoiaCurve) -> Result<ApiCurve> {
    match curve {
        SequoiaCurve::Cv25519  => Ok(ApiCurve::X25519),
        SequoiaCurve::Ed25519  => Ok(ApiCurve::Ed25519),
        SequoiaCurve::NistP256 => Ok(ApiCurve::NistP256),
        SequoiaCurve::NistP384 => Ok(ApiCurve::NistP384),
        SequoiaCurve::NistP521 => Ok(ApiCurve::NistP521),
        curve => Err(Error::msg(format!("unsupported curve {}", curve))),
    }
}

fn try_unlock_p12(cert_file: String) -> Result<Identity> {
    let mut cert_stream = File::open(cert_file.clone())
        .context(format!("opening {}", cert_file))?;
    let mut cert = Vec::new();
    cert_stream.read_to_end(&mut cert)
        .context(format!("reading {}", cert_file))?;
    // Try to unlock certificate without password first
    let mut first = true;
    if let Ok(id) = Identity::from_pkcs12(&cert, "") {
        Ok(id)
    } else {
        loop {
            // Prompt the user for PKCS12 password
            match rpassword::read_password_from_tty(
                Some(
                    &format!(
                        "{}Enter password to unlock {}: ",
                        if first { "" } else { "Invalid password. " },
                        cert_file))
            ) {
                Ok(p) => {
                    first = false;
                    if let Ok(id) = Identity::from_pkcs12(&cert, &p) {
                        break Ok(id)
                    }
                },
                Err(err) => {
                    return Err(Error::msg(format!(
                                "While reading password: {}", err)
                    ));
                }
            }
        }
    }
}

trait CustomSerialize {
    type Serialized;
    fn custom_serialize(&self) -> Self::Serialized;
    fn custom_deserialize(ser: Self::Serialized) -> Self;
    fn to_human(&self) -> String;
}

// See sec 5.2.3.22 of RFC4880bis.
//
// We ignore the second octet for now.
// CS   = 0x03, 0x00 =  3, 0
// EtEr = 0x0c, 0x00 = 12, 0
impl CustomSerialize for KeyFlags {
    type Serialized = [u8; 2];

    fn custom_serialize(&self) -> [u8; 2] {
         [
             (0b0000_0001 * (self.for_certification() as u8))
           | (0b0000_0010 * (self.for_signing() as u8))
           | (0b0000_0100 * (self.for_transport_encryption() as u8))
           | (0b0000_1000 * (self.for_storage_encryption() as u8))
           | (0b0001_0000 * (self.is_split_key() as u8))
           | (0b0010_0000 * (self.for_authentication() as u8))
           | (0b0100_0000 * (self.is_group_key() as u8)), 0
         ]
    }

    fn custom_deserialize(ser: [u8; 2]) -> Self {
        let mut flags = KeyFlags::empty();
        if ser[0] & 0b0000_0001 != 0 {
            flags = flags.set_certification();
        }
        if ser[0] & 0b0000_0010 != 0 {
            flags = flags.set_signing();
        }
        if ser[0] & 0b0000_0100 != 0 {
            flags = flags.set_transport_encryption();
        }
        if ser[0] & 0b0000_1000 != 0 {
            flags = flags.set_storage_encryption();
        }
        if ser[0] & 0b0001_0000 != 0 {
            flags = flags.set_split_key();
        }
        if ser[0] & 0b0010_0000 != 0 {
            flags = flags.set_authentication();
        }
        if ser[0] & 0b0100_0000 != 0 {
            flags = flags.set_group_key();
        }

        flags
    }

    fn to_human(&self) -> String {
        let mut s = String::new();
        if self.for_certification() {
            s += "Certification, ";
        }
        if self.for_signing() {
            s += "Signing, ";
        }
        match (self.for_transport_encryption(), self.for_storage_encryption()) {
            (true, true) => { s += "Transport and Storage Encryption, "},
            (true, false) => { s += "Transport Encryption, "},
            (false, true) => { s += "Storage Encryption, "},
            _ => {}
        }
        if self.is_split_key() {
            s += "Split Key, ";
        }
        if self.for_authentication() {
            s += "Authentication, ";
        }
        if self.is_group_key() {
            s += "Group Key, ";
        }

        s.pop();
        s.pop();
        s
    }
}
