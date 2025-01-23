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
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Error, Result};
use http::uri::Uri;
use hyper::client::{Client as HyperClient, ProxyConfig};
use hyper::net::HttpsConnector;
use hyper_native_tls::native_tls::{Identity, TlsConnector};
use hyper_native_tls::NativeTlsClient;
use ipnetwork::IpNetwork;
use log::{info, warn};
use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, ApprovalStatus, DecryptRequest,
    DecryptResponse, DigestAlgorithm, EllipticCurve as ApiCurve, KeyLinks,
    KeyOperations, ObjectType, RsaEncryptionPaddingPolicy, RsaEncryptionPolicy,
    RsaOptions, RsaSignaturePaddingPolicy, RsaSignaturePolicy, SignRequest,
    SignResponse, Sobject, SobjectDescriptor, SobjectRequest, Time as SdkmsTime,
    ListSobjectsParams
};
use sdkms::operations::Operation;
use sdkms::{Error as DsmError, PendingApproval, SdkmsClient as DsmClient};
use semver::{Version, VersionReq};
use sequoia_openpgp::cert::{ValidCert, Preferences};
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
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{
    Curve as SequoiaCurve, Features, HashAlgorithm, KeyFlags,
    PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm, Timestamp,
};
use sequoia_openpgp::{Cert, Packet};
use serde::{Deserialize, Serialize};
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
const ENV_P12_PASS:       &str = "FORTANIX_PKCS12_PASSPHRASE";
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
        cli_api_key:     Option<&str>,
        cli_client_cert: Option<&str>,
        cli_app_uuid:    Option<&str>,
        cli_p12_pass:    Option<&str>,
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
                let p12_id = try_unlock_p12(client_cert, cli_p12_pass)?;

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
            .context(format!("could not get primary key {:?}", descriptor))?;
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
            .context(format!("could not get signer key {:?}", descriptor))?;
        if let Some(flags) = KeyMetadata::from_sobject(&prim_sob)?.key_flags {
            if flags.for_signing() {
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
        let KeyLinks { subkeys, .. } = prim_sob.links
            .ok_or_else(|| Error::msg("no subkeys found"))?;
        for uid in subkeys {
            let descriptor = SobjectDescriptor::Kid(uid);
            let sub_sob = dsm_client
                .get_sobject(None, &descriptor)?;
            if let Some(flags) = KeyMetadata::from_sobject(&sub_sob)?.key_flags {
                if flags.for_signing() {
                    // Initialize Signer with subkey
                    let key = PublicKey::from_sobject(sub_sob, KeyRole::SigningSubkey)?;
                    return Ok(DsmAgent {
                        credentials,
                        descriptor,
                        public: key.sequoia_key.context("key is not loaded")?,
                        role: Role::Signer,
                    })
                }
            }
        }

        Err(anyhow::anyhow!("Found no suitable signing key in DSM"))
    }

    fn new_signing_subkey_from_descriptor(
        credentials: Credentials, desc: &SobjectDescriptor
    ) -> Result<Self> {
        let dsm_client = credentials.dsm_client()?;

        let sob = dsm_client
            .get_sobject(None, desc)
            .context(format!("could not get signer key {:?}", &desc))?;
        let key = PublicKey::from_sobject(sob, KeyRole::SigningSubkey)?;
        Ok(DsmAgent {
            credentials,
            descriptor: desc.clone(),
            public: key.sequoia_key.context("key is not loaded")?,
            role: Role::Signer,
        })
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
            .context(format!("could not get primary key {:?}", &prim_descriptor))?;

        if let Some(KeyLinks { subkeys, .. }) = prim_sobject.links {
            for uid in subkeys {
                let descriptor = SobjectDescriptor::Kid(uid);
                let sobject = dsm_client
                    .get_sobject(None, &descriptor)
                    .context("could not get subkey".to_string())?;
                if let Some(kf) = KeyMetadata::from_sobject(&sobject)?.key_flags {
                    if kf.for_storage_encryption() || kf.for_transport_encryption() {
                        let key = PublicKey::from_sobject(sobject, KeyRole::EncryptionSubkey)?;
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
    SigningSubkey,
    EncryptionSubkey,
}

#[derive(Deserialize, Serialize, Default)]
struct KeyMetadata {
    sq_dsm_version:              String,
    fingerprint:                 String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_flags:                   Option<KeyFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate:                 Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_creation_timestamp: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_algo:                   Option<HashAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symm_algo:                   Option<SymmetricAlgorithm>,
}

impl KeyMetadata {
    fn from_sobject(sob: &Sobject) -> Result<Self> {
        match &sob.custom_metadata {
            Some(dict) => {
                if !dict.contains_key(DSM_LABEL_PGP) {
                    return Err(anyhow::anyhow!("malformed metadata"));
                }
                match serde_json::from_str(&dict[DSM_LABEL_PGP]) {
                    Ok(key_md) => Ok(key_md),
                    Err(e) => {
                        KeyMetadata::print_metadata_for_pre_0_3_0(&dict[DSM_LABEL_PGP])
                            .map_err(|e| anyhow::anyhow!("Failed to read metadata: {:?}", e))?;
                        Err(anyhow::anyhow!("Failed to parse Sobject: {:?}", e))

                    }
                }
            }
            None => Err(anyhow::anyhow!("no metadata found on {:?}", sob.kid))
        }
    }

    fn to_custom_metadata(&self) -> Result<HashMap<String, String>> {
        let key_json = serde_json::to_string(&self)?;
        let mut custom_metadata = HashMap::<String, String>::new();
        custom_metadata.insert(DSM_LABEL_PGP.to_string(), key_json);

        Ok(custom_metadata)
    }

    fn print_metadata_for_pre_0_3_0(md: &str) -> Result<()> {
        // It should at least be a dict
        let dict: HashMap::<String, String> = serde_json::from_str(md)?;

        let version = dict.get("sq_dsm_version")
            .unwrap_or(&"<0.3.0-beta".to_string()).to_string();

        let cert = dict.get("certificate")
            .ok_or(anyhow::anyhow!("cannot read metadata"))?;

        let cert_obj = Cert::from_str(cert)?;
        let p = &StandardPolicy::new();
        let cert_obj = cert_obj.with_policy(p, None)?;
        let primary = cert_obj.primary_key();
        let subkeys = cert_obj.keys().subkeys();
        let hash_algo = cert_obj.preferred_hash_algorithms().map(|h| h[0]);
        let symm_algo = cert_obj.preferred_symmetric_algorithms().map(|c| c[0]);

        println!(r#"
        It appears that this PGP key was generated with an older version of
        sq-dsm. Please
          1. Make a backup of the following public PGP key:

          ### BACKUP THE FOLLOWING KEY ###
          {}

          2. Update the custom metadata as follows:
        "#, cert);

        // Primary
        let prim_metadata = KeyMetadata {
            sq_dsm_version: version.clone(),
            fingerprint:    primary.fingerprint().to_hex(),
            key_flags:      primary.key_flags(),
            certificate:    Some(cert.to_string()),
            hash_algo,
            symm_algo,
            // Pre 0.3.0, private key import is not supported
            external_creation_timestamp: None,
        }.to_custom_metadata()?;

        println!("For primary key:\nkey=sq_dsm\nvalue={}\n", prim_metadata[DSM_LABEL_PGP]);

        for key in subkeys {
            let subkey_metadata = KeyMetadata {
                sq_dsm_version: version.clone(),
                fingerprint:    key.fingerprint().to_hex(),
                key_flags:      key.key_flags(),
                certificate:    None,
                hash_algo,
                symm_algo,
                external_creation_timestamp: None,
            }.to_custom_metadata()?;
            println!("For subkey:\nkey=sq_dsm\nvalue={}\n", subkey_metadata[DSM_LABEL_PGP]);
        }

        Ok(())
    }
}

/// Generates an OpenPGP key with secrets stored in DSM. At the OpenPGP
/// level, this method produces a PGP key with the structure given by the
/// `key_flags` argument.
/// For example, `[CS,EtEr]` produces a PGP key with a primary key used
/// for both certification and signing and an encryption subkey, and `[C,S,EtEr]`
/// produces a PGP key with a certification primary key, a signing subkey, and
/// an encryption subkey.
///
/// At the DSM level, this method creates corresponding Sobjects,
/// linked by KeyLinks.
///
/// The public certificate (Transferable Public Key) is computed, stored as
/// an additional custom metadata field on the primary key.
pub fn generate_key(
    key_name: &str,
    key_flag_args: Vec<KeyFlags>,
    validity_period: Option<Duration>,
    user_id: Option<&str>,
    algo: Option<&str>,
    exportable: bool,
    credentials: Credentials,
) -> Result<()> {

    if key_flag_args.is_empty() {
        return Err(Error::msg("key_flags not specified."))
    }
    let c = KeyFlags::empty().set_certification();
    let s = KeyFlags::empty().set_signing();
    let cs = KeyFlags::empty().set_certification().set_signing();
    let eter = KeyFlags::empty().set_storage_encryption().set_transport_encryption();
    let prim_flags = match key_flag_args.len() {
        2 => {
            if (key_flag_args[0] != cs)
                || (key_flag_args[1] != eter) {
                    return Err(Error::msg("key_flags supported structures are CS,EtEr and C,S,EtEr."));
            }
            KeyFlags::empty().set_certification().set_signing()
        },
        3 =>  {
            if (key_flag_args[0] != c)
                || (key_flag_args[1] != s)
                || (key_flag_args[2] != eter) {
                    return Err(Error::msg("key_flags supported structures are CS,EtEr and C,S,EtEr."));
            }
            KeyFlags::empty().set_certification()
        },
        _ => return Err(Error::msg("key_flags supported structures are CS,EtEr and C,S,EtEr.")),
    };

    // Hash and symmetric algorithms for signatures/encryption
    let hash_algo = HashAlgorithm::SHA512;
    let symm_algo = SymmetricAlgorithm::AES256;

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
        Some("rsa8k") => SupportedPkAlgo::Rsa(8192),
        Some("cv25519") => SupportedPkAlgo::Curve25519,
        Some("nistp256") => SupportedPkAlgo::Ec(ApiCurve::NistP256),
        Some("nistp384") => SupportedPkAlgo::Ec(ApiCurve::NistP384),
        Some("nistp521") => SupportedPkAlgo::Ec(ApiCurve::NistP521),
        _ => unreachable!("argument has a default value"),
    };

    let dsm_client = credentials.dsm_client()?;

    info!("key generation: create primary key");
    let primary = PublicKey::create(
        &dsm_client,
        key_name.to_string(),
        KeyRole::Primary,
        &algorithm,
        exportable,
        validity_period
    )
    .context("could not create primary key")?;

    let mut signing_subkeys: Vec<PublicKey> = vec![];
    let mut encryption_subkeys: Vec<PublicKey> = vec![];
    for key_flag in key_flag_args.iter().skip(1) {
        if key_flag.for_signing() {
            info!("key generation: create signing subkey");
            let signing_subkey = PublicKey::create(
                &dsm_client,
                key_name.to_string(),
                KeyRole::SigningSubkey,
                &algorithm,
                exportable,
                validity_period
            )?;

            signing_subkeys.push(signing_subkey);
        }

        if key_flag.for_storage_encryption() & key_flag.for_transport_encryption() {
            info!("key generation: create decryption subkey");
            let encryption_subkey = PublicKey::create(
                &dsm_client,
                key_name.to_string(),
                KeyRole::EncryptionSubkey,
                &algorithm,
                exportable,
                validity_period
            )?;

            encryption_subkeys.push(encryption_subkey);
        }
    }

    let signing_subkey_flags = KeyFlags::empty().set_signing();
    let encryption_subkey_flags = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let links = KeyLinks {
        parent: Some(primary.uid()?),
        ..Default::default()
    };
    let link_update_req = SobjectRequest {
        links: Some(links),
        ..Default::default()
    };
    info!("key generation: bind subkeys to primary key in DSM");
    for subkey in &signing_subkeys {
        dsm_client.__update_sobject(
            &subkey.uid()?, &link_update_req, "bind subkey to primary key"
        )?;
    }
    for subkey in &encryption_subkeys {
        dsm_client.__update_sobject(
            &subkey.uid()?, &link_update_req, "bind subkey to primary key"
        )?;
    }

    // Primary + sig, UserID + sig, subkeys + sigs
    let mut packets = Vec::<Packet>::with_capacity(8);

    info!("key generation: self-sign primary key");
    let prim: Key<PublicParts, PrimaryRole> = primary
        .sequoia_key
        .clone()
        .context("unloaded primary key")?
        .into();
    let prim_fingerprint = prim.fingerprint().to_hex();
    let prim_id = prim.keyid().to_hex();
    let prim_creation_time = prim.creation_time();

    // To sign other keys and packets
    let mut prim_signer = DsmAgent::new_certifier(credentials.clone(), key_name)?;

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
        .set_hash_algo(hash_algo);

    // A direct key signature is always over the primary key.
    let prim_sig = prim_sig_builder.sign_direct_key(&mut prim_signer, None)?;

    packets.push(prim.into());
    packets.push(prim_sig.into());

    let mut cert = Cert::try_from(packets)?;

    // User ID + signature
    info!("key generation: sign user ID");
    {
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
    }

    if !encryption_subkeys.is_empty() {
        info!("key generation: sign encryption subkey");
        {
            let (subkey, flags) = (&encryption_subkeys[0], &encryption_subkey_flags);
            let pk: Key<PublicParts, SubordinateRole> = subkey
                .sequoia_key.as_ref().context("unloaded subkey")?.clone().into();

            let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_key_validity_period(validity_period)?
                .set_hash_algo(hash_algo)
                .set_signature_creation_time(pk.creation_time())?
                .set_key_flags(flags.clone())?;

            let signature = pk.bind(&mut prim_signer, &cert, builder)?;
            cert = cert.insert_packets(vec![Packet::from(pk), signature.into()])?;
        }
    }

    if !signing_subkeys.is_empty() {
        info!("key generation: create embedded signature (signing-subkey signs primary)");
        // To sign primary key
        let mut subkey_signer = DsmAgent::new_signing_subkey_from_descriptor(
            credentials, &signing_subkeys[0].descriptor)?;
        let embedded_signature = {
            let subkey: Key<PublicParts, SubordinateRole> = signing_subkeys[0]
                .sequoia_key.as_ref().context("unloaded subkey")?.clone().into();

            let pk: Key<PublicParts, PrimaryRole> = primary
                .sequoia_key.as_ref().context("unloaded subkey")?.clone().into();

            SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                .set_key_validity_period(validity_period)?
                .set_hash_algo(hash_algo)
                .set_signature_creation_time(subkey.creation_time())?
                .sign_primary_key_binding(&mut subkey_signer, &pk, &subkey)?
        };

        info!("key generation: sign signing key");
        {
            let (subkey, flags) = (&signing_subkeys[0], &signing_subkey_flags);
            let pk: Key<PublicParts, SubordinateRole> = subkey
                .sequoia_key.as_ref().context("unloaded subkey")?.clone().into();

            let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_key_validity_period(validity_period)?
                .set_hash_algo(hash_algo)
                .set_signature_creation_time(pk.creation_time())?
                .set_key_flags(flags.clone())?
                .set_embedded_signature(embedded_signature)?;

            let signature = pk.bind(&mut prim_signer, &cert, builder)?;
            cert = cert.insert_packets(vec![Packet::from(pk), signature.into()])?;
        }
    }

    info!("key generation: store primary metadata");
    {
        let primary_desc = format!(
            "PGP primary, {}, {}", prim_id, prim_flags.human_readable()
        );
        let prim_metadata = KeyMetadata {
            sq_dsm_version: SQ_DSM_VERSION.to_string(),
            fingerprint:    prim_fingerprint,
            key_flags:      Some(prim_flags),
            certificate:    Some(String::from_utf8(cert.armored().to_vec()?)?),
            ..Default::default()
        }.to_custom_metadata()?;
        let update_req = SobjectRequest {
            description:     Some(primary_desc),
            custom_metadata: Some(prim_metadata),
            ..Default::default()
        };
        dsm_client.__update_sobject(
            &primary.uid()?, &update_req, "store PGP certificate as metadata"
        )?;
    }

    info!("key generation: rename subkeys and store metadata");
    let mut subkey_flag:Vec<(&PublicKey, &KeyFlags)> = vec![];
    if !signing_subkeys.is_empty() {
        subkey_flag.push((&signing_subkeys[0], &signing_subkey_flags));
    }
    if !encryption_subkeys.is_empty() {
        subkey_flag.push((&encryption_subkeys[0], &encryption_subkey_flags));
    }
    for (subkey, flags) in subkey_flag {
        let pk: Key<PublicParts, SubordinateRole> = subkey
            .sequoia_key.as_ref().context("unloaded subkey")?.clone().into();

        let subkey_name = format!(
            "{} {}/{}", key_name, pk.keyid().to_hex(), prim_id,
        ).to_string();
        let subkey_desc = format!(
            "PGP subkey, {}", flags.human_readable()
        );
        let key_json = serde_json::to_string(&KeyMetadata {
            sq_dsm_version:              SQ_DSM_VERSION.to_string(),
            fingerprint:                 pk.fingerprint().to_hex(),
            key_flags:                   Some(flags.clone()),
            certificate:                 None,
            external_creation_timestamp: None,
            hash_algo:                   Some(hash_algo),
            symm_algo:                   Some(symm_algo),
        })?;
        let mut sub_metadata = HashMap::<String, String>::new();
        sub_metadata.insert(DSM_LABEL_PGP.to_string(), key_json);
        let update_req = SobjectRequest {
            name:            Some(subkey_name),
            description:     Some(subkey_desc),
            custom_metadata: Some(sub_metadata),
            ..Default::default()
        };
        dsm_client.__update_sobject(
            &subkey.uid()?, &update_req, "store subkey metadata"
        )?;
    }

    Ok(())
}

pub struct DsmKeyInfo {
    name: String,
    kid: Uuid,
    object_type: ObjectType,
    created_at: SdkmsTime,
    last_used_at: SdkmsTime,
    fingerprint: String,
}

impl TryFrom<&Sobject> for DsmKeyInfo {
    type Error = anyhow::Error;

    /// Expects `DSM_LABEL_PGP` key to be present in metadata.
    fn try_from(key: &Sobject) -> Result<Self, Self::Error> {
        let key_md = KeyMetadata::from_sobject(&key)?;
        Ok(DsmKeyInfo { 
            name: key.name.as_ref()
                .ok_or(anyhow::anyhow!("Key name not present"))?
                .into(),
            kid: key.kid
                .ok_or(anyhow::anyhow!("Key ID not present"))?,
            object_type: key.obj_type,
            created_at: key.created_at,
            last_used_at: key.lastused_at,
            fingerprint: key_md.fingerprint,
        })
    }
}

impl DsmKeyInfo {
    /// Prints key details in concise format, includes name, uuid, created_at
     pub fn format_details_short(&self) -> String {
        format!(
            "{}  {}  {name:<20.*}",
            self.kid,
            self.created_at.to_datetime(),
            20,
            name = self.name,
            )
    }

    /// Prints key details in verbose format, includes all fields.
    pub fn format_details_long(&self) -> String {
        format!(
            "{}:
    UUID: {}
    Object Type: {:?}
    Created at: {}
    Last used at: {}
    PGP fingerprint: {}
",
            self.name,
            self.kid,
            self.object_type,
            self.created_at.to_datetime(),
            if self.last_used_at.eq(&SdkmsTime(0)) {
                "NA".into()
            } else {
                self.last_used_at.to_datetime().to_string()
            },
            self.fingerprint
        )
    }
}

/// Gets info on a key and prints revelant PGP details for it.
/// Returns `Err` if key is not present.
pub fn dsm_key_info(cred: Credentials, key_name: &str) -> Result<Option<DsmKeyInfo>> {
    info!("dsm key_info");
    let dsm_client = cred.dsm_client()?;

    let params = ListSobjectsParams {
        name: Some(key_name.to_string()),
        ..Default::default()
    };

    let key: DsmKeyInfo = match dsm_client.list_sobjects(Some(&params))?.first() {
        Some(key) => key.try_into()?,
        None => return Err(anyhow::anyhow!("no key with name {} exists",
                                           &key_name)),
    };

    Ok(Some(key))
}

/// Iterates through accessible groups and fetches all keys available to app.
/// Returns a sorted list of keys grouped by group ID.
pub fn list_keys(cred: Credentials) -> Result<Vec<DsmKeyInfo>> {
    info!("dsm list_keys");
    let dsm_client = cred.dsm_client()?;
    let mut key_info_store: Vec<DsmKeyInfo> = Vec::new();

    let groups = dsm_client.list_groups()?;


    for group in groups {
        let params = ListSobjectsParams {
            group_id: Some(group.group_id),
            ..Default::default()
        };

        for key_details in dsm_client.list_sobjects(Some(&params))?
            .iter()
            .filter(|key|
                    match &key.custom_metadata {
                        Some(metadata) => metadata.contains_key(&DSM_LABEL_PGP.to_string()),
                        None => false,
                    })
            .map(|key| DsmKeyInfo::try_from(key)) {
            key_info_store.push(key_details?);
        }
    }

    Ok(key_info_store)
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
    let packet = secret_packet_from_sobject(&prim_sob)?;
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
            let packet = secret_packet_from_sobject(&sob)?;
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

/// Imports a given Transferable Secret Key (TSK) or a Transferable Public Key (TPK) into DSM.
pub fn import_key_to_dsm(
    tsk:        ValidCert,
    key_name:   &str,
    cred:       Credentials,
    exportable: bool,
) -> Result<()> {

    fn import_constructed_sobject(
        cred:     &Credentials,
        name:     String,
        desc:     String,
        ops:      KeyOperations,
        metadata: &mut KeyMetadata,
        mpis:     &MpiPublic,
        hazmat:   Option<&MpiSecret>,
        deact:    Option<SdkmsTime>,
    ) -> Result<Uuid> {
        let req = match (mpis, hazmat) {
            (MpiPublic::RSA{ e, n }, Some(MpiSecret::RSA { d, p, q, u })) => {
                let value = der::serialize::rsa_private(n, e, d, p, q, u);
                let key_size = n.bits() as u32;
                let rsa_opts = if ops.contains(KeyOperations::SIGN) {
                    let sig_policy = RsaSignaturePolicy {
                        padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                    };
                    Some(RsaOptions {
                        signature_policy: vec![sig_policy],
                        ..Default::default()
                    })
                } else if ops.contains(KeyOperations::DECRYPT) {
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
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Rsa),
                    key_ops:           Some(ops),
                    key_size:          Some(key_size),
                    rsa:               rsa_opts,
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::RSA{ e, n }, None) => {
                let value = der::serialize::spki_rsa(n, e);
                let key_size = n.bits() as u32;
                let rsa_opts = if ops.contains(KeyOperations::SIGN) {
                    let sig_policy = RsaSignaturePolicy {
                        padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                    };
                    Some(RsaOptions {
                        signature_policy: vec![sig_policy],
                        ..Default::default()
                    })
                } else if ops.contains(KeyOperations::DECRYPT) {
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
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Rsa),
                    key_ops:           Some(ops),
                    key_size:          Some(key_size),
                    rsa:               rsa_opts,
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::EdDSA { curve, .. }, Some(MpiSecret::EdDSA { scalar })) => {
                let value = der::serialize::ec_private(curve, scalar)?;
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::EdDSA { curve, q }, None ) => {
                let value = der::serialize::spki_ec(curve, q);
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::ECDSA { curve, q }, None) => {
                let value = der::serialize::spki_ec(curve, q);
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::ECDH { curve, q, hash, sym }, None) => {
                let value = der::serialize::spki_ec(curve, q);
                metadata.hash_algo = Some(*hash);
                metadata.symm_algo = Some(*sym);
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::ECDSA { curve, .. },Some( MpiSecret::ECDSA { scalar })) => {
                let value = der::serialize::ec_private(curve, scalar)?;
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            (MpiPublic::ECDH { curve, q: _, hash, sym }, Some(MpiSecret::ECDH { scalar })) => {
                let value = der::serialize::ec_private(curve, scalar)?;
                metadata.hash_algo = Some(*hash);
                metadata.symm_algo = Some(*sym);
                SobjectRequest {
                    name:              Some(name.clone()),
                    custom_metadata:   Some(metadata.to_custom_metadata()?),
                    description:       Some(desc),
                    obj_type:          Some(ObjectType::Ec),
                    key_ops:           Some(ops),
                    value:             Some(value.into()),
                    deactivation_date: deact,
                    ..Default::default()
                }
            },
            _ => unimplemented!("public key algorithm")
        };

        Ok(
            cred.dsm_client()?
            .import_sobject(&req)
            .context(format!("could not import secret {}", name))?
            .kid
            .ok_or(anyhow::anyhow!("no UUID returned from DSM"))?
        )
    }

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
        is_secret_key: bool,
    ) -> KeyOperations {
        let mut ops = KeyOperations::APPMANAGEABLE;

        if exportable {
            ops |= KeyOperations::EXPORT;
        }

        if is_secret_key{
            // SECRET KEY
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
        } else {
            // PUBLIC KEY
            if let Some(f) = key_flags {
                if f.for_signing() | f.for_certification() {
                    ops |= KeyOperations::VERIFY;
                }

                if f.for_transport_encryption() | f.for_storage_encryption() {
                    if pk_algo == PublicKeyAlgorithm::ECDH {
                        ops |= KeyOperations::AGREEKEY;
                    } else{
                        ops |= KeyOperations::ENCRYPT;
                    }
                }
            }
        }

        ops
    }

    let prim_key = tsk.primary_key();
    let key = prim_key.key();

    let (secret_key, public_key, is_secret_key) = match key.clone().parts_into_secret() {
        Ok(v) => (Some(v), None, true),
        Err(_e) => (None, Some(key.clone().parts_into_public()), false),
    };

    let (key_creation_time, creation_secs) = if is_secret_key {
        // If it's a secret key, calculate creation time using the secret key's creation time
        let creation_time = secret_key.as_ref().unwrap().creation_time();
        let creation_secs = creation_time.duration_since(UNIX_EPOCH)?.as_secs();
        (creation_time, creation_secs)
    } else {
        // If it's a public key, calculate creation time using the public key's creation time
        let creation_time = public_key.as_ref().unwrap().creation_time();
        let creation_secs = creation_time.duration_since(UNIX_EPOCH)?.as_secs();
        (creation_time, creation_secs)
    };
    
    let creation_time = Timestamp::try_from(key_creation_time)?;
    
    let prim_flags = tsk.primary_key()
        .key_flags()
        .ok_or_else(|| anyhow::anyhow!("Bad input: primary has no key flags"))?;
    let prim_id = prim_key.keyid().to_hex();
    let prim_name = key_name.to_string();
    let prim_desc = format!(
        "PGP primary, {}, {}", prim_id, prim_flags.human_readable()
    );
    let prim_deactivation = if let Some(d) = prim_key.key_validity_period() {
        Some(SdkmsTime(creation_secs + d.as_secs()))
    } else {
        None
    };

    let armored = String::from_utf8(tsk.cert().armored().to_vec()?)?;
    let mut prim_metadata = KeyMetadata {
        sq_dsm_version:              SQ_DSM_VERSION.to_string(),
        fingerprint:                 prim_key.fingerprint().to_hex(),
        key_flags:                   Some(prim_flags),
        certificate:                 Some(armored),
        external_creation_timestamp: Some(creation_time.into()),
        ..Default::default()
    };

    let prim_ops = get_operations(
        prim_key.key_flags(),
        prim_key.pk_algo(),
        exportable,
        is_secret_key
    );

    let (prim_hazmat, mpis) = if is_secret_key {
        let secret = secret_key.as_ref().unwrap();
        (Some(get_hazardous_material(secret)), secret.mpis())
    } else {
        let public = public_key.as_ref().unwrap();
        (None, public.mpis())
    };

    let prim_uuid = import_constructed_sobject( 
        &cred,
        prim_name,
        prim_desc,
        prim_ops,
        &mut prim_metadata,
        mpis,
        prim_hazmat.as_ref(),
        prim_deactivation
    )?;

    if is_secret_key{
        // TSK SubKeys
        for subkey in tsk.keys().subkeys().unencrypted_secret() {
            let creation_time = Timestamp::try_from(subkey.creation_time())?;
            let subkey_flags = subkey.key_flags().unwrap_or_else(KeyFlags::empty);
            let subkey_id = subkey.keyid().to_hex();
            let subkey_name = format!(
                "{} {}/{}", key_name, prim_id, subkey_id,
            ).to_string();
            let subkey_desc = format!(
                "PGP subkey, {}", subkey_flags.human_readable()
            );
            let subkey_deactivation = if let Some(d) = subkey.key_validity_period() {
                let creation_secs = subkey
                    .creation_time()
                    .duration_since(UNIX_EPOCH)?.as_secs();
                Some(SdkmsTime(creation_secs + d.as_secs()))
            } else {
                None
            };
    
            let mut subkey_md = KeyMetadata {
                certificate:                 None,
                sq_dsm_version:              SQ_DSM_VERSION.to_string(),
                external_creation_timestamp: Some(creation_time.into()),
                fingerprint:                 subkey.fingerprint().to_hex(),
                key_flags:                   Some(subkey_flags),
                ..Default::default()
            };
    
            let subkey_ops = get_operations(
                subkey.key_flags(),
                subkey.pk_algo(),
                exportable,
                is_secret_key
            );
    
            let subkey_hazmat = Some(get_hazardous_material(&subkey));
    
            info!("import subkey {}", subkey_name);
            let subkey_uuid = import_constructed_sobject(
                &cred,
                subkey_name.clone(),
                subkey_desc,
                subkey_ops,
                &mut subkey_md,
                subkey.mpis(),
                subkey_hazmat.as_ref(),
                subkey_deactivation,
            )?;
    
            info!("bind subkey {} to primary key in DSM", subkey_name);
            let link_req = SobjectRequest {
                links: Some(KeyLinks {
                    parent: Some(prim_uuid),
                    ..Default::default()
                }),
                ..Default::default()
            };
    
            cred.dsm_client()?.__update_sobject(
                &subkey_uuid, &link_req, "bind subkey to primary key"
            )?;
        }
    }else {
        // TPK SubKeys
        for subkey in tsk.keys().subkeys() {
            let creation_time = Timestamp::try_from(subkey.creation_time())?;
            let subkey_flags = subkey.key_flags().unwrap_or_else(KeyFlags::empty);
            let subkey_id = subkey.keyid().to_hex();
            let subkey_name = format!(
                "{} {}/{}", key_name, prim_id, subkey_id,
            ).to_string();
            let subkey_desc = format!(
                "PGP subkey, {}", subkey_flags.human_readable()
            );
            let subkey_deactivation = if let Some(d) = subkey.key_validity_period() {
                let creation_secs = subkey
                    .creation_time()
                    .duration_since(UNIX_EPOCH)?.as_secs();
                Some(SdkmsTime(creation_secs + d.as_secs()))
            } else {
                None
            };
    
            let mut subkey_md = KeyMetadata {
                certificate:                 None,
                sq_dsm_version:              SQ_DSM_VERSION.to_string(),
                external_creation_timestamp: Some(creation_time.into()),
                fingerprint:                 subkey.fingerprint().to_hex(),
                key_flags:                   Some(subkey_flags),
                ..Default::default()
            };
    
            let subkey_ops = get_operations(
                subkey.key_flags(),
                subkey.pk_algo(),
                exportable,
                is_secret_key
            );
    
            info!("import subkey {}", subkey_name);
            let subkey_uuid = import_constructed_sobject(
                &cred,
                subkey_name.clone(),
                subkey_desc,
                subkey_ops,
                &mut subkey_md,
                subkey.mpis(),
                None,
                subkey_deactivation,
            )?;
    
            info!("bind subkey {} to primary key in DSM", subkey_name);
            let link_req = SobjectRequest {
                links: Some(KeyLinks {
                    parent: Some(prim_uuid),
                    ..Default::default()
                }),
                ..Default::default()
            };
    
            cred.dsm_client()?.__update_sobject(
                &subkey_uuid, &link_req, "bind subkey to primary key"
            )?;
        }
    }

    Ok(())
}

impl PublicKey {
    // Creates the private key inside DSM and returns the associated PublicKey
    fn create(
        client: &DsmClient,
        key_name: String,
        role: KeyRole,
        algo: &SupportedPkAlgo,
        exportable: bool,
        validity_period: Option<Duration>
    ) -> Result<Self> {
        let name = match role {
            KeyRole::Primary => key_name,
            KeyRole::EncryptionSubkey => key_name + " (PGP: decryption subkey)",
            KeyRole::SigningSubkey => key_name + " (PGP: signing subkey)",
        };

        let mut sobject_request = match (&role, algo) {
            (KeyRole::Primary | KeyRole::SigningSubkey, SupportedPkAlgo::Rsa(key_size)) => {
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
            (KeyRole::EncryptionSubkey, SupportedPkAlgo::Rsa(key_size)) => {
                let enc_policy = RsaEncryptionPolicy {
                    padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                };
                let rsa_options = Some(RsaOptions {
                    encryption_policy: vec![enc_policy],
                    ..Default::default()
                });

                SobjectRequest {
                    name: Some(name),
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(
                        KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE,
                    ),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            }
            (KeyRole::Primary | KeyRole::SigningSubkey, SupportedPkAlgo::Curve25519) => SobjectRequest {
                name: Some(name),
                obj_type: Some(ObjectType::Ec),
                key_ops: Some(
                    KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
                ),
                elliptic_curve: Some(ApiCurve::Ed25519),
                ..Default::default()
            },
            (KeyRole::EncryptionSubkey, SupportedPkAlgo::Curve25519) => {
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
            (KeyRole::Primary | KeyRole::SigningSubkey, SupportedPkAlgo::Ec(curve)) => SobjectRequest {
                name: Some(name),
                obj_type: Some(ObjectType::Ec),
                key_ops: Some(
                    KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
                ),
                elliptic_curve: Some(*curve),
                ..Default::default()
            },
            (KeyRole::EncryptionSubkey, SupportedPkAlgo::Ec(curve)) => SobjectRequest {
                name: Some(name),
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

        sobject_request.deactivation_date = if let Some(d) = validity_period {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            Some(SdkmsTime(now + d.as_secs()))
        } else {
            None
        };

        let sobject = client.create_sobject(&sobject_request)
            .context("dsm client could not create sobject")?;

        PublicKey::from_sobject(sobject, role)
    }

    fn from_sobject(sob: Sobject, role: KeyRole) -> Result<Self> {
        let default_hash = HashAlgorithm::SHA512;
        let default_symm = SymmetricAlgorithm::AES256;
        let descriptor = SobjectDescriptor::Kid(sob.kid.context("no kid")?);

        // Newly created Sobjects don't have metadata yet
        let md = KeyMetadata::from_sobject(&sob).unwrap_or_default();
        let time: SystemTime = if let Some(secs) = md.external_creation_timestamp {
            Timestamp::from(secs).into()
        } else {
            sob.created_at.to_datetime().into()
        };

        let raw_pk = sob.pub_key.context("public bits of sobject missing")?;

        let (pk_algo, pk_material) = match sob.obj_type {
            ObjectType::Ec => match sob.elliptic_curve {
                Some(ApiCurve::Ed25519) => {
                    let pk_algo = PublicKeyAlgorithm::EdDSA;
                    let curve = SequoiaCurve::Ed25519;

                    // Strip the leading OID
                    let point = MPI::new_compressed_point(&raw_pk[12..]);

                    let ec_pk = MpiPublic::EdDSA { curve, q: point };
                    (pk_algo, ec_pk)
                }
                Some(ApiCurve::X25519) => {
                    let pk_algo = PublicKeyAlgorithm::ECDH;
                    let curve = SequoiaCurve::Cv25519;

                    // Strip the leading OID
                    let point = MPI::new_compressed_point(&raw_pk[12..]);

                    let ec_pk = MpiPublic::ECDH {
                        curve,
                        q: point,
                        hash: md.hash_algo.unwrap_or(default_hash),
                        sym: md.symm_algo.unwrap_or(default_symm),
                    };

                    (pk_algo, ec_pk)
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
                        KeyRole::Primary | KeyRole::SigningSubkey => (
                            PublicKeyAlgorithm::ECDSA,
                            MpiPublic::ECDSA { curve, q: point },
                        ),
                        KeyRole::EncryptionSubkey => (
                            PublicKeyAlgorithm::ECDH,
                            MpiPublic::ECDH {
                                curve,
                                q: point,
                                hash: md.hash_algo.unwrap_or(default_hash),
                                sym: md.symm_algo.unwrap_or(default_symm),
                            },
                        ),
                    };
                    (pk_algo, ec_pk)
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

                (pk_algo, pk_material)
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
                let data_length = c.value().len();

                // RSA Key size is not directly available, so we're estimating it based on the ciphertext size. 
                let target_length = match data_length {
                    len if len <= 256 => 256,     // likely RSA-2048
                    len if len <= 384 => 384,     // likely RSA-3072
                    len if len <= 512 => 512,     // likely RSA-4096
                    len if len <= 1024 => 1024,   // likely RSA-8192
                    _ => data_length,             // Return original length if no match
                };

                let mut cipher = c.value().to_vec().into();
                if data_length < target_length {
                    cipher = c.value_padded(target_length).context("Failed to adjust padding.")?.to_vec().into();
                }

                let decrypt_req = DecryptRequest {
                    cipher: cipher,
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
                    _ => return Err(Error::msg("inconsistent pk algo")),
                };

                let ephemeral_der = der::serialize::spki_ec(curve, e);

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

fn secret_packet_from_sobject(sobject: &Sobject) -> Result<Packet> {
    let md = KeyMetadata::from_sobject(sobject)?;

    let role = match md.key_flags {
        Some(f) if f.for_certification() => {
            KeyRole::Primary
        },
        Some(f) if f.for_signing() => {
            KeyRole::SigningSubkey
        },
        Some(f) if f.for_transport_encryption() || f.for_storage_encryption() => {
            KeyRole::EncryptionSubkey
        },
        _ => {
            return Err(anyhow::anyhow!(
                    "cannot deduce key role from Sobject flags"));
        }
    };

    let time: SystemTime = if let Some(secs) = md.external_creation_timestamp {
        Timestamp::from(secs).into()
    } else {
        sobject.created_at.to_datetime().into()
    };

    let raw_secret = sobject.value.as_ref()
        .context("secret bits missing in Sobject")?;
    let raw_public = sobject.pub_key.as_ref()
        .context("public bits missing in Sobject")?;
    let is_signer = (sobject.key_ops & KeyOperations::SIGN) == KeyOperations::SIGN;
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
                    KeyRole::SigningSubkey => Ok(Key::V4(
                        Key4::<_, SubordinateRole>::import_secret_ed25519(
                            secret, time,
                        )?,
                    )
                    .into()),
                    KeyRole::EncryptionSubkey => {
                        return Err(anyhow::anyhow!("encryption keys can't sign"))
                    },
                }
            }
            Some(ApiCurve::X25519) => {
                if raw_secret.len() < 16 {
                    return Err(anyhow::anyhow!("malformed X25519 secret"));
                }
                let secret = &raw_secret[16..];
                match role {
                    KeyRole::Primary | KeyRole::SigningSubkey => {
                        Err(anyhow::anyhow!("signing keys can't decrypt"))
                    },
                    KeyRole::EncryptionSubkey => Ok(Key::V4(
                        Key4::<_, SubordinateRole>::import_secret_cv25519(
                            secret, md.hash_algo, md.symm_algo, time,
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
                        hash: md.hash_algo.unwrap_or(HashAlgorithm::SHA512),
                        sym: md.symm_algo.unwrap_or(SymmetricAlgorithm::AES256),
                        q: point,
                    };
                };
                match role {
                    KeyRole::Primary => {
                        Ok(Key::V4(Key4::<_, PrimaryRole>::with_secret(
                            time, algo, public, secret,
                        )?).into())
                    }
                    KeyRole::EncryptionSubkey | KeyRole::SigningSubkey => {
                        Ok(Key::V4(Key4::<_, SubordinateRole>::with_secret(
                            time, algo, public, secret,
                        )?).into())
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
                KeyRole::SigningSubkey | KeyRole::EncryptionSubkey => Ok(Key::V4(
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

fn try_unlock_p12(cert_file: String, passphrase: Option<&str>) -> Result<Identity> {
    let mut cert_stream = File::open(cert_file.clone())
        .context(format!("opening {}", cert_file))?;
    let mut cert = Vec::new();
    cert_stream.read_to_end(&mut cert)
        .context(format!("reading {}", cert_file))?;
    // Try to unlock certificate with passed password, if any
    let mut first = true;
    if let Ok(id) = Identity::from_pkcs12(&cert, passphrase.unwrap_or("")) {
        Ok(id)
    } else {
        // Try to unlock with env var passphrase
        if let Ok(pass) = env::var(ENV_P12_PASS) {
            if let Ok(id) = Identity::from_pkcs12(&cert, &pass) {
                return Ok(id)
            } else {
                warn!("could not unlock PKCS12 identity with {:?}", ENV_P12_PASS);
            }
        }
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
                        return Ok(id)
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

trait HumanReadable {
    fn human_readable(&self) -> String;
}

impl HumanReadable for KeyFlags {
    fn human_readable(&self) -> String {
        let mut s = Vec::new();
        if self.for_certification() {
            s.push("Certification");
        }
        if self.for_signing() {
            s.push("Signing");
        }
        match (self.for_transport_encryption(), self.for_storage_encryption()) {
            (true, true) => s.push("Transport and Storage Encryption"),
            (true, false) => s.push("Transport Encryption"),
            (false, true) => s.push("Storage Encryption"),
            _ => {}
        }
        if self.is_split_key() {
            s.push("Split Key");
        }
        if self.for_authentication() {
            s.push("Authentication");
        }
        if self.is_group_key() {
            s.push("Group Key");
        }

        s.join(", ")
    }
}
