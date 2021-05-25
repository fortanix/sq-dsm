//! Fortanix Self-Defending KMS
//!
//! This module implements the necessary logic to use secrets stored inside
//! Fortanix SDKMS for low-level signing and decryption operations, given proper
//! credentials (namely, the `FORTANIX_API_KEY` and `FORTANIX_API_ENDPOINT`
//! environment variables).

use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::net::IpAddr;

use anyhow::{Context, Error, Result};
use bit_vec::BitVec;
use http::uri::Uri;
use hyper::client::{Client as HyperClient, ProxyConfig};
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use ipnetwork::IpNetwork;
use log::info;
use mbedtls::pk::Pk;
use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, DecryptRequest, DigestAlgorithm,
    EllipticCurve as ApiCurve, KeyOperations, ObjectType,
    RsaEncryptionPaddingPolicy, RsaEncryptionPolicy, RsaOptions,
    RsaSignaturePaddingPolicy, RsaSignaturePolicy, SignRequest, Sobject,
    SobjectDescriptor, SobjectRequest,
};
use sdkms::SdkmsClient;
use uuid::Uuid;
use yasna::models::ObjectIdentifier as Oid;

use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::mpi::PublicKey::ECDH;
use sequoia_openpgp::crypto::{ecdh, mpi, Decryptor, SessionKey, Signer};
use sequoia_openpgp::packet::key::{
    Key4, PrimaryRole, PublicParts, SubordinateRole, UnspecifiedRole
};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Key, UserID};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{
    Curve as SequoiaCurve, HashAlgorithm, KeyFlags, PublicKeyAlgorithm,
    SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};

/// SdkmsAgent implements [Signer] and [Decryptor] with secrets stored inside
/// Fortanix SDKMS.
///
///   [Decryptor]: ../../crypto/trait.Decryptor.html
///   [Signer]: ../../crypto/trait.Signer.html
pub struct SdkmsAgent {
    credentials: Credentials,
    descriptor:  SobjectDescriptor,
    public:      Key<PublicParts, UnspecifiedRole>,
    role:        Role,
}

const ENV_API_KEY: &str = "FORTANIX_API_KEY";
const ENV_API_ENDPOINT: &str = "FORTANIX_API_ENDPOINT";
const ENV_HTTP_PROXY: &str = "http_proxy";
const ENV_NO_PROXY: &str = "no_proxy";
const SUBKEY: &str = "subkey";

struct Credentials {
    api_endpoint: String,
    api_key:      String,
    proxy:        Option<Arc<HyperClient>>,
}

impl Credentials {
    fn new_from_env() -> Result<Self> {
        let api_endpoint = env::var(ENV_API_ENDPOINT)
            .with_context(|| format!("{} env var absent", ENV_API_ENDPOINT))?;
        let api_key = env::var(ENV_API_KEY)
            .with_context(|| format!("{} env var absent", ENV_API_KEY))?;
        let proxy = decide_proxy_from_env(&api_endpoint);

        Ok(Self {
            api_endpoint,
            api_key,
            proxy,
        })
    }

    fn http_client(&self) -> Result<SdkmsClient> {
        let mut builder = SdkmsClient::builder()
            .with_api_endpoint(&self.api_endpoint)
            .with_api_key(&self.api_key);
        if let Some(proxy) = &self.proxy {
            builder = builder.with_hyper_client(proxy.clone());
        }

        Ok(builder
            .build()
            .context("could not initiate an SDKMS client")?)
    }
}

#[derive(PartialEq)]
enum Role {
    Signer,
    Decryptor,
}

impl SdkmsAgent {
    /// Returns an SdkmsAgent with signing capabilities, corresponding to the
    /// given key name.
    pub fn new_signer(key_name: &str) -> Result<Self> {
        let credentials = Credentials::new_from_env()?;
        let http_client = credentials.http_client()?;

        let descriptor = SobjectDescriptor::Name(key_name.to_string());
        let sobject = http_client
            .get_sobject(None, &descriptor)
            .context(format!("could not get primary key {}", key_name))?;
        let key = PublicKey::from_sobject(sobject, KeyRole::Primary)?;

        Ok(SdkmsAgent {
            credentials,
            descriptor,
            public: key.sequoia_key.expect("key is not loaded"),
            role: Role::Signer,
        })
    }

    /// Returns an SdkmsAgent with decryption capabilities, corresponding to the
    /// given key name.
    pub fn new_decryptor(key_name: &str) -> Result<Self> {
        let credentials = Credentials::new_from_env()?;
        let http_client = credentials.http_client()?;

        let descriptor = SobjectDescriptor::Name(key_name.to_string());
        let sobject = http_client
            .get_sobject(None, &descriptor)
            .context(format!("could not get primary key {}", key_name))?;

        if let Some(dict) = sobject.custom_metadata {
            if dict.contains_key(SUBKEY) {
                let uid = Uuid::parse_str(&dict[SUBKEY])?;
                let descriptor = SobjectDescriptor::Kid(uid);
                let sobject = http_client
                    .get_sobject(None, &descriptor)
                    .context("could not get subkey".to_string())?;
                let key = PublicKey::from_sobject(sobject, KeyRole::Subkey)?;
                return Ok(SdkmsAgent {
                    descriptor,
                    public: key.sequoia_key.expect("key is not loaded"),
                    role: Role::Decryptor,
                    credentials,
                });
            }
        }
        Err(Error::msg("was not able to get decryption subkey"))
    }
}

#[derive(Clone)]
struct PublicKey {
    role: KeyRole,
    descriptor: SobjectDescriptor,
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

/// Generates an OpenPGP key with secrets stored in SDKMS. At the OpenPGP
/// level, this method produces a key consisting of
///
/// - A primary signing key (flags C + S),
/// - a transport and storage encryption subkey (flags Et + Er).
///
/// At the SDKMS level, this method creates the two corresponding Sobjects.
/// The encryption key's KID is stored as a custom metadata field of the
/// signing key.
///
/// The public certificate (Transferable Public Key) is computed, stored as
/// an additional custom metadata field on the primary key, and returned.
pub fn generate_key(key_name: &str,
                    user_id: Option<&str>,
                    algo: Option<&str>) -> Result<()> {
    let uid: UserID = match user_id {
        Some(id) => id.into(),
        None => return Err(Error::msg("no User ID")),
    };
    let algorithm = match algo {
        Some("rsa3k") => SupportedPkAlgo::Rsa(3072),
        Some("rsa4k") => SupportedPkAlgo::Rsa(4096),
        Some("cv25519") => SupportedPkAlgo::Curve25519,
        Some("nistp256") => SupportedPkAlgo::Ec(ApiCurve::NistP256),
        Some("nistp384") => SupportedPkAlgo::Ec(ApiCurve::NistP384),
        Some("nistp521") => SupportedPkAlgo::Ec(ApiCurve::NistP521),
        _ => unreachable!("argument has a default value"),
    };

    let credentials = Credentials::new_from_env()?;
    let http_client = credentials.http_client()?;

    info!("create primary key");
    let primary = PublicKey::create(
        &http_client,
        key_name.to_string(),
        KeyRole::Primary,
        &algorithm,
    )
    .context("could not create primary key")?;

    info!("create decryption subkey");
    let subkey = PublicKey::create(
        &http_client,
        key_name.to_string(),
        KeyRole::Subkey,
        &algorithm,
    )?;

    info!("generate certificate");
    // Primary, UserID + sig, subkey + sig
    let mut packets = Vec::<Packet>::with_capacity(5);

    // Self-sign primary key
    let prim: Key<PublicParts, PrimaryRole> = primary
        .sequoia_key
        .clone()
        .expect("unloaded primary key")
        .into();

    packets.push(prim.into());

    let mut prim_signer = SdkmsAgent::new_signer(&key_name)?;



    let primary_flags = KeyFlags::empty().set_certification().set_signing();

    let mut cert = Cert::try_from(packets)?;

    // User ID + signature
    let builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_primary_userid(true)?
        .set_key_flags(primary_flags)?
        .set_preferred_hash_algorithms(
            vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256]
            )?
        .set_preferred_symmetric_algorithms(
            vec![SymmetricAlgorithm::AES256, SymmetricAlgorithm::AES128]
        )?;
    let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

    cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

    // Subkey + signature
    let subkey_public: Key<PublicParts, SubordinateRole> = subkey
        .sequoia_key
        .as_ref()
        .expect("unloaded subkey")
        .clone()
        .into();

    let subkey_flags = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_key_flags(subkey_flags)?;

    let signature = subkey_public.bind(&mut prim_signer, &cert, builder)?;
    cert = cert
        .insert_packets(vec![Packet::from(subkey_public), signature.into()])?;

    info!("bind keys and store certificate in SDKMS");
    let armored = String::from_utf8(cert.armored().to_vec()?)?;

    let mut metadata = HashMap::<String, String>::new();
    metadata.insert(SUBKEY.to_string(), subkey.uid()?.to_string());
    metadata.insert("certificate".to_string(), armored);

    let update_req = SobjectRequest {
        custom_metadata: Some(metadata),
        ..Default::default()
    };

    http_client.update_sobject(&primary.uid()?, &update_req)?;

    Ok(())
}

/// Extracts the certificate of the corresponding PGP key. Note that this
/// certificate, created at key-generation time, is stored in the custom
/// metadata of the Security Object representing the primary key.
pub fn extract_cert(key_name: &str) -> Result<Cert> {
    info!("sdkms extract_cert");
    let credentials = Credentials::new_from_env()?;
    let http_client = credentials.http_client()?;

    let metadata = {
        let req = SobjectDescriptor::Name(key_name.to_string());
        let sobject = http_client
            .get_sobject(None, &req)
            .context(format!("could not get primary key {}", key_name))?;

        match sobject.custom_metadata {
            None => return Err(Error::msg("metadata not found".to_string())),
            Some(dict) => dict,
        }
    };

    Ok(Cert::from_str(&metadata["certificate"])?)
}

impl PublicKey {
    fn create(
        client: &SdkmsClient,
        name: String,
        role: KeyRole,
        algo: &SupportedPkAlgo,
    ) -> Result<Self> {
        let description = Some("Created with sq-sdkms".to_string());

        let sobject_request = match (&role, algo) {
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
                    description,
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(
                        KeyOperations::SIGN | KeyOperations::APPMANAGEABLE
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
                    description,
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(
                        KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE
                        ),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            }
            (KeyRole::Primary, SupportedPkAlgo::Curve25519) => {
                SobjectRequest {
                    name: Some(name),
                    description,
                    obj_type: Some(ObjectType::Ec),
                    key_ops: Some(
                        KeyOperations::SIGN | KeyOperations::APPMANAGEABLE
                    ),
                    elliptic_curve: Some(ApiCurve::Ed25519),
                    ..Default::default()
                }
            }
            (KeyRole::Subkey, SupportedPkAlgo::Curve25519) => {
                let name = name + " (PGP: decryption subkey)";

                SobjectRequest {
                    name: Some(name),
                    description,
                    obj_type: Some(ObjectType::Ec),
                    key_ops: Some(
                        KeyOperations::AGREEKEY | KeyOperations::APPMANAGEABLE
                    ),
                    elliptic_curve: Some(ApiCurve::X25519),
                    ..Default::default()
                }
            }
            (KeyRole::Primary, SupportedPkAlgo::Ec(curve)) => {
                SobjectRequest {
                    name: Some(name),
                    description,
                    obj_type: Some(ObjectType::Ec),
                    key_ops: Some(
                        KeyOperations::SIGN | KeyOperations::APPMANAGEABLE
                    ),
                    elliptic_curve: Some(*curve),
                    ..Default::default()
                }
            }
            (KeyRole::Subkey, SupportedPkAlgo::Ec(curve)) => {
                SobjectRequest {
                    name: Some(name + " (PGP: decryption subkey)"),
                    description,
                    obj_type: Some(ObjectType::Ec),
                    key_ops: Some(
                        KeyOperations::AGREEKEY | KeyOperations::APPMANAGEABLE
                    ),
                    elliptic_curve: Some(*curve),
                    ..Default::default()
                }
            }
        };

        let sobject = client.create_sobject(&sobject_request)?;

        PublicKey::from_sobject(sobject, role)
    }

    fn from_sobject(sob: Sobject, role: KeyRole) -> Result<Self> {
        let descriptor = SobjectDescriptor::Kid(sob.kid.context("no kid")?);
        let time = sob.created_at.to_datetime();
        let raw_pk = sob.pub_key.context("public bits of sobject missing")?;

        match sob.obj_type {
            ObjectType::Ec => match sob.elliptic_curve {
                Some(ApiCurve::Ed25519) => {
                    if role == KeyRole::Subkey {
                        return Err(Error::msg("signing subkeys unsupported"));
                    }
                    let pk_algo = PublicKeyAlgorithm::EdDSA;
                    let curve = SequoiaCurve::Ed25519;

                    // Strip the leading OID
                    let point = mpi::MPI::new_compressed_point(&raw_pk[12..]);

                    let ec_pk = mpi::PublicKey::EdDSA { curve, q: point };
                    let key = Key::V4(
                        Key4::new(time, pk_algo, ec_pk)
                            .context("cannot import EC key into Sequoia")?,
                    );

                    Ok(PublicKey {
                        descriptor,
                        role: KeyRole::Primary,
                        sequoia_key: Some(key),
                    })
                }
                Some(ApiCurve::X25519) => {
                    let pk_algo = PublicKeyAlgorithm::ECDH;
                    let curve = SequoiaCurve::Cv25519;

                    // Strip the leading OID
                    let point = mpi::MPI::new_compressed_point(&raw_pk[12..]);

                    let ec_pk = mpi::PublicKey::ECDH {
                        curve,
                        q: point,
                        hash: HashAlgorithm::SHA512,
                        sym: SymmetricAlgorithm::AES256,
                    };

                    let key = Key::V4(
                        Key4::new(time, pk_algo, ec_pk)
                            .context("cannot import EC key into Sequoia")?,
                    );

                    Ok(PublicKey {
                        descriptor,
                        role: KeyRole::Subkey,
                        sequoia_key: Some(key),
                    })
                }
                Some(curve @ ApiCurve::NistP256) |
                    Some(curve @ ApiCurve::NistP384) |
                    Some(curve @ ApiCurve::NistP521) => {
                        let curve = sequoia_curve_from_api_curve(curve)?;
                        let deserialized_pk = Pk::from_public_key(&raw_pk)
                            .context("cannot deserialize key into mbedTLS")?;
                        let mbed_point = deserialized_pk.ec_public()?;
                        let bits_field = curve.bits()
                            .ok_or_else(|| Error::msg("bad curve"))?;
                        let point = mpi::MPI::new_point(
                            &mbed_point.x()?.to_binary()?,
                            &mbed_point.y()?.to_binary()?,
                            bits_field,
                        );
                        let (pk_algo, ec_pk) = match role {
                            KeyRole::Primary => (
                                PublicKeyAlgorithm::ECDSA,
                                mpi::PublicKey::ECDSA { curve, q: point },
                            ),
                            KeyRole::Subkey => (
                                PublicKeyAlgorithm::ECDH,
                                mpi::PublicKey::ECDH {
                                    curve,
                                    q: point,
                                    hash: HashAlgorithm::SHA512,
                                    sym: SymmetricAlgorithm::AES256,
                                },
                            ),
                        };
                        let key = Key::V4(
                            Key4::new(time, pk_algo, ec_pk)
                            .context("cannot import EC key into Sequoia")?,
                        );
                        Ok(PublicKey {
                            descriptor,
                            role,
                            sequoia_key: Some(key),
                        })
                    }
                Some(curve) => {
                    return Err(
                        Error::msg(format!("unimplemented curve: {:?}", curve))
                    )
                }
                None => return Err(Error::msg("Sobject has no curve attribute"))
            },
            ObjectType::Rsa => {
                let deserialized_pk = Pk::from_public_key(&raw_pk)
                    .context("cannot deserialize SDKMS key into mbedTLS")?;

                let (e, n) = (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                );
                let key = Key::V4(
                    Key4::import_public_rsa(&e, &n, Some(time.into()))
                    .context("cannot import RSA key into Sequoia")?,
                );

                Ok(PublicKey {
                    descriptor,
                    role,
                    sequoia_key: Some(key),
                })
            }
            t @ _ => {
                return Err(Error::msg(format!("unknown object : {:?}", t)));
            }
        }
    }

    fn uid(&self) -> Result<Uuid> {
        match self.descriptor {
            SobjectDescriptor::Kid(x) => Ok(x),
            _ => Err(Error::msg("bad descriptor")),
        }
    }
}

impl Signer for SdkmsAgent {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8]) -> Result<mpi::Signature> {
        if self.role != Role::Signer {
            return Err(Error::msg("bad role for SDKMS agent"));
        }
        let http_client = self.credentials.http_client()?;

        let hash_alg = match hash_algo {
            HashAlgorithm::SHA1 => DigestAlgorithm::Sha1,
            HashAlgorithm::SHA512 => DigestAlgorithm::Sha512,
            HashAlgorithm::SHA256 => DigestAlgorithm::Sha256,
            hash @ _ => {
                return Err(Error::msg(format!("unimplemented: {}", hash)));
            }
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
                let sign_resp = http_client.sign(&sign_req)?;

                let plain: Vec<u8> = sign_resp.signature.into();
                Ok(mpi::Signature::RSA { s: plain.into() })
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
                let sign_resp = http_client.sign(&sign_req)?;

                let plain: Vec<u8> = sign_resp.signature.into();
                Ok(mpi::Signature::EdDSA {
                    r: mpi::MPI::new(&plain[..32]),
                    s: mpi::MPI::new(&plain[32..]),
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
                let sign_resp = http_client.sign(&sign_req)?;

                let plain: Vec<u8> = sign_resp.signature.into();
                let (r, s) = yasna::parse_der(&plain, |reader| {
                    reader.read_sequence(|reader| {
                        let r = reader.next().read_biguint()?.to_bytes_be();
                        let s = reader.next().read_biguint()?.to_bytes_be();
                        Ok((r, s))
                    })
                })
                .map_err(|e| anyhow::Error::msg(format!("ECDSA: {}", e)))?;

                Ok(mpi::Signature::ECDSA {
                    r: r.to_vec().into(),
                    s: s.to_vec().into(),
                })
            }
            algo @ _ => {
                return Err(Error::msg(format!("unknown algo: {}", algo)));
            }
        }
    }
}

const ID_ECDH: [u64; 6] = [1, 2, 840, 10045, 2, 1];

impl Decryptor for SdkmsAgent {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        if self.role != Role::Decryptor {
            return Err(Error::msg("bad role for SDKMS agent"));
        }
        let mut cli = SdkmsClient::builder()
            .with_api_endpoint(&self.credentials.api_endpoint)
            .with_api_key(&self.credentials.api_key)
            .build()?;

        match ciphertext {
            mpi::Ciphertext::RSA { c } => {
                let decrypt_req = DecryptRequest {
                    cipher: c.value().to_vec().into(),
                    alg:    Some(Rsa),
                    iv:     None,
                    key:    Some(self.descriptor.clone()),
                    mode:   None,
                    ad:     None,
                    tag:    None,
                };

                Ok(cli.decrypt(&decrypt_req)?.plain.to_vec().into())
            }
            mpi::Ciphertext::ECDH { e, .. } => {
                let curve = match &self.public.mpis() {
                    ECDH { curve, .. } => curve.clone(),
                    _ => return Err(Error::msg("inconsistent pk algo")),
                };

                cli = cli.authenticate_with_api_key(&self.credentials.api_key)?;

                let ephemeral_der = match curve {
                    SequoiaCurve::Cv25519 => {
                        let x = e.value()[1..].to_vec();

                        let oid = Oid::from_slice(&[1, 3, 101, 110]);
                        yasna::construct_der(|w| {
                            w.write_sequence(|w| {
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&oid);
                                });
                                w.next().write_bitvec(&BitVec::from_bytes(&x))
                            });
                        })
                    }
                    _ => {
                        //
                        // Note: SDKMS expects UNRESTRICTED ALGORITHM IDENTIFIER
                        // AND PARAMETERS (RFC5480 sec. 2.1.1) for Nist curves
                        //
                        let id_ecdh = Oid::from_slice(&ID_ECDH);
                        let named_curve = curve_oid(&curve)?;

                        let alg_id = yasna::construct_der(|writer| {
                            writer.write_sequence(|writer| {
                                writer.next().write_oid(&id_ecdh);
                                writer.next().write_oid(&named_curve);
                            });
                        });

                        let subj_public_key = BitVec::from_bytes(&e.value());
                        yasna::construct_der(|writer| {
                            writer.write_sequence(|writer| {
                                writer.next().write_der(&alg_id);
                                writer.next().write_bitvec(&subj_public_key);
                            });
                        })
                    }
                };

                // Import ephemeral public key
                let e_descriptor = {
                    let api_curve = api_curve_from_sequoia_curve(curve.clone())?;
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
                        .expect("failed import ephemeral public key into SDKMS")
                        .transient_key
                        .ok_or_else(|| {
                            Error::msg(
                                "could not retrieve SDKMS transient key \
                                 (representing ECDH ephemeral public key)",
                            )
                        })?;

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
                        key_size:          curve_key_size(&curve)?,
                        enabled:           true,
                        description:       None,
                        custom_metadata:   None,
                        key_ops:           Some(KeyOperations::EXPORT),
                        state:             None,
                        transient:         true,
                    };

                    let agreed_tkey = cli
                        .agree(&agree_req)
                        .expect("failed ECDH agreement on SDKMS")
                        .transient_key
                        .ok_or_else(|| Error::msg("could not retrieve agreed key"))?;

                    let desc = SobjectDescriptor::TransientKey(agreed_tkey);

                    cli.export_sobject(&desc)?
                        .value
                        .ok_or_else(|| Error::msg("could not retrieve secret"))?
                        .to_vec()
                        .into()
                };

                Ok(ecdh::decrypt_unwrap(&self.public, &secret, ciphertext)?
                    .to_vec()
                    .into())
            }
            _ => Err(Error::msg("unsupported/unknown algorithm")),
        }
    }
}

fn curve_oid(curve: &SequoiaCurve) -> Result<Oid> {
    match curve {
        SequoiaCurve::NistP256 => Ok(Oid::from_slice(&[1, 2, 840, 10045, 3, 1, 7])),
        SequoiaCurve::NistP384 => Ok(Oid::from_slice(&[1, 3, 132, 0, 34])),
        SequoiaCurve::NistP521 => Ok(Oid::from_slice(&[1, 3, 132, 0, 35])),
        SequoiaCurve::Cv25519 => Ok(Oid::from_slice(&[1, 3, 101, 110])),
        curve @ _ => Err(Error::msg(format!("unsupported curve {}", curve))),
    }
}

fn curve_key_size(curve: &SequoiaCurve) -> Result<u32> {
    match curve {
        SequoiaCurve::Cv25519 => Ok(253),
        SequoiaCurve::NistP256 => Ok(256),
        SequoiaCurve::NistP384 => Ok(384),
        SequoiaCurve::NistP521 => Ok(521),
        curve @ _ => Err(Error::msg(format!("unsupported curve {}", curve))),
    }
}

fn sequoia_curve_from_api_curve(curve: ApiCurve) -> Result<SequoiaCurve> {
    match curve {
        ApiCurve::X25519 => Ok(SequoiaCurve::Cv25519),
        ApiCurve::Ed25519 => Ok(SequoiaCurve::Ed25519),
        ApiCurve::NistP256 => Ok(SequoiaCurve::NistP256),
        ApiCurve::NistP384 => Ok(SequoiaCurve::NistP384),
        ApiCurve::NistP521 => Ok(SequoiaCurve::NistP521),
        _ => Err(Error::msg("cannot convert curve")),
    }
}

fn api_curve_from_sequoia_curve(curve: SequoiaCurve) -> Result<ApiCurve> {
    match curve {
        SequoiaCurve::Cv25519 => Ok(ApiCurve::X25519),
        SequoiaCurve::Ed25519 => Ok(ApiCurve::Ed25519),
        SequoiaCurve::NistP256 => Ok(ApiCurve::NistP256),
        SequoiaCurve::NistP384 => Ok(ApiCurve::NistP384),
        SequoiaCurve::NistP521 => Ok(ApiCurve::NistP521),
        curve @ _ => Err(Error::msg(format!("unsupported curve {}", curve))),
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
            .split(",")
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
    fn is_no_proxy_match(no_proxy: &NoProxyEntry, host: &str, port: u16) -> bool {
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
    pub ipnetwork: Option<IpNetwork>,
    pub split_hostname: Vec<String>,
    pub port: Option<u16>,
}

impl FromStr for NoProxyEntry {
    type Err = ();

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        // split host and port from no_proxy

        let mut no_proxy_splits = s.trim().splitn(2, ":");
        let no_proxy_host = no_proxy_splits.next().ok_or_else(|| ())?;
        let no_proxy_port = no_proxy_splits.next()
            .and_then(|port| port.parse().ok());

        // remove leading dot
        let no_proxy_host = no_proxy_host.trim_start_matches('.');

        Ok(NoProxyEntry {
            ipnetwork: IpNetwork::from_str(no_proxy_host).ok(),
            split_hostname: no_proxy_host.split(".").map(String::from).collect(),
            port: no_proxy_port,
        })
    }
}

fn decide_proxy_from_env(endpoint: &str) -> Option<Arc::<HyperClient>> {
    let uri = endpoint.parse::<Uri>().ok()?;
    let endpoint_host = uri.host()?;
    let endpoint_port = uri.port().map_or(80, |p| p.as_u16());
    if let Ok(proxy) = env::var(ENV_HTTP_PROXY) {
        let uri = proxy.parse::<Uri>().ok()?;
        let proxy_host = uri.host()?;
        let proxy_port = uri.port().map_or(80, |p| p.as_u16());

        //  If host is in no_proxy, then don't use the proxy
        let no_proxy = env::var(ENV_NO_PROXY).map(|list| NoProxy::parse(&list));
        if let Ok(s) = no_proxy {
            if !s.is_no_proxy(endpoint_host, endpoint_port) {
                let hyper_client = HyperClient::with_proxy_config(
                    ProxyConfig::new(
                        "http",
                        proxy_host.to_string(),
                        proxy_port,
                        HttpsConnector::new(NativeTlsClient::new().ok()?),
                        NativeTlsClient::new().ok()?,
                    ));
                return Some(Arc::new(hyper_client))
            }
        }
    }

    None
}
