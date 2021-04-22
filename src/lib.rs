use std::{
    collections::HashMap,
    convert::TryFrom,
    io::{Error as StdIoError, Write},
    string::FromUtf8Error,
    str::FromStr,
};

use log::info;

use uuid::{Uuid, parser::ParseError as UuidError};

use sdkms::{
    api_model::{
        KeyOperations, ObjectType, SobjectDescriptor, SobjectRequest,
        RsaEncryptionPolicy, RsaEncryptionPaddingPolicy,
        RsaOptions,
        RsaSignaturePolicy, RsaSignaturePaddingPolicy,
    },
    Error as SdkmsError,
    SdkmsClient,
};

use mbedtls::{
    Error as MbedtlsError,
    pk::Pk,
};

extern crate sequoia_openpgp as openpgp;

use openpgp::{
    Cert,
    crypto::SessionKey,
    KeyHandle,
    packet::{
        key::{
            Key4, PublicParts, PrimaryRole, SubordinateRole,
            UnspecifiedRole
        },
        Key,
        PKESK,
        signature::SignatureBuilder,
        SKESK,
        UserID,
    },
    parse::{
        stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper, MessageStructure},
        Parse,
    },
    Packet,
    policy::StandardPolicy,
    serialize::{SerializeInto, stream::{Armorer, LiteralWriter, Message, Signer}},
    types::{KeyFlags, HashAlgorithm, SymmetricAlgorithm, SignatureType},
};

use anyhow::Error as SequoiaError;

type Result<T> = core::result::Result<T, Error>;

mod signer;

mod decryptor;

use signer::RawSigner;
use decryptor::RawDecryptor;

#[derive(Debug)]
pub enum Error {
    Mbedtls(MbedtlsError),
    SdkmsBadResponse,
    SdkmsSubkeyNotFound,
    Sdkms(SdkmsError),
    Sequoia(SequoiaError),
    StdIo(StdIoError),
    Uuid(UuidError),
    Utf8(FromUtf8Error),
}

impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

pub struct PgpAgent {
    api_endpoint: String,
    api_key: String,
    primary: SequoiaKey,
    subkey: SequoiaKey,
    pub certificate: Cert,
}

#[derive(Clone)]
struct SequoiaKey {
    kid: Uuid,
    descriptor: SobjectDescriptor,
    public_key: Key<PublicParts, UnspecifiedRole>,
}

enum KeyRole {
    Primary,
    Subkey,
}

impl PgpAgent {
    /// TODO: Doc
    pub fn generate_key(
        api_endpoint: &str,
        api_key: &str,
        key_name: &str,
    ) -> Result<Self> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()?;

        fn raw_key(
            client: &SdkmsClient,
            mut name: String,
            op: KeyOperations,
            role: KeyRole,
        ) -> Result<SequoiaKey> {
            match role {
                KeyRole::Subkey => name += " (PGP: decryption subkey)",
                _ => ()
            }

            let enc_policy = RsaEncryptionPolicy {
                padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15{}),
            };

            let sig_policy = RsaSignaturePolicy {
                padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15{}),
            };

            let rsa_options = RsaOptions {
                encryption_policy: vec![enc_policy],
                signature_policy: vec![sig_policy],
                ..Default::default()
            };

            let sobject_req = SobjectRequest {
                name: Some(name),
                description: Some("SDKMS-PGP Tool".to_string()),
                obj_type: Some(ObjectType::Rsa),
                key_ops: Some(op),
                key_size: Some(2048),
                rsa: Some(rsa_options),
                ..Default::default()
            };

            let sobject = client.create_sobject(&sobject_req)?;
            let (e, n, time) = {
                let raw_pk = sobject.pub_key.ok_or(Error::SdkmsBadResponse)?;
                let deserialized_pk = Pk::from_public_key(&raw_pk)?;
                (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                    sobject.created_at.to_datetime(),
                )
            };

            let descriptor = sobject.kid.ok_or_else(|| Error::SdkmsBadResponse)?;
            Ok(SequoiaKey{
                kid: descriptor,
                descriptor: SobjectDescriptor::Kid(descriptor),
                public_key: Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?),
            })
        }

        info!("create primary key");
        let primary = raw_key(
            &http_client,
            key_name.to_string(),
            KeyOperations::SIGN | KeyOperations::APPMANAGEABLE,
            KeyRole::Primary,
        )?;

        info!("create decryption subkey");
        let subkey = raw_key(
            &http_client,
            key_name.to_string(),
            KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE,
            KeyRole::Subkey,
        )?;

        let cert = Self::bind_sdkms_keys_and_generate_cert(
            api_endpoint,
            api_key,
            primary.clone(),
            subkey.clone(),
        )?;

        Ok(PgpAgent {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            primary,
            subkey,
            certificate: cert,
        })
    }

    /// Generates the certificate (`----- BEGIN PUBLIC KEY BLOCK -----`), caches
    /// it, and stores it in SDKMS.
    fn bind_sdkms_keys_and_generate_cert(
        api_endpoint: &str,
        api_key: &str,
        primary: SequoiaKey,
        subkey: SequoiaKey,
    ) -> Result<Cert> {
        info!("generate certificate");

        // Primary + self signature, UserID + sig, subkey + sig
        let mut packets = Vec::<Packet>::with_capacity(6);

        // Self-sign primary key
        let prim_key: Key<PublicParts, PrimaryRole> = primary.public_key.clone().into();
        let mut prim_signer = RawSigner {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            sequoia_key: primary.clone(),
        };

        let sig = {
            let builder = SignatureBuilder::new(SignatureType::DirectKey)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_key_flags(KeyFlags::empty().set_certification())?
                .set_preferred_hash_algorithms(vec![
                    HashAlgorithm::SHA512,
                    HashAlgorithm::SHA256,
                ])?
                .set_preferred_symmetric_algorithms(vec![
                    SymmetricAlgorithm::AES256,
                    SymmetricAlgorithm::AES128,
                ])?;

            builder.sign_direct_key(&mut prim_signer, prim_key.parts_as_public())?
        };

        packets.push(prim_key.into());
        packets.push(sig.into());

        let mut cert = Cert::try_from(packets)?;

        // User ID + signature
        let sig = SignatureBuilder::new(SignatureType::GenericCertification);
        let uid: UserID = "Alice Lovelace <alice@example.org>".into();
        let builder = SignatureBuilder::from(sig).set_primary_userid(true)?;
        let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

        cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

        // Subkey + signature
        let subkey_public: Key<PublicParts, SubordinateRole> = subkey.public_key.clone().into();
        let flags = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

        let builder =
            SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_key_flags(flags)?
            .set_preferred_hash_algorithms(vec![
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA256,
            ])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?;

        let signature = subkey_public.bind(&mut prim_signer, &cert, builder)?;
        cert = cert.insert_packets(
            vec![Packet::from(subkey_public), signature.into()])?;

        info!("bind keys and store certificate in SDKMS");
        let armored = String::from_utf8(cert.armored().to_vec()?)?;

        let mut metadata = HashMap::<String, String>::new();
        metadata.insert("subkey".to_string(), subkey.kid.to_string());
        metadata.insert("certificate".to_string(), armored);

        let update_req = SobjectRequest {
            custom_metadata: Some(metadata), ..Default::default()
        };

        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()?;

        http_client.update_sobject(&primary.kid, &update_req)?;

        Ok(cert)
    }

    pub fn summon(
        api_endpoint: &str,
        api_key: &str,
        key_name: &str,
    ) -> Result<Self> {
        info!("summon PGP agent");
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()?;

        // Get primary key by name and subkey by UID
        let (primary, metadata) = {
            let req = SobjectDescriptor::Name(key_name.to_string());
            let sobject = http_client.get_sobject(None, &req)?;
            let (e, n, time) = {
                let raw_pk = sobject.pub_key.ok_or(Error::SdkmsBadResponse)?;
                let deserialized_pk = Pk::from_public_key(&raw_pk)?;
                (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                    sobject.created_at.to_datetime(),
                )
            };

            let kid = sobject.kid.ok_or_else(|| Error::SdkmsBadResponse)?;

            let key = SequoiaKey {
                kid: kid,
                descriptor: req,
                public_key: Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?),
            };

            match sobject.custom_metadata {
                None => return Err(Error::SdkmsSubkeyNotFound),
                Some(dict) => (key, dict),
            }
        };

        let subkey = {
            let kid = Uuid::parse_str(&metadata["subkey"])?;
            let descriptor = SobjectDescriptor::Kid(kid);
            let sobject = http_client.get_sobject(None, &descriptor)?;
            let (e, n, time) = {
                let raw_pk = sobject.pub_key.ok_or(Error::SdkmsBadResponse)?;
                let deserialized_pk = Pk::from_public_key(&raw_pk)?;
                (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                    sobject.created_at.to_datetime(),
                )
            };

            SequoiaKey {
                kid: kid,
                descriptor: descriptor,
                public_key: Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?)
            }
        };

        // Parse certificate
        let cert = Cert::from_str(&metadata["certificate"])?;

        Ok(PgpAgent {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            primary,
            subkey,
            certificate: cert,
        })
    }

    pub fn sign(
        &self,
        sink: &mut (dyn Write + Send + Sync),
        plaintext: &[u8],
    ) -> Result<()> {

        let signer = RawSigner {
            api_endpoint: self.api_endpoint.clone(),
            api_key: self.api_key.clone(),
            sequoia_key: self.primary.clone(),
        };

        let message = Message::new(sink);

        let message = Armorer::new(message).build()?;

        let message = Signer::new(message, signer).build()?;

        let mut message = LiteralWriter::new(message).build()?;

        message.write_all(plaintext)?;

        message.finalize()?;

        Ok(())
    }

    pub fn decrypt(
        &self,
        sink: &mut dyn Write,
        ciphertext: &[u8],
    ) -> Result<()>
    {
        struct Helper {
            decryptor: RawDecryptor,
        }

        impl VerificationHelper for Helper {
            fn get_certs(&mut self, _ids: &[KeyHandle])
                -> openpgp::Result<Vec<Cert>> {
                    // Return public keys for signature verification here.
                    // TODO
                    Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure)
                -> openpgp::Result<()> {
                    // Implement your signature verification policy here.
                    // TODO
                    Ok(())
            }
        }

        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self,
                pkesks: &[PKESK],
                _skesks: &[SKESK],
                sym_algo: Option<SymmetricAlgorithm>,
                mut decrypt: D)
                -> openpgp::Result<Option<openpgp::Fingerprint>>
                    where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {

                pkesks[0].decrypt(&mut self.decryptor, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));

                // XXX: In production code, return the Fingerprint of the
                // recipient's Cert here
                Ok(None)
            }
        }

        let decryptor = RawDecryptor {
            api_key: self.api_key.clone(),
            api_endpoint: self.api_endpoint.clone(),
            sequoia_key: self.subkey.clone(),
        };

        let h = Helper { decryptor };

        let p = &StandardPolicy::new();
        let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
            .with_policy(p, None, h)?;

        std::io::copy(&mut decryptor, sink)?;

        Ok(())
    }
}

// Error conversions
macro_rules! define_from {
    ($error:ident, $variant:ident) => {
        impl From<$error> for Error {
            fn from(other: $error) -> Self {
                Error::$variant(other)
            }
        }
    }
}

define_from!(SdkmsError, Sdkms);
define_from!(MbedtlsError, Mbedtls);
define_from!(SequoiaError, Sequoia);
define_from!(UuidError, Uuid);
define_from!(StdIoError, StdIo);
define_from!(FromUtf8Error, Utf8);

#[cfg(test)]
mod tests;
