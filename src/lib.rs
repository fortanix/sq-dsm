use anyhow::{Context, Result};

use std::{collections::HashMap, convert::TryFrom, io::Write, str::FromStr};

use log::info;

use uuid::Uuid;

use sdkms::{
    api_model::{
        KeyOperations, RsaEncryptionPaddingPolicy, RsaEncryptionPolicy,
        RsaOptions, RsaSignaturePaddingPolicy, RsaSignaturePolicy, Sobject,
        SobjectDescriptor, SobjectRequest,
    },
    SdkmsClient,
};

pub use sdkms::api_model::ObjectType;

use mbedtls::pk::Pk;

extern crate sequoia_openpgp as openpgp;

use openpgp::{
    crypto::SessionKey,
    packet::{
        key::{Key4, PrimaryRole, PublicParts, SubordinateRole, UnspecifiedRole},
        signature::SignatureBuilder,
        Key, UserID, PKESK, SKESK,
    },
    parse::{
        stream::{
            DecryptionHelper, DecryptorBuilder, MessageStructure,
            VerificationHelper
        },
        Parse,
    },
    policy::Policy as PgpPolicy,
    serialize::{
        stream::{Armorer, LiteralWriter, Message, Signer},
        SerializeInto,
    },
    types::{HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
    Cert, KeyHandle, Packet,
};

mod signer;

mod decryptor;

use signer::RawSigner;

use decryptor::RawDecryptor;

/// The PgpAgent is responsible of one PGP key. It talks to SDKMS and produces
/// valid OpenPGP material
pub struct PgpAgent {
    api_endpoint: String,
    api_key: String,
    primary: PublicKey,
    subkey: PublicKey,
    pub certificate: Cert,
}

#[derive(Clone)]
struct PublicKey {
    kid: Uuid,
    name: String,
    sequoia_key: Key<PublicParts, UnspecifiedRole>,
}

pub enum SupportedPkAlgo {
    Rsa(u32),
}

enum KeyRole {
    Primary,
    Subkey,
}

impl PublicKey {
    fn raw_key(
        client: &SdkmsClient,
        name: String,
        role: KeyRole,
        algo: &SupportedPkAlgo,
    ) -> Result<Self> {
        let description = Some("Created with sq-sdkms".to_string());

        let sobject_request = match (&role, algo) {
            (KeyRole::Primary, SupportedPkAlgo::Rsa(key_size)) => {
                let ops = KeyOperations::SIGN | KeyOperations::APPMANAGEABLE;
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
                    key_ops: Some(ops),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            },
            (KeyRole::Subkey, SupportedPkAlgo::Rsa(key_size)) => {
                let ops = KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE;
                let enc_policy = RsaEncryptionPolicy {
                    padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                };
                let rsa_options = Some(RsaOptions {
                    encryption_policy: vec![enc_policy],
                    ..Default::default()
                });
                let name = name + " (PGP: decryption subkey)";

                SobjectRequest {
                    name: Some(name),
                    description,
                    obj_type: Some(ObjectType::Rsa),
                    key_ops: Some(ops),
                    key_size: Some(*key_size),
                    rsa: rsa_options,
                    ..Default::default()
                }
            },
        };

        let sobject = client.create_sobject(&sobject_request)?;

        PublicKey::new_from_raw(sobject, role)
    }

    fn new_from_raw(sobject: Sobject, _role: KeyRole) -> Result<Self> {
        let kid = sobject.kid.context("no kid in sobject")?;
        let name = sobject.name.context("no name in sobject")?;
        let time = sobject.created_at.to_datetime();
        let raw_pk = sobject
            .pub_key
            .context("public bits of sobject not returned")?;

        match sobject.obj_type {
            ObjectType::Rsa => {
                let deserialized_pk = Pk::from_public_key(&raw_pk)
                    .context("cannot deserialize SDKMS key into mbedTLS object")?;

                let (e, n) = (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                );

                Ok(PublicKey {
                    kid, name,
                    sequoia_key: Key::V4(
                        Key4::import_public_rsa(&e, &n, Some(time.into()))
                        .context("cannot import RSA key into Sequoia object")?,
                    ),
                })
            },
            _ => unimplemented!()
        }
    }
}

impl PgpAgent {
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
    /// an additional custom medatada field on the primary key, and returned.
    pub fn generate_key(
        api_endpoint: &str,
        api_key: &str,
        key_name: &str,
        user_id: &str,
        algorithm: &SupportedPkAlgo,
    ) -> Result<Self> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()
            .context("could not initiate an SDKMS client")?;

        info!("create primary key");
        let primary = PublicKey::raw_key(
            &http_client,
            key_name.to_string(),
            KeyRole::Primary,
            algorithm,
        )?;

        info!("create decryption subkey");
        let subkey = PublicKey::raw_key(
            &http_client,
            key_name.to_string(),
            KeyRole::Subkey,
            algorithm,
        )?;

        let cert = Self::bind_sdkms_keys_and_generate_cert(
            api_endpoint,
            api_key,
            user_id,
            primary.clone(),
            subkey.clone(),
        )
            .context("could not generate public certificate")?;

        Ok(PgpAgent {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            primary,
            subkey,
            certificate: cert,
        })
    }

    // Generates the Transferable Public Key certificate, caches it, and stores
    // it in SDKMS.
    fn bind_sdkms_keys_and_generate_cert(
        api_endpoint: &str,
        api_key: &str,
        user_id: &str,
        primary: PublicKey,
        subkey: PublicKey,
    ) -> Result<Cert> {
        info!("generate certificate");
        // Primary, UserID + sig, subkey + sig
        let mut packets = Vec::<Packet>::with_capacity(5);

        // Self-sign primary key
        let prim_key: Key<PublicParts, PrimaryRole> = primary.sequoia_key.clone().into();
        let mut prim_signer = RawSigner {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            public: primary.clone(),
        };

        let pref_hashes = vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256];
        let pref_ciphers = vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ];
        let primary_flags = KeyFlags::empty()
            .set_certification()
            .set_signing();

        packets.push(prim_key.into());

        let mut cert = Cert::try_from(packets)?;

        // User ID + signature
        let builder = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_primary_userid(true)?
            .set_key_flags(primary_flags)?
            .set_preferred_hash_algorithms(pref_hashes)?
            .set_preferred_symmetric_algorithms(pref_ciphers)?;
        let uid: UserID = user_id.into();
        let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

        cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

        // Subkey + signature
        let subkey_public: Key<PublicParts, SubordinateRole> = subkey.sequoia_key.clone().into();
        let subkey_flags = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

        let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_key_flags(subkey_flags)?;

        let signature = subkey_public.bind(&mut prim_signer, &cert, builder)?;
        cert = cert.insert_packets(vec![Packet::from(subkey_public), signature.into()])?;

        info!("bind keys and store certificate in SDKMS");
        let armored = String::from_utf8(cert.armored().to_vec()?)?;

        let mut metadata = HashMap::<String, String>::new();
        metadata.insert("subkey".to_string(), subkey.kid.to_string());
        metadata.insert("certificate".to_string(), armored);

        let update_req = SobjectRequest {
            custom_metadata: Some(metadata),
            ..Default::default()
        };

        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()?;

        http_client.update_sobject(&primary.kid, &update_req)?;

        Ok(cert)
    }

    /// Given proper credentials, a PgpAgent is created for this key.
    pub fn summon(api_endpoint: &str, api_key: &str, key_name: &str) -> Result<Self> {
        info!("summon PGP agent");
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()?;

        // Get primary key by name and subkey by UID
        let (primary, metadata) = {
            let req = SobjectDescriptor::Name(key_name.to_string());
            let sobject = http_client
                .get_sobject(None, &req)
                .context(format!("could not get primary key {}", key_name))?;
            let key = PublicKey::new_from_raw(sobject.clone(), KeyRole::Primary)?;

            match sobject.custom_metadata {
                None => return Err(anyhow::Error::msg("subkey not found".to_string())),
                Some(dict) => (key, dict),
            }
        };

        let subkey = {
            let kid = Uuid::parse_str(&metadata["subkey"])?;
            let descriptor = SobjectDescriptor::Kid(kid);
            let sobject = http_client
                .get_sobject(None, &descriptor)
                .context(format!("could not get subkey (sobject {})", kid))?;

            PublicKey::new_from_raw(sobject, KeyRole::Subkey)?
        };

        let cert = Cert::from_str(&metadata["certificate"])?;

        Ok(PgpAgent {
            api_endpoint: api_endpoint.to_string(),
            api_key: api_key.to_string(),
            primary,
            subkey,
            certificate: cert,
        })
    }

    /// Signs the given content and writes it to `sink`.
    pub fn sign(
        &self,
        sink: &mut (dyn Write + Send + Sync),
        content: &[u8],
        detached: bool,
        armored: bool,
    ) -> Result<()> {
        let signer = RawSigner {
            api_endpoint: self.api_endpoint.clone(),
            api_key: self.api_key.clone(),
            public: self.primary.clone(),
        };

        let message = match armored {
            true => {
                let message = Message::new(sink);
                Armorer::new(message).build()?
            }
            false => Message::new(sink),
        };

        match detached {
            true => {
                let mut message = Signer::new(message, signer)
                    .detached()
                    .build()?;
                message.write_all(content)?;
                message.finalize()?;
            }
            false => {
                let message = Signer::new(message, signer).build()?;
                let mut message = LiteralWriter::new(message).build()?;
                message.write_all(content)?;
                message.finalize()?;
            }
        }

        Ok(())
    }

    /// Decrypts the given ciphertext and writes the plaintext to `sink`.
    pub fn decrypt(
        &self,
        sink: &mut dyn Write,
        ciphertext: &[u8],
        policy: &(dyn PgpPolicy + 'static),
    ) -> Result<()> {
        struct Helper {
            decryptor: RawDecryptor,
        }

        impl VerificationHelper for Helper {
            fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for Helper {
            fn decrypt<D>(
                &mut self,
                pkesks: &[PKESK],
                _skesks: &[SKESK],
                sym_algo: Option<SymmetricAlgorithm>,
                mut decrypt: D,
            ) -> openpgp::Result<Option<openpgp::Fingerprint>>
            where
                D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
                {
                    pkesks[0]
                        .decrypt(&mut self.decryptor, sym_algo)
                        .map(|(algo, session_key)| decrypt(algo, &session_key));

                    Ok(Some(self.decryptor.public.sequoia_key.fingerprint()))
                }
        }

        let decryptor = RawDecryptor {
            api_key: self.api_key.clone(),
            api_endpoint: self.api_endpoint.clone(),
            public: self.subkey.clone(),
        };

        let h = Helper { decryptor };

        let mut decryptor =
            DecryptorBuilder::from_bytes(ciphertext)?
            .with_policy(policy, None, h)?;

        std::io::copy(&mut decryptor, sink)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
