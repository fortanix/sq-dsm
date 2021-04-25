use anyhow::{Context, Result};

use std::{collections::HashMap, convert::TryFrom, io::Write, str::FromStr};

use log::info;

use uuid::Uuid;

use sdkms::{
    api_model::{
        KeyOperations, ObjectType, RsaEncryptionPaddingPolicy,
        RsaEncryptionPolicy, RsaOptions, RsaSignaturePaddingPolicy,
        RsaSignaturePolicy, Sobject, SobjectDescriptor, SobjectRequest,
    },
    SdkmsClient,
};

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
    name: String,
    public_key: Key<PublicParts, UnspecifiedRole>,
}

impl SequoiaKey {
    fn new_from_raw(sobject: Sobject) -> Result<Self> {
        let (e, n, time) = {
            let raw_pk = sobject
                .pub_key
                .context("public bits of sobject not returned")?;
            let deserialized_pk = Pk::from_public_key(&raw_pk)
                .context("cannot deserialize SDKMS key into Sequoia object")?;
            (
                deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                deserialized_pk.rsa_public_modulus()?.to_binary()?,
                sobject.created_at.to_datetime(),
            )
        };

        Ok(SequoiaKey {
            kid: sobject.kid.context("uuid not returned by SDKMS")?,
            name: sobject.name.context("name not returned by SDKMS")?,
            public_key: Key::V4(
                Key4::import_public_rsa(&e, &n, Some(time.into()))
                    .context("cannot import RSA key into Sequoia object")?,
            ),
        })
    }
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
        user_id: &str
    ) -> Result<Self> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&api_endpoint)
            .with_api_key(&api_key)
            .build()
            .context("could not initiate an SDKMS client")?;

        fn raw_key(
            client: &SdkmsClient,
            name: String,
            op: KeyOperations,
            role: KeyRole,
        ) -> Result<SequoiaKey> {
            let (name, rsa_options) = match role {
                KeyRole::Subkey => {
                    let enc_policy = RsaEncryptionPolicy {
                        padding: Some(RsaEncryptionPaddingPolicy::Pkcs1V15 {}),
                    };
                    let rsa_options = RsaOptions {
                        encryption_policy: vec![enc_policy],
                        ..Default::default()
                    };

                    (name + " (PGP: decryption subkey)", rsa_options)
                }
                KeyRole::Primary => {
                    let sig_policy = RsaSignaturePolicy {
                        padding: Some(RsaSignaturePaddingPolicy::Pkcs1V15 {}),
                    };
                    let rsa_options = RsaOptions {
                        signature_policy: vec![sig_policy],
                        ..Default::default()
                    };

                    (name, rsa_options)
                }
            };

            let sobject_req = SobjectRequest {
                name: Some(name),
                description: Some("Created with sq-sdkms".to_string()),
                obj_type: Some(ObjectType::Rsa),
                key_ops: Some(op),
                key_size: Some(2048),
                rsa: Some(rsa_options),
                ..Default::default()
            };

            let sobject = client.create_sobject(&sobject_req)?;

            SequoiaKey::new_from_raw(sobject)
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

    /// Generates the Transferable Public Key certificate, caches it, and stores
    /// it in SDKMS.
    fn bind_sdkms_keys_and_generate_cert(
        api_endpoint: &str,
        api_key: &str,
        user_id: &str,
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

        let pref_hashes = vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256];
        let pref_ciphers = vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ];

        let sig = {
            let flags = KeyFlags::empty().set_certification().set_signing();
            let builder = SignatureBuilder::new(SignatureType::DirectKey)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_key_flags(flags)?
                .set_preferred_hash_algorithms(pref_hashes.clone())?
                .set_preferred_symmetric_algorithms(pref_ciphers.clone())?;

            builder.sign_direct_key(&mut prim_signer, prim_key.parts_as_public())?
        };

        packets.push(prim_key.into());
        packets.push(sig.into());

        let mut cert = Cert::try_from(packets)?;

        // User ID + signature
        let builder = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_primary_userid(true)?;
        let uid: UserID = user_id.into();
        let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

        cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

        // Subkey + signature
        let subkey_public: Key<PublicParts, SubordinateRole> = subkey.public_key.clone().into();
        let flags = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

        let builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_key_flags(flags)?
            .set_preferred_hash_algorithms(pref_hashes.clone())?
            .set_preferred_symmetric_algorithms(pref_ciphers.clone())?;

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
            let key = SequoiaKey::new_from_raw(sobject.clone())?;

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

            SequoiaKey::new_from_raw(sobject)?
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

    pub fn sign(
        &self,
        sink: &mut (dyn Write + Send + Sync),
        plaintext: &[u8],
        detached: bool,
        armored: bool,
    ) -> Result<()> {
        let signer = RawSigner {
            api_endpoint: self.api_endpoint.clone(),
            api_key: self.api_key.clone(),
            sequoia_key: self.primary.clone(),
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
                message.write_all(plaintext)?;
                message.finalize()?;
            }
            false => {
                let message = Signer::new(message, signer).build()?;
                let mut message = LiteralWriter::new(message).build()?;
                message.write_all(plaintext)?;
                message.finalize()?;
            }
        }

        Ok(())
    }

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
                // Return public keys for signature verification here.
                // TODO
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
                // Implement your signature verification policy here.
                // TODO
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

        let mut decryptor =
            DecryptorBuilder::from_bytes(ciphertext)?
            .with_policy(policy, None, h)?;

        std::io::copy(&mut decryptor, sink)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
