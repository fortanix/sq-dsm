use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Write;
use std::str::FromStr;

use anyhow::{Context, Result};
use log::info;
use mbedtls::pk::Pk;
use openpgp::crypto::SessionKey;
use openpgp::packet::key::{
    Key4, PrimaryRole, PublicParts, SubordinateRole, UnspecifiedRole,
};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{Key, UserID, PKESK, SKESK};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::Policy as PgpPolicy;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::serialize::SerializeInto;
use openpgp::types::{
    HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm,
};
use openpgp::{Cert, KeyHandle, Packet};
use sdkms::api_model::{
    KeyOperations, ObjectType, RsaEncryptionPaddingPolicy, RsaEncryptionPolicy,
    RsaOptions, RsaSignaturePaddingPolicy, RsaSignaturePolicy, Sobject,
    SobjectDescriptor, SobjectRequest,
};
use sdkms::SdkmsClient;
use sequoia_openpgp as openpgp;
use uuid::Uuid;

mod signer;

mod decryptor;

use decryptor::RawDecryptor;
use signer::RawSigner;

/// The PgpAgent is responsible for one PGP key. It talks to SDKMS and produces
/// valid OpenPGP material
pub struct PgpAgent<'a> {
    pub http_client: &'a SdkmsClient,
    primary:         PublicKey,
    subkey:          PublicKey,
    pub certificate: Option<Cert>,
}

#[derive(Clone)]
struct PublicKey {
    role:        KeyRole,
    descriptor:  SobjectDescriptor,
    sequoia_key: Option<Key<PublicParts, UnspecifiedRole>>,
}

#[derive(Clone)]
enum KeyRole {
    Primary,
    Subkey,
}

pub enum SupportedPkAlgo {
    Rsa(u32),
}

impl<'a> PgpAgent<'a> {
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
    pub fn generate_key(
        http_client: &'a SdkmsClient,
        key_name: &str,
        user_id: &str,
        algorithm: &SupportedPkAlgo,
    ) -> Result<Self> {
        info!("create primary key");
        let primary = PublicKey::create(
            &http_client,
            key_name.to_string(),
            KeyRole::Primary,
            algorithm,
        )?;

        info!("create decryption subkey");
        let subkey = PublicKey::create(
            &http_client,
            key_name.to_string(),
            KeyRole::Subkey,
            algorithm,
        )?;

        let mut agent = PgpAgent {
            http_client: &http_client,
            primary,
            subkey,
            certificate: None,
        };

        agent
            .bind_sdkms_keys_and_generate_cert(user_id)
            .context("could not generate public certificate")?;

        Ok(agent)
    }

    /// Signs the given content and writes the detached signature to `sink`.
    pub fn sign_detached(
        self,
        sink: &mut (dyn Write + Send + Sync),
        content: &[u8],
        armored: bool,
    ) -> Result<()> {
        let sequoia_key =
            &self.primary.sequoia_key.expect("unloaded primary key");

        let signer = RawSigner {
            http_client: &self.http_client,
            descriptor:  &self.primary.descriptor,
            public:      &sequoia_key,
        };

        let mut message = Message::new(sink);
        if armored {
            message = Armorer::new(message).build()?;
        }

        let mut message = Signer::new(message, signer).detached().build()?;
        message.write_all(content)?;
        message.finalize()?;

        Ok(())
    }

    /// Decrypts the given ciphertext and writes the plaintext to `sink`.
    pub fn decrypt(
        &mut self,
        sink: &mut dyn Write,
        ciphertext: &[u8],
        policy: &(dyn PgpPolicy + 'static),
    ) -> Result<()> {
        struct Helper<'a> {
            decryptor: RawDecryptor<'a>,
        }

        impl VerificationHelper for Helper<'_> {
            fn get_certs(
                &mut self,
                _ids: &[KeyHandle],
            ) -> openpgp::Result<Vec<Cert>> {
                Ok(Vec::new())
            }

            fn check(
                &mut self,
                _structure: MessageStructure,
            ) -> openpgp::Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for Helper<'_> {
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
                if pkesks.len() == 0 {
                    return Err(anyhow::Error::msg("PKESK not found"));
                }
                pkesks[0]
                    .decrypt(&mut self.decryptor, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));

                Ok(Some(self.decryptor.public.fingerprint()))
            }
        }

        self.maybe_fetch_subkey()?;

        let decryptor = RawDecryptor {
            http_client: self.http_client,
            descriptor:  &self.subkey.descriptor,
            public:      &self
                .subkey
                .sequoia_key
                .as_ref()
                .expect("unloaded subkey"),
        };

        let h = Helper { decryptor };

        let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
            .with_policy(policy, None, h)?;

        std::io::copy(&mut decryptor, sink)?;

        Ok(())
    }

    /// Given proper credentials, a PgpAgent is created for this PGP key.
    pub fn summon(
        http_client: &'a SdkmsClient,
        key_name: &str,
    ) -> Result<Self> {
        info!("summon PGP agent");
        // Get primary key by name and subkey by UID
        let (primary, metadata) = {
            let req = SobjectDescriptor::Name(key_name.to_string());
            let sobject = http_client
                .get_sobject(None, &req)
                .context(format!("could not get primary key {}", key_name))?;
            let key =
                PublicKey::from_sobject(sobject.clone(), KeyRole::Primary)?;

            match sobject.custom_metadata {
                None => {
                    return Err(anyhow::Error::msg(
                        "subkey not found".to_string(),
                    ))
                }
                Some(dict) => (key, dict),
            }
        };

        // Don't request for subkey now
        let des = SobjectDescriptor::Kid(Uuid::parse_str(&metadata["subkey"])?);

        let subkey = PublicKey {
            descriptor:  des,
            role:        KeyRole::Subkey,
            sequoia_key: None,
        };

        let cert = Cert::from_str(&metadata["certificate"])?;

        Ok(PgpAgent {
            http_client: &http_client,
            primary,
            subkey,
            certificate: Some(cert),
        })
    }

    // Generates the Transferable Public Key certificate, caches it, and stores
    // it in SDKMS.
    fn bind_sdkms_keys_and_generate_cert(
        &mut self,
        user_id: &str,
    ) -> Result<()> {
        info!("generate certificate");
        // Primary, UserID + sig, subkey + sig
        let mut packets = Vec::<Packet>::with_capacity(5);

        // Self-sign primary key
        let prim: Key<PublicParts, PrimaryRole> = self
            .primary
            .sequoia_key
            .clone()
            .expect("unloaded primary key")
            .into();

        packets.push(prim.clone().into());

        let mut prim_signer = RawSigner {
            http_client: &self.http_client,
            descriptor:  &self.primary.descriptor,
            public:      &prim.into(),
        };

        let pref_hashes = vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256];

        let pref_ciphers =
            vec![SymmetricAlgorithm::AES256, SymmetricAlgorithm::AES128];

        let primary_flags = KeyFlags::empty().set_certification().set_signing();

        let mut cert = Cert::try_from(packets)?;

        // User ID + signature
        let builder =
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_primary_userid(true)?
                .set_key_flags(primary_flags)?
                .set_preferred_hash_algorithms(pref_hashes)?
                .set_preferred_symmetric_algorithms(pref_ciphers)?;
        let uid: UserID = user_id.into();
        let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

        cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

        // Subkey + signature
        let subkey_public: Key<PublicParts, SubordinateRole> = self
            .subkey
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
        cert = cert.insert_packets(vec![
            Packet::from(subkey_public),
            signature.into(),
        ])?;

        info!("bind keys and store certificate in SDKMS");
        let armored = String::from_utf8(cert.armored().to_vec()?)?;

        let mut metadata = HashMap::<String, String>::new();
        metadata.insert("subkey".to_string(), self.subkey.uid()?.to_string());
        metadata.insert("certificate".to_string(), armored);

        let update_req = SobjectRequest {
            custom_metadata: Some(metadata),
            ..Default::default()
        };

        self.http_client
            .update_sobject(&self.primary.uid()?, &update_req)?;

        self.certificate = Some(cert);

        Ok(())
    }

    fn maybe_fetch_subkey(&mut self) -> Result<()> {
        if self.subkey.sequoia_key.is_some() {
            return Ok(());
        }

        let sobject = self
            .http_client
            .get_sobject(None, &self.subkey.descriptor)
            .context("could not get subkey".to_string())?;
        let key = PublicKey::from_sobject(sobject, KeyRole::Subkey)?;
        let key = key
            .sequoia_key
            .context("could not get subkey".to_string())?;

        self.subkey.sequoia_key = Some(key);

        Ok(())
    }
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
            }
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
            }
        };

        let sobject = client.create_sobject(&sobject_request)?;

        PublicKey::from_sobject(sobject, role)
    }

    fn from_sobject(sob: Sobject, role: KeyRole) -> Result<Self> {
        let des = SobjectDescriptor::Kid(sob.kid.context("no kid in sobject")?);
        let time = sob.created_at.to_datetime();
        let raw_pk =
            sob.pub_key.context("public bits of sobject not returned")?;

        match sob.obj_type {
            ObjectType::Rsa => {
                let deserialized_pk = Pk::from_public_key(&raw_pk).context(
                    "cannot deserialize SDKMS key into mbedTLS object",
                )?;

                let (e, n) = (
                    deserialized_pk.rsa_public_exponent()?.to_be_bytes(),
                    deserialized_pk.rsa_public_modulus()?.to_binary()?,
                );
                let key = Key::V4(
                    Key4::import_public_rsa(&e, &n, Some(time.into()))
                        .context("cannot import RSA key into Sequoia object")?,
                );

                Ok(PublicKey {
                    descriptor: des,
                    role,
                    sequoia_key: Some(key),
                })
            }
            _ => unimplemented!(),
        }
    }

    fn uid(&self) -> Result<Uuid> {
        match self.descriptor {
            SobjectDescriptor::Kid(x) => Ok(x),
            _ => Err(anyhow::Error::msg("bad descriptor")),
        }
    }
}

#[cfg(test)]
mod tests;
