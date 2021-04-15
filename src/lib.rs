use std::{collections::HashMap, convert::TryFrom};

use uuid::{Uuid, parser::ParseError as UuidError};

use sdkms::{
    api_model::{KeyOperations, ObjectType, SobjectDescriptor, SobjectRequest},
    Error as SdkmsError,
    SdkmsClient,
};

use mbedtls::{
    Error as MbedtlsError,
    pk::Pk,
};

use sequoia_openpgp::{
    Cert,
    packet::{
        key::{Key4, PublicParts, UnspecifiedRole, PrimaryRole, SubordinateRole},
        Key,
        signature::SignatureBuilder,
        UserID,
    },
    Packet,
    serialize::SerializeInto,
    types::{HashAlgorithm, SignatureType, PublicKeyAlgorithm},
};

use anyhow::Error as SequoiaError;

#[derive(Debug)]
pub enum Error {
    Sdkms(SdkmsError),
    Sequoia(SequoiaError),
    Mbedtls(MbedtlsError),
    Uuid(UuidError),
    SdkmsBadResponse,
    SdkmsSubkeysNotFound,
}

type Result<T> = core::result::Result<T, Error>;

pub mod sign;

use sign::RawSigner;

pub mod decrypt;

struct PgpAgent {
    key_name: &'static str,
    primary_key: Key<PublicParts, UnspecifiedRole>,
    sig_subkey: Key<PublicParts, UnspecifiedRole>,
    dec_subkey: Key<PublicParts, UnspecifiedRole>,
    http_client: SdkmsClient,
}

enum KeyRole {
    Primary,
    SigningSubkey,
    DecryptionSubkey,
}

impl PgpAgent {
    const DEFAULT_API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";

    pub(crate) fn generate_key(
        api_endpoint: Option<String>,
        api_key: String,
        key_name: &'static str,
    ) -> Result<Self> {
        let endpoint = match api_endpoint {
            Some(s) => s,
            None => Self::DEFAULT_API_ENDPOINT.to_string(),
        };

        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&endpoint)
            .with_api_key(&api_key)
            .build()?;

        fn raw_key(
            client: &SdkmsClient,
            name: String,
            op: KeyOperations,
            role: KeyRole,
            metadata: Option<HashMap<String, String>>,
        ) -> Result<(Key<PublicParts, UnspecifiedRole>, Uuid)> {
            let name = name + match role {
                KeyRole::Primary => "",
                KeyRole::SigningSubkey => " (PGP: subkey, signing)",
                KeyRole::DecryptionSubkey => " (PGP: subkey, decryption)",
            };
            let sobject_req = SobjectRequest {
                name: Some(name),
                description: Some("Created with SDKMS-PGP".to_string()),
                obj_type: Some(ObjectType::Rsa),
                key_ops: Some(op),
                key_size: Some(2048),
                custom_metadata: metadata,
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

            Ok((
                Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?),
                sobject.kid.unwrap(),
            ))
        }


        // Create subkeys
        let (sig_subkey, sig_kid) = raw_key(
            &http_client,
            key_name.to_string(),
            KeyOperations::SIGN,
            KeyRole::DecryptionSubkey,
            None,
        )?;

        let (dec_subkey, dec_kid) = raw_key(
            &http_client,
            key_name.to_string(),
            KeyOperations::DECRYPT,
            KeyRole::SigningSubkey,
            None,
        )?;

        // Create primary key
        let mut metadata_for_primary = HashMap::<String, String>::new();
        metadata_for_primary.insert("SIGN".to_string(), sig_kid.to_string());
        metadata_for_primary.insert("DECRYPT".to_string(), dec_kid.to_string());
        let (primary_key, _) = raw_key(
            &http_client,
            key_name.to_string(),
            KeyOperations::SIGN,
            KeyRole::Primary,
            Some(metadata_for_primary),
        )?;

        Ok(PgpAgent {
            key_name,
            http_client,
            primary_key,
            dec_subkey,
            sig_subkey,
        })
    }

    pub(crate) fn from_key_name(
        api_endpoint: Option<String>,
        api_key: String,
        key_name: &'static str,
    ) -> Result<Self> {
        let endpoint = match api_endpoint {
            Some(s) => s,
            None => Self::DEFAULT_API_ENDPOINT.to_string(),
        };

        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&endpoint)
            .with_api_key(&api_key)
            .build()?;

        // Get primary key by name, but subkeys by UID
        let (mut primary_key, sig_uid, dec_uid) = {
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

            match sobject.custom_metadata {
                None => return Err(Error::SdkmsSubkeysNotFound),
                Some(dict) => {
                    (
                        Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?),
                        dict["SIGN"].to_string(),
                        dict["DECRYPT"].to_string(),
                    )
                }
            }
        };
        primary_key.set_pk_algo(PublicKeyAlgorithm::RSASign);

        let mut sig_subkey = {
            let kid = Uuid::parse_str(&sig_uid)?;
            let req = SobjectDescriptor::Kid(kid);
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

            Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?)
        };
        sig_subkey.set_pk_algo(PublicKeyAlgorithm::RSASign);

        let mut dec_subkey = {
            let kid = Uuid::parse_str(&dec_uid)?;
            let req = SobjectDescriptor::Kid(kid);
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

            Key::V4(Key4::import_public_rsa(&e, &n, Some(time.into()))?)
        };
        dec_subkey.set_pk_algo(PublicKeyAlgorithm::RSAEncrypt);

        Ok(PgpAgent {
            key_name,
            http_client,
            primary_key,
            sig_subkey,
            dec_subkey,
        })
    }

    pub(crate) fn get_armored_key(&mut self) -> Result<Vec<u8>> {
        let cert = {
            // Primary, Self-Signature, UserID, subkeys.
            let mut packets = Vec::<Packet>::with_capacity(5);

            // Self-sign primary key
            let prim_key: Key<PublicParts, PrimaryRole> = self.primary_key.clone().into();
            let mut prim_signer = RawSigner {
                http_client: &self.http_client,
                sobject_name: self.key_name,
                public_key: prim_key.clone().into(),
            };
            let sig = {
                let builder = SignatureBuilder::new(SignatureType::DirectKey)
                    .set_hash_algo(HashAlgorithm::SHA512);
                builder.sign_direct_key(&mut prim_signer, prim_key.parts_as_public())?
            };

            packets.push(prim_key.clone().into());
            packets.push(sig.clone().into());

            let mut cert = Cert::try_from(packets)?;

            let sig = SignatureBuilder::new(SignatureType::GenericCertification);

            // Sign User ID
            let uid: UserID = "Alice Lovelace <alice@example.org>".into();
            let builder = SignatureBuilder::from(sig.clone()).set_primary_userid(true)?;
            let uid_sig = uid.bind(&mut prim_signer, &cert, builder)?;

            cert = cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?;

            // Sign subkeys
            let mut subkeys: Vec<Key<PublicParts, SubordinateRole>> = vec![];
            subkeys.push(self.dec_subkey.clone().into());
            subkeys.push(self.sig_subkey.clone().into());
            for subkey in subkeys {
                let builder =
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_hash_algo(HashAlgorithm::SHA512);
                let signature = subkey.bind(&mut prim_signer, &cert, builder)?;
                cert = cert.insert_packets(
                    vec![Packet::from(subkey.clone()), signature.into()])?;
            }

            cert
        };

        let armored = cert.armored().to_vec()?;
        Ok(armored)
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

#[cfg(test)]
mod tests;
