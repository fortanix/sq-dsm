use std::convert::TryFrom;

use sdkms::api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor};

use sequoia_openpgp::{
    Cert,
    crypto::{mpi, Signer},
    packet::{
        key::{PublicParts, UnspecifiedRole, PrimaryRole},
        Key,
        signature::SignatureBuilder,
        UserID,
    },
    Packet,
    Result as SequoiaResult,
    serialize::SerializeInto,
    types::{HashAlgorithm, SignatureType},
};

use super::{Operation, Result};

pub(crate) struct Sign {}

impl Operation for Sign {}


pub(crate) type PgpSigner = super::Agent<Sign>;

impl Signer for PgpSigner {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public_key
    }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8]
    ) -> SequoiaResult<mpi::Signature> {
        let signature = {
            let hash_alg = match hash_algo {
                HashAlgorithm::SHA1 => DigestAlgorithm::Sha1,
                HashAlgorithm::SHA512 => DigestAlgorithm::Sha512,
                HashAlgorithm::SHA256 => DigestAlgorithm::Sha256,
                _ => {
                    panic!("unimplemented hash algorithm");
                }
            };

            let sign_req = SignRequest {
                key: Some(SobjectDescriptor::Name(self.key_name.to_string())),
                hash_alg: hash_alg,
                hash: Some(digest.to_vec().into()),
                data: None,
                mode: None,
                deterministic_signature: None,
            };

            let sign_resp = self.http_client.sign(&sign_req)?;
            let plain: Vec<u8> = sign_resp.signature.into();
            mpi::Signature::RSA { s: plain.into() }
        };

        Ok(signature)
    }
}

impl PgpSigner {
    pub(crate) fn get_armored_key(&mut self) -> Result<Vec<u8>> {
        let cert = {
            // Manually create the packets.
            let mut packets = Vec::<Packet>::with_capacity(3);

            // 1. Primary key
            let key: Key<PublicParts, PrimaryRole> = self.public_key.clone().into();
            packets.push(key.clone().into());

            // 2. Self-signature
            let sig = SignatureBuilder::new(SignatureType::DirectKey)
                .set_hash_algo(HashAlgorithm::SHA512);
                // .set_features(Features::sequoia())?
                // .set_key_flags(self.primary.flags.clone())?
                // .set_signature_creation_time(creation_time)?
                // .set_key_validity_period(self.primary.validity)?;
                // .set_preferred_hash_algorithms(vec![
                //     HashAlgorithm::SHA512,
                //     HashAlgorithm::SHA256,
                // ])?
                // .set_preferred_symmetric_algorithms(vec![
                //     SymmetricAlgorithm::AES256,
                //     SymmetricAlgorithm::AES128,
                // ])?;
            let sig = sig.sign_direct_key(self, key.parts_as_public())?;
            packets.push(sig.clone().into());

            let cert = Cert::try_from(packets)?;

            let sig = SignatureBuilder::new(SignatureType::GenericCertification);
            // .set_signature_creation_time(creation_time)?;

            // let sig = sig.set_revocation_key(vec![])?;

            // 3. User ID
            let uid: UserID = "Alice Lovelace <alice@example.org>".into();
            let builder = SignatureBuilder::from(sig.clone());
            let uid_sig = uid.bind(self, &cert, builder)?;

            cert.insert_packets(vec![Packet::from(uid), uid_sig.into()])?
        };

        let armored = cert.armored().to_vec()?;

        Ok(armored)
    }
}
