use sdkms::api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor};

use sequoia_openpgp::{
    crypto::{mpi, Signer},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    types::HashAlgorithm,
    Result as SequoiaResult,
};

use super::Operation;

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
                _ => unimplemented!(),
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
