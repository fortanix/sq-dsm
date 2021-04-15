use sdkms::{
    api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor},
    SdkmsClient,
};

use sequoia_openpgp::{
    crypto::{mpi, Signer},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    Result as SequoiaResult,
    types::HashAlgorithm,
};

pub(crate) struct RawSigner<'a> {
    pub(crate) http_client: &'a SdkmsClient,
    pub(crate) sobject_name: &'static str,
    pub(crate) public_key: Key<PublicParts, UnspecifiedRole>,
}

impl Signer for RawSigner<'_> {
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
                key: Some(SobjectDescriptor::Name(self.sobject_name.to_string())),
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
