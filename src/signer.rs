use sequoia_openpgp::{
    crypto::{mpi, Signer},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    types::{HashAlgorithm, PublicKeyAlgorithm},
    Result as SequoiaResult,
};

use sdkms::{
    api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor},
    SdkmsClient,
};

use super::PublicKey;

pub(crate) struct RawSigner {
    pub(crate) api_endpoint: String,
    pub(crate) api_key: String,
    pub(crate) public: PublicKey,
}

impl Signer for RawSigner {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public.sequoia_key
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> SequoiaResult<mpi::Signature> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&self.api_endpoint)
            .with_api_key(&self.api_key)
            .build()?;

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
                key: Some(SobjectDescriptor::Kid(self.public.kid)),
                hash_alg,
                hash: Some(digest.to_vec().into()),
                data: None,
                mode: None,
                deterministic_signature: None,
            };

            let sign_resp = http_client.sign(&sign_req)?;
            let plain: Vec<u8> = sign_resp.signature.into();
            match self.public.sequoia_key.pk_algo() {
                PublicKeyAlgorithm::RSAEncryptSign => {
                    mpi::Signature::RSA { s: plain.into() }
                },
                _ => unimplemented!()
            }
        };

        Ok(signature)
    }
}
