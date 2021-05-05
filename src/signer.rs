use sdkms::api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::{mpi, Signer};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
use sequoia_openpgp::Result as SequoiaResult;

use super::Credentials;

pub struct RawSigner<'a> {
    pub credentials: &'a Credentials,
    pub descriptor:  &'a SobjectDescriptor,
    pub public:      &'a Key<PublicParts, UnspecifiedRole>,
}

impl Signer for RawSigner<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> SequoiaResult<mpi::Signature> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&self.credentials.api_endpoint)
            .with_api_key(&self.credentials.api_key)
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
                key: Some(self.descriptor.clone()),
                hash_alg,
                hash: Some(digest.to_vec().into()),
                data: None,
                mode: None,
                deterministic_signature: None,
            };

            let sign_resp = http_client.sign(&sign_req)?;
            let plain: Vec<u8> = sign_resp.signature.into();
            match self.public.pk_algo() {
                PublicKeyAlgorithm::RSAEncryptSign => {
                    mpi::Signature::RSA { s: plain.into() }
                }
                _ => unimplemented!(),
            }
        };

        Ok(signature)
    }
}
