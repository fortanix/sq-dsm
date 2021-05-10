use sdkms::api_model::{DigestAlgorithm, SignRequest, SobjectDescriptor};
use sdkms::SdkmsClient;

use sequoia_openpgp::crypto::{mpi, Signer};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
use sequoia_openpgp::Result as SequoiaResult;

pub(crate) struct RawSigner<'a> {
    pub(crate) api_endpoint: &'a str,
    pub(crate) api_key:      &'a str,
    pub(crate) descriptor:   &'a SobjectDescriptor,
    pub(crate) public:       &'a Key<PublicParts, UnspecifiedRole>,
}

impl Signer for RawSigner<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn sign(
        &mut self,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> SequoiaResult<mpi::Signature> {
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

            match self.public.pk_algo() {
                PublicKeyAlgorithm::RSAEncryptSign => {
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
                    mpi::Signature::RSA { s: plain.into() }
                }
                PublicKeyAlgorithm::EdDSA => {
                    let sign_req = SignRequest {
                        key: Some(self.descriptor.clone()),
                        hash_alg,
                        data: Some(digest.to_vec().into()),
                        hash: None,
                        mode: None,
                        deterministic_signature: None,
                    };
                    let sign_resp = http_client.sign(&sign_req)?;

                    let plain: Vec<u8> = sign_resp.signature.into();
                    mpi::Signature::EdDSA {
                        r: mpi::MPI::new(&plain[..32]),
                        s: mpi::MPI::new(&plain[32..]),
                    }
                }
                PublicKeyAlgorithm::ECDSA => {
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
                    let (r, s) = yasna::parse_der(&plain, |reader| {
                        reader.read_sequence(|reader| {
                            let r = reader.next().read_biguint()?.to_bytes_be();
                            let s = reader.next().read_biguint()?.to_bytes_be();
                            Ok((r, s))
                        })
                    })
                    .map_err(|e| {
                        anyhow::Error::msg(format!("ECDSA signature: {}", e))
                    })?;

                    mpi::Signature::ECDSA {
                        r: r.to_vec().into(),
                        s: s.to_vec().into(),
                    }
                }
                _ => unimplemented!(),
            }
        };

        Ok(signature)
    }
}
