use sdkms::api_model::{Algorithm, DecryptRequest, SobjectDescriptor};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::{mpi, Decryptor, SessionKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Result as SequoiaResult;

pub struct RawDecryptor<'a> {
    pub api_endpoint: &'a str,
    pub api_key:      &'a str,
    pub descriptor:   &'a SobjectDescriptor,
    pub public:       &'a Key<PublicParts, UnspecifiedRole>,
}

impl Decryptor for RawDecryptor<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> SequoiaResult<SessionKey> {
        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&self.api_endpoint)
            .with_api_key(&self.api_key)
            .build()?;

        let raw_ciphertext = match ciphertext {
            mpi::Ciphertext::RSA { c } => c.value().to_vec(),
            _ => unimplemented!(),
        };

        let decrypt_req = DecryptRequest {
            cipher: raw_ciphertext.into(),
            alg:    Some(Algorithm::Rsa),
            iv:     None,
            key:    Some(self.descriptor.clone()),
            mode:   None,
            ad:     None,
            tag:    None,
        };

        let decrypt_resp = http_client.decrypt(&decrypt_req)?;

        Ok(decrypt_resp.plain.to_vec().into())
    }
}
