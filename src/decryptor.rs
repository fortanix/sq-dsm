use sdkms::api_model::{Algorithm, DecryptRequest, SobjectDescriptor};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::{mpi, Decryptor, SessionKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Result as SequoiaResult;

pub struct RawDecryptor<'a> {
    pub http_client: &'a SdkmsClient,
    pub descriptor:  &'a SobjectDescriptor,
    pub public:      &'a Key<PublicParts, UnspecifiedRole>,
}

impl Decryptor for RawDecryptor<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> SequoiaResult<SessionKey> {
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

        let decrypt_resp = self.http_client.decrypt(&decrypt_req)?;

        Ok(decrypt_resp.plain.to_vec().into())
    }
}
