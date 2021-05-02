use sequoia_openpgp::{
    crypto::{mpi, Decryptor, SessionKey},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    Result as SequoiaResult,
};

use sdkms::{
    api_model::{Algorithm::Rsa, DecryptRequest, SobjectDescriptor},
    SdkmsClient,
};

pub(crate) struct RawDecryptor<'a> {
    pub(crate) api_endpoint: &'a str,
    pub(crate) api_key: &'a str,
    pub(crate) descriptor: &'a SobjectDescriptor,
    pub(crate) public: &'a Key<PublicParts, UnspecifiedRole>,
}

impl Decryptor for RawDecryptor<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

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
            alg: Some(Rsa),
            iv: None,
            key: Some(self.descriptor.clone()),
            mode: None,
            ad: None,
            tag: None,
        };

        let decrypt_resp = http_client.decrypt(&decrypt_req).unwrap();

        Ok(decrypt_resp.plain.to_vec().into())
    }
}
