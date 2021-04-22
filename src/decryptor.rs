use sequoia_openpgp::{
    crypto::{mpi, Decryptor, SessionKey},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    Result as SequoiaResult,
};

use sdkms::{
    api_model::{Algorithm::Rsa, DecryptRequest},
    SdkmsClient,
};

use super::SequoiaKey;

pub(crate) struct RawDecryptor {
    pub(crate) api_endpoint: String,
    pub(crate) api_key: String,
    pub(crate) sequoia_key: SequoiaKey,
}

impl Decryptor for RawDecryptor {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.sequoia_key.public_key
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
            key: Some(self.sequoia_key.descriptor.clone()),
            mode: None,
            ad: None,
            tag: None,
        };

        let decrypt_resp = http_client.decrypt(&decrypt_req).unwrap();
        let plain: Vec<u8> = decrypt_resp.plain.into();

        Ok(plain.into())
    }
}
