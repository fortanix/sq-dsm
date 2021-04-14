use sequoia_openpgp::{
    crypto::{mpi, Decryptor, SessionKey},
    packet::{
        key::{PublicParts, UnspecifiedRole},
        Key,
    },
    Result as SequoiaResult,
};

use sdkms::{
    api_model::{DecryptRequest, SobjectDescriptor},
};

use super::Operation;

pub(crate) struct Decrypt {}

impl Operation for Decrypt {}

pub(crate) type PgpDecryptor = super::Agent<Decrypt>;

impl Decryptor for PgpDecryptor {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public_key
    }

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
            iv: None,
            key: Some(SobjectDescriptor::Name(self.key_name.to_string())),
            mode: None,
            alg: None,
            ad: None,
            tag: None,
        };

        let decrypt_resp = self.http_client.decrypt(&decrypt_req)?;
        let plain: Vec<u8> = decrypt_resp.plain.into();

        Ok(plain.into())
    }
}
