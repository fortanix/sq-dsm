use std::borrow::Cow;

use crate::{Error, Result};

use crate::crypto::{
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        use self::SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            TripleDES | IDEA | CAST5 | Blowfish |
            AES128 | AES192 | AES256 | Twofish |
            Camellia128 | Camellia192 | Camellia256
                => true,
            Unencrypted | Private(_) | Unknown(_)
                => false,
        }
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB => {
                let mut cipher = botan::Cipher::new(
                    &format!("{}/CFB", algo.botan_name()?),
                    botan::CipherDirection::Encrypt)?;

                cipher.set_key(key)?;
                cipher.start(&iv)?;

                Ok(Box::new(cipher))
            },

            BlockCipherMode::CBC => {
                let mut cipher = botan::Cipher::new(
                    &format!("{}/CBC/NoPadding", algo.botan_name()?),
                    botan::CipherDirection::Encrypt)?;

                cipher.set_key(key)?;
                cipher.start(&iv)?;

                Ok(Box::new(cipher))
            },

            BlockCipherMode::ECB => {
                let mut cipher =
                    botan::BlockCipher::new(algo.botan_name()?)?;

                cipher.set_key(key)?;

                Ok(Box::new(cipher))
            },
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB => {
                let mut cipher = botan::Cipher::new(
                    &format!("{}/CFB", algo.botan_name()?),
                    botan::CipherDirection::Decrypt)?;

                cipher.set_key(key)?;
                cipher.start(&iv)?;

                Ok(Box::new(cipher))
            },

            BlockCipherMode::CBC => {
                let mut cipher = botan::Cipher::new(
                    &format!("{}/CBC/NoPadding", algo.botan_name()?),
                    botan::CipherDirection::Decrypt)?;

                cipher.set_key(key)?;
                cipher.start(&iv)?;

                Ok(Box::new(cipher))
            },

            BlockCipherMode::ECB =>
                Self::encryptor_impl(algo, mode, key, iv),
        }
    }
}

impl Context for botan::BlockCipher {
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len());
        let l = dst.len().min(src.len());
        dst[..l].copy_from_slice(&src[..l]);
        self.encrypt_in_place(dst)?;
        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len());
        let l = dst.len().min(src.len());
        dst[..l].copy_from_slice(&src[..l]);
        self.decrypt_in_place(dst)?;
        Ok(())
    }
}

impl Context for botan::Cipher {
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len());
        self.finish_into(src, dst)?;
        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len());
        self.finish_into(src, dst)?;
        Ok(())
    }
}

impl SymmetricAlgorithm {
    /// Returns the name of the algorithm for use with Botan's
    /// constructor.
    pub(crate) fn botan_name(self) -> Result<&'static str> {
        #[allow(deprecated)]
        match self {
            SymmetricAlgorithm::IDEA => Ok("IDEA"),
            SymmetricAlgorithm::TripleDES => Ok("3DES"),
            SymmetricAlgorithm::CAST5 => Ok("CAST-128"),
            SymmetricAlgorithm::Blowfish => Ok("Blowfish"),
            SymmetricAlgorithm::AES128 => Ok("AES-128"),
            SymmetricAlgorithm::AES192 => Ok("AES-192"),
            SymmetricAlgorithm::AES256 => Ok("AES-256"),
            SymmetricAlgorithm::Twofish => Ok("Twofish"),
            SymmetricAlgorithm::Camellia128 => Ok("Camellia-128"),
            SymmetricAlgorithm::Camellia192 => Ok("Camellia-192"),
            SymmetricAlgorithm::Camellia256 => Ok("Camellia-256"),
            SymmetricAlgorithm::Unencrypted |
            SymmetricAlgorithm::Unknown(_) |
            SymmetricAlgorithm::Private(_) =>
                Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }
}
