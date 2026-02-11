use std::borrow::Cow;

use nettle::cipher::{self, Cipher};
use nettle::mode::{self};

use crate::crypto;
use crate::crypto::mem::Protected;
use crate::crypto::symmetric::{BlockCipherMode, Context};

use crate::{Error, Result};
use crate::types::SymmetricAlgorithm;

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        use self::SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            TripleDES | CAST5 | Blowfish | AES128 | AES192 | AES256 | Twofish
                | Camellia128 | Camellia192 | Camellia256
                => true,
            Unencrypted | IDEA | Private(_) | Unknown(_)
                => false,
        }
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        #[allow(deprecated)]
        match mode {
            BlockCipherMode::CFB => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Des3>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Cast128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Blowfish>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES128 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES192 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes192>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES256 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes256>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Twofish =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Twofish>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia192>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia256>::with_encrypt_key(key)?, iv)),
                _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
            },

            BlockCipherMode::CBC => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Des3>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Cast128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Blowfish>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES128 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES192 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes192>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES256 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes256>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Twofish =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Twofish>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia128>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia192>::with_encrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia256>::with_encrypt_key(key)?, iv)),
                _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
            },

            BlockCipherMode::ECB => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(Box::new(cipher::Des3::with_encrypt_key(key)?)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(Box::new(cipher::Cast128::with_encrypt_key(key)?)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(Box::new(cipher::Blowfish::with_encrypt_key(key)?)),
                SymmetricAlgorithm::AES128 =>
                    Ok(Box::new(cipher::Aes128::with_encrypt_key(key)?)),
                SymmetricAlgorithm::AES192 =>
                    Ok(Box::new(cipher::Aes192::with_encrypt_key(key)?)),
                SymmetricAlgorithm::AES256 =>
                    Ok(Box::new(cipher::Aes256::with_encrypt_key(key)?)),
                SymmetricAlgorithm::Twofish =>
                    Ok(Box::new(cipher::Twofish::with_encrypt_key(key)?)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(Box::new(cipher::Camellia128::with_encrypt_key(key)?)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(Box::new(cipher::Camellia192::with_encrypt_key(key)?)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(Box::new(cipher::Camellia256::with_encrypt_key(key)?)),
                _ =>
                    Err(Error::UnsupportedSymmetricAlgorithm(algo).into())
            },
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        #[allow(deprecated)]
        match mode {
            BlockCipherMode::CFB => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Des3>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Cast128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Blowfish>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES128 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES192 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes192>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES256 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Aes256>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Twofish =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Twofish>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia192>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(ModeWrapper::new(
                        mode::Cfb::<cipher::Camellia256>::with_decrypt_key(key)?, iv)),
                _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into())
            },

            BlockCipherMode::CBC => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Des3>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Cast128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Blowfish>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES128 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES192 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes192>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::AES256 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Aes256>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Twofish =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Twofish>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia128>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia192>::with_decrypt_key(key)?, iv)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(ModeWrapper::new(
                        mode::Cbc::<cipher::Camellia256>::with_decrypt_key(key)?, iv)),
                _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into())
            },

            BlockCipherMode::ECB => match algo {
                SymmetricAlgorithm::TripleDES =>
                    Ok(Box::new(cipher::Des3::with_decrypt_key(key)?)),
                SymmetricAlgorithm::CAST5 =>
                    Ok(Box::new(cipher::Cast128::with_decrypt_key(key)?)),
                SymmetricAlgorithm::Blowfish =>
                    Ok(Box::new(cipher::Blowfish::with_decrypt_key(key)?)),
                SymmetricAlgorithm::AES128 =>
                    Ok(Box::new(cipher::Aes128::with_decrypt_key(key)?)),
                SymmetricAlgorithm::AES192 =>
                    Ok(Box::new(cipher::Aes192::with_decrypt_key(key)?)),
                SymmetricAlgorithm::AES256 =>
                    Ok(Box::new(cipher::Aes256::with_decrypt_key(key)?)),
                SymmetricAlgorithm::Twofish =>
                    Ok(Box::new(cipher::Twofish::with_decrypt_key(key)?)),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(Box::new(cipher::Camellia128::with_decrypt_key(key)?)),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(Box::new(cipher::Camellia192::with_decrypt_key(key)?)),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(Box::new(cipher::Camellia256::with_decrypt_key(key)?)),
                _ =>
                    Err(Error::UnsupportedSymmetricAlgorithm(algo).into())
            },
        }
    }
}

struct ModeWrapper<M>
{
    mode: M,
    iv: Protected,
}

impl<M> ModeWrapper<M>
where
    M: nettle::mode::Mode + Send + Sync + 'static,
{
    fn new(mode: M, iv: Cow<'_, [u8]>) -> Box<dyn Context> {
        Box::new(ModeWrapper {
            mode,
            iv: iv.into_owned().into(),
        })
    }
}

impl<M> Context for ModeWrapper<M>
where
    M: nettle::mode::Mode + Send + Sync,
{
    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.mode.encrypt(&mut self.iv, dst, src)?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.mode.decrypt(&mut self.iv, dst, src)?;
        Ok(())
    }
}

impl<C> Context for C
where
    C: Cipher + Send + Sync,
{
    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.encrypt(dst, src);
        Ok(())
    }

    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.decrypt(dst, src);
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// Anchors the constants used in Sequoia with the ones from
    /// Nettle.
    #[test]
    fn key_size() -> Result<()> {
        assert_eq!(SymmetricAlgorithm::TripleDES.key_size()?,
                   cipher::Des3::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::CAST5.key_size()?,
                   cipher::Cast128::KEY_SIZE);
        // RFC4880, Section 9.2: Blowfish (128 bit key, 16 rounds)
        assert_eq!(SymmetricAlgorithm::Blowfish.key_size()?, 16);
        assert_eq!(SymmetricAlgorithm::AES128.key_size()?,
                   cipher::Aes128::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::AES192.key_size()?,
                   cipher::Aes192::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::AES256.key_size()?,
                   cipher::Aes256::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::Twofish.key_size()?,
                   cipher::Twofish::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia128.key_size()?,
                   cipher::Camellia128::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia192.key_size()?,
                   cipher::Camellia192::KEY_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia256.key_size()?,
                   cipher::Camellia256::KEY_SIZE);
        Ok(())
    }

    /// Anchors the constants used in Sequoia with the ones from
    /// Nettle.
    #[test]
    fn block_size() -> Result<()> {
        assert_eq!(SymmetricAlgorithm::TripleDES.block_size()?,
                   cipher::Des3::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::CAST5.block_size()?,
                   cipher::Cast128::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::Blowfish.block_size()?,
                   cipher::Blowfish::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::AES128.block_size()?,
                   cipher::Aes128::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::AES192.block_size()?,
                   cipher::Aes192::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::AES256.block_size()?,
                   cipher::Aes256::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::Twofish.block_size()?,
                   cipher::Twofish::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia128.block_size()?,
                   cipher::Camellia128::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia192.block_size()?,
                   cipher::Camellia192::BLOCK_SIZE);
        assert_eq!(SymmetricAlgorithm::Camellia256.block_size()?,
                   cipher::Camellia256::BLOCK_SIZE);
        Ok(())
    }
}
