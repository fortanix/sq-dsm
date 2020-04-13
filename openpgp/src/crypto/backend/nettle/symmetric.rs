use nettle::cipher::{self, Cipher};
use nettle::mode::{self};

use crate::crypto::symmetric::Mode;

use crate::{Error, Result};
use crate::types::SymmetricAlgorithm;

impl<T: nettle::mode::Mode> Mode for T {
    fn block_size(&self) -> usize {
        self.block_size()
    }

    fn encrypt(
        &mut self,
        iv: &mut [u8],
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.encrypt(iv, dst, src)
            .map_err(Into::into)
    }

    fn decrypt(
        &mut self,
        iv: &mut [u8],
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        self.decrypt(iv, dst, src)
            .map_err(Into::into)
    }
}

impl SymmetricAlgorithm {
    /// Length of a key for this algorithm in bytes.  Fails if Sequoia
    /// does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        match self {
            SymmetricAlgorithm::TripleDES => Ok(cipher::Des3::KEY_SIZE),
            SymmetricAlgorithm::CAST5 => Ok(cipher::Cast128::KEY_SIZE),
            // RFC4880, Section 9.2: Blowfish (128 bit key, 16 rounds)
            SymmetricAlgorithm::Blowfish => Ok(16),
            SymmetricAlgorithm::AES128 => Ok(cipher::Aes128::KEY_SIZE),
            SymmetricAlgorithm::AES192 => Ok(cipher::Aes192::KEY_SIZE),
            SymmetricAlgorithm::AES256 => Ok(cipher::Aes256::KEY_SIZE),
            SymmetricAlgorithm::Twofish => Ok(cipher::Twofish::KEY_SIZE),
            SymmetricAlgorithm::Camellia128 => Ok(cipher::Camellia128::KEY_SIZE),
            SymmetricAlgorithm::Camellia192 => Ok(cipher::Camellia192::KEY_SIZE),
            SymmetricAlgorithm::Camellia256 => Ok(cipher::Camellia256::KEY_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Length of a block for this algorithm in bytes.  Fails if
    /// Sequoia does not support this algorithm.
    pub fn block_size(self) -> Result<usize> {
        match self {
            SymmetricAlgorithm::TripleDES => Ok(cipher::Des3::BLOCK_SIZE),
            SymmetricAlgorithm::CAST5 => Ok(cipher::Cast128::BLOCK_SIZE),
            SymmetricAlgorithm::Blowfish => Ok(cipher::Blowfish::BLOCK_SIZE),
            SymmetricAlgorithm::AES128 => Ok(cipher::Aes128::BLOCK_SIZE),
            SymmetricAlgorithm::AES192 => Ok(cipher::Aes192::BLOCK_SIZE),
            SymmetricAlgorithm::AES256 => Ok(cipher::Aes256::BLOCK_SIZE),
            SymmetricAlgorithm::Twofish => Ok(cipher::Twofish::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia128 => Ok(cipher::Camellia128::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia192 => Ok(cipher::Camellia192::BLOCK_SIZE),
            SymmetricAlgorithm::Camellia256 => Ok(cipher::Camellia256::BLOCK_SIZE),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Creates a Nettle context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Des3>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Cast128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Blowfish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes256>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Twofish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia256>::with_encrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Creates a Nettle context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Des3>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Cast128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Blowfish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Aes256>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Twofish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
                Ok(Box::new(
                    mode::Cfb::<cipher::Camellia256>::with_decrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into())
        }
    }

    /// Creates a Nettle context for encrypting in CBC mode.
    pub(crate) fn make_encrypt_cbc(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Des3>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Cast128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Blowfish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes256>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Twofish>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Camellia128>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Camellia192>::with_encrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Camellia256>::with_encrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Creates a Nettle context for decrypting in CBC mode.
    pub(crate) fn make_decrypt_cbc(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        match self {
            SymmetricAlgorithm::TripleDES =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Des3>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::CAST5 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Cast128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Blowfish =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Blowfish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES128 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES192 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::AES256 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Aes256>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Twofish =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Twofish>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia128 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Camellia128>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia192 =>
                Ok(Box::new(
                    mode::Cbc::<cipher::Camellia192>::with_decrypt_key(&key[..])?)),
            SymmetricAlgorithm::Camellia256 =>
            Ok(Box::new(
                    mode::Cbc::<cipher::Camellia256>::with_decrypt_key(&key[..])?)),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }
}