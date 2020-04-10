use std::convert::TryFrom;

use win_crypto_ng::symmetric as cng;

use crate::crypto::symmetric::Mode;

use crate::{Error, Result};
use crate::types::SymmetricAlgorithm;


impl Mode for cng::SymmetricAlgorithmKey {
    fn block_size(&self) -> usize {
        self.block_size().expect("CNG not to fail internally")
    }

    fn encrypt(
        &mut self,
        iv: &mut [u8],
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        let block_size = Mode::block_size(self);
        // If necessary, round up to the next block size and pad with zeroes
        // NOTE: In theory CFB doesn't need this but CNG always requires
        // passing full blocks.
        let mut _src = vec![];
        let missing = (block_size - (src.len() % block_size)) % block_size;
        let src = if missing != 0 {
            _src = vec![0u8; src.len() + missing];
            &mut _src[..src.len()].copy_from_slice(src);
            &_src
        } else {
            src
        };

        let len = std::cmp::min(src.len(), dst.len());
        // NOTE: `None` IV is required for ECB mode but we don't ever use it.
        let buffer = cng::SymmetricAlgorithmKey::encrypt(self, Some(iv), src, None)?;
        Ok(dst[..len].copy_from_slice(&buffer.as_slice()[..len]))
    }

    fn decrypt(
        &mut self,
        iv: &mut [u8],
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        let block_size = Mode::block_size(self);
        // If necessary, round up to the next block size and pad with zeroes
        // NOTE: In theory CFB doesn't need this but CNG always requires
        // passing full blocks.
        let mut _src = vec![];
        let missing = (block_size - (src.len() % block_size)) % block_size;
        let src = if missing != 0 {
            _src = vec![0u8; src.len() + missing];
            &mut _src[..src.len()].copy_from_slice(src);
            &_src
        } else {
            src
        };

        let len = std::cmp::min(src.len(), dst.len());
        // NOTE: `None` IV is required for ECB mode but we don't ever use it.
        let buffer = cng::SymmetricAlgorithmKey::decrypt(self, Some(iv), src, None)?;
        dst[..len].copy_from_slice(&buffer.as_slice()[..len]);

        Ok(())
    }
}


#[derive(Debug, thiserror::Error)]
#[error("Unsupported algorithm: {0}")]
pub struct UnsupportedAlgorithm(SymmetricAlgorithm);

impl From<UnsupportedAlgorithm> for Error {
    fn from(value: UnsupportedAlgorithm) -> Error {
        Error::UnsupportedSymmetricAlgorithm(value.0)
    }
}

impl TryFrom<SymmetricAlgorithm> for (cng::SymmetricAlgorithmId, usize) {
    type Error = UnsupportedAlgorithm;
    fn try_from(value: SymmetricAlgorithm) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            SymmetricAlgorithm::TripleDES => (cng::SymmetricAlgorithmId::TripleDes, 168),
            SymmetricAlgorithm::AES128 => (cng::SymmetricAlgorithmId::Aes, 128),
            SymmetricAlgorithm::AES192 => (cng::SymmetricAlgorithmId::Aes, 192),
            SymmetricAlgorithm::AES256 => (cng::SymmetricAlgorithmId::Aes, 256),
            algo => Err(UnsupportedAlgorithm(algo))?,
        })
    }
}

impl SymmetricAlgorithm {
    /// Length of a key for this algorithm in bytes.  Fails if Sequoia
    /// does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        Ok(match self {
            SymmetricAlgorithm::TripleDES => 24,
            SymmetricAlgorithm::AES128 => 16,
            SymmetricAlgorithm::AES192 => 24,
            SymmetricAlgorithm::AES256 => 32,
            _ => Err(UnsupportedAlgorithm(self))?,
        })
    }

    /// Length of a block for this algorithm in bytes.  Fails if
    /// Sequoia does not support this algorithm.
    pub fn block_size(self) -> Result<usize> {
        Ok(match self {
            SymmetricAlgorithm::TripleDES => 8,
            SymmetricAlgorithm::AES128 => 16,
            SymmetricAlgorithm::AES192 => 16,
            SymmetricAlgorithm::AES256 => 16,
            _ => Err(UnsupportedAlgorithm(self))?,
        })
    }

    /// Creates a symmetric cipher context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let (algo, _) = TryFrom::try_from(self)?;

        let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Cfb)?;
        let mut key = algo.new_key(key)?;
        // Use full-block CFB mode as expected everywhere else (by default it's
        // set to 8-bit CFB)
        key.set_msg_block_len(key.block_size()?)?;

        Ok(Box::new(key))
    }

    /// Creates a symmetric cipher context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        Self::make_encrypt_cfb(self, key)
    }

    /// Creates a Nettle context for encrypting in CBC mode.
    pub(crate) fn make_encrypt_cbc(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let (algo, _) = TryFrom::try_from(self)?;

        let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Cbc)?;

        Ok(Box::new(
            algo.new_key(key).expect(
                "CNG to successfully create a symmetric key for valid/supported algorithm"
            )
        ))
    }

    /// Creates a Nettle context for decrypting in CBC mode.
    pub(crate) fn make_decrypt_cbc(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let (algo, _) = TryFrom::try_from(self)?;

        let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Cbc)?;

        Ok(Box::new(
            algo.new_key(key).expect(
                "CNG to successfully create a symmetric key for valid/supported algorithm"
            )
        ))
    }
}
