use std::borrow::Cow;
use std::convert::TryFrom;
use std::sync::Mutex;

use win_crypto_ng::symmetric as cng;

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
            AES128 | AES192 | AES256 | TripleDES
                => true,
            IDEA | CAST5 | Blowfish | Twofish
                | Camellia128 | Camellia192 | Camellia256
                | Unencrypted  | Private(_) | Unknown(_)
                => false,
        }
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        let block_size = algo.block_size()?;
        match mode {
            BlockCipherMode::CFB => {
                let (algo, _) = TryFrom::try_from(algo)?;

                let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Cfb)?;
                let mut key = algo.new_key(key)?;
                // Use full-block CFB mode as expected everywhere else (by default it's
                // set to 8-bit CFB)
                key.set_msg_block_len(key.block_size()?)?;

                Ok(Box::new(KeyWrapper::new(key, block_size,
                                            Some(iv.into_owned()))))
            },

            BlockCipherMode::CBC => {
                let (algo, _) = TryFrom::try_from(algo)?;

                let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Cbc)?;
                let key = algo.new_key(key)?;

                Ok(Box::new(KeyWrapper::new(key, block_size,
                                            Some(iv.into_owned()))))
            },

            BlockCipherMode::ECB => {
                let (algo, _) = TryFrom::try_from(algo)?;

                let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Ecb)?;
                let key = algo.new_key(key)?;

                Ok(Box::new(KeyWrapper::new(key, block_size, None)))
            },
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB =>
                Self::encryptor_impl(algo, mode, key, iv),

            BlockCipherMode::CBC =>
                Self::encryptor_impl(algo, mode, key, iv),

            BlockCipherMode::ECB =>
                Self::encryptor_impl(algo, mode, key, iv),
        }
    }
}

struct KeyWrapper {
    key: Mutex<cng::SymmetricAlgorithmKey>,
    block_size: usize,
    iv: Option<Protected>,
}

impl KeyWrapper {
    fn new(key: cng::SymmetricAlgorithmKey,
           block_size: usize,
           iv: Option<Vec<u8>>)
           -> KeyWrapper
    {
        KeyWrapper {
            key: Mutex::new(key),
            block_size,
            iv: iv.map(|iv| iv.into()),
        }
    }
}

impl Context for KeyWrapper {
    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        let block_size = self.block_size;
        // If necessary, round up to the next block size and pad with zeroes
        // NOTE: In theory CFB doesn't need this but CNG always requires
        // passing full blocks.
        let mut _src;
        let missing = (block_size - (src.len() % block_size)) % block_size;
        let src = if missing != 0 {
            _src = Protected::new(src.len() + missing);
            _src[..src.len()].copy_from_slice(src);
            &_src
        } else {
            src
        };

        let len = std::cmp::min(src.len(), dst.len());
        let buffer = cng::SymmetricAlgorithmKey::encrypt(
            &*self.key.lock().expect("Mutex not to be poisoned"),
            self.iv.as_deref_mut(), src, None)?;
        Ok(dst[..len].copy_from_slice(&buffer.as_slice()[..len]))
    }

    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        let block_size = self.block_size;
        // If necessary, round up to the next block size and pad with zeroes
        // NOTE: In theory CFB doesn't need this but CNG always requires
        // passing full blocks.
        let mut _src = vec![];
        let missing = (block_size - (src.len() % block_size)) % block_size;
        let src = if missing != 0 {
            _src = vec![0u8; src.len() + missing];
            _src[..src.len()].copy_from_slice(src);
            &_src
        } else {
            src
        };

        let len = std::cmp::min(src.len(), dst.len());
        let buffer = cng::SymmetricAlgorithmKey::decrypt(
            &*self.key.lock().expect("Mutex not to be poisoned"),
            self.iv.as_deref_mut(), src, None)?;
        dst[..len].copy_from_slice(&buffer.as_slice()[..len]);

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Unsupported algorithm: {0}")]
pub struct UnsupportedAlgorithm(SymmetricAlgorithm);
assert_send_and_sync!(UnsupportedAlgorithm);

impl From<UnsupportedAlgorithm> for Error {
    fn from(value: UnsupportedAlgorithm) -> Error {
        Error::UnsupportedSymmetricAlgorithm(value.0)
    }
}

impl TryFrom<SymmetricAlgorithm> for (cng::SymmetricAlgorithmId, usize) {
    type Error = UnsupportedAlgorithm;
    fn try_from(value: SymmetricAlgorithm) -> std::result::Result<Self, Self::Error> {
        #[allow(deprecated)]
        Ok(match value {
            SymmetricAlgorithm::TripleDES => (cng::SymmetricAlgorithmId::TripleDes, 168),
            SymmetricAlgorithm::AES128 => (cng::SymmetricAlgorithmId::Aes, 128),
            SymmetricAlgorithm::AES192 => (cng::SymmetricAlgorithmId::Aes, 192),
            SymmetricAlgorithm::AES256 => (cng::SymmetricAlgorithmId::Aes, 256),
            algo => Err(UnsupportedAlgorithm(algo))?,
        })
    }
}
