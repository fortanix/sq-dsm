use std::borrow::Cow;

use crate::{Error, Result};

use crate::crypto::{
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        let cipher: &CipherRef = if let Ok(cipher) = algo.make_cfb_cipher() {
            cipher
        } else {
            return false;
        };

        let mut ctx = if let Ok(ctx) = CipherCtx::new() {
            ctx
        } else {
            return false;
        };
        ctx.encrypt_init(Some(cipher), None, None).is_ok()
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        #[allow(deprecated)]
        match mode {
            BlockCipherMode::CFB => {
                let cipher = algo.make_cfb_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.encrypt_init(Some(cipher), Some(key), Some(&iv))?;
                Ok(Box::new(OpenSslMode::new(ctx)))
            },

            BlockCipherMode::CBC => {
                let cipher = algo.make_cbc_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.encrypt_init(Some(cipher), Some(key), Some(&iv))?;
                ctx.set_padding(false);
                Ok(Box::new(OpenSslMode::new(ctx)))
            },

            BlockCipherMode::ECB => {
                let cipher = algo.make_ecb_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.encrypt_init(Some(cipher), Some(key), None)?;
                ctx.set_padding(false);
                Ok(Box::new(OpenSslMode::new(ctx)))
            },
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        #[allow(deprecated)]
        match mode {
            BlockCipherMode::CFB => {
                let cipher = algo.make_cfb_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.decrypt_init(Some(cipher), Some(key), Some(&iv))?;
                Ok(Box::new(OpenSslMode::new(ctx)))
            },

            BlockCipherMode::CBC => {
                let cipher = algo.make_cbc_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.decrypt_init(Some(cipher), Some(key), Some(&iv))?;
                ctx.set_padding(false);
                Ok(Box::new(OpenSslMode::new(ctx)))
            },

            BlockCipherMode::ECB => {
                let cipher = algo.make_ecb_cipher()?;
                let mut ctx = CipherCtx::new()?;
                ctx.decrypt_init(Some(cipher), Some(key), None)?;
                ctx.set_padding(false);
                Ok(Box::new(OpenSslMode::new(ctx)))
            },
        }
    }
}

struct OpenSslMode {
    ctx: CipherCtx,
}

impl OpenSslMode {
    fn new(ctx: CipherCtx) -> Self {
        Self { ctx }
    }
}

impl Context for OpenSslMode {
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        // Note that for cipher constructions that OpenSSL considers
        // "streaming" (such as CFB mode) the block size will be
        // always "1" instead of the real block size of the underlying
        // cipher.
        let block_size = self.ctx.block_size();

        // SAFETY: If this is a block cipher we require the source length
        // to be a multiple of the block size.
        if block_size > 1 && src.len() % block_size > 0 {
            return Err(Error::InvalidArgument(
                "src needs to be a multiple of the block size".into()).into());
        }

        // SAFETY: `dst` must be big enough to hold decrypted data.
        if dst.len() < src.len() {
            return Err(Error::InvalidArgument(
                "dst need to be big enough to hold decrypted data".into(),
            )
            .into());
        }

        // SAFETY: This call is safe because either:
        //
        // - this is a streaming cipher (block_size == 1),
        // - or a block cipher (block_size > 1) and `src` and `dst`
        //   are a multiple of the block size, and we don't use any
        //   padding.
        debug_assert_eq!(dst.len(), src.len());
        unsafe {
            self.ctx.cipher_update_unchecked(src, Some(dst))?;
        }

        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.encrypt(dst, src)
    }
}

impl SymmetricAlgorithm {
    fn make_cfb_cipher(self) -> Result<&'static CipherRef> {
        #[allow(deprecated)]
        Ok(match self {
            #[cfg(not(osslconf = "OPENSSL_NO_IDEA"))]
            SymmetricAlgorithm::IDEA => Cipher::idea_cfb64(),

            SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),

            SymmetricAlgorithm::TripleDES => Cipher::des_ede3_cfb64(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_cfb128(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia192 => Cipher::camellia192_cfb128(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia256 => Cipher::camellia256_cfb128(),

            #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
            SymmetricAlgorithm::Blowfish => Cipher::bf_cfb64(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAST"))]
            SymmetricAlgorithm::CAST5 => Cipher::cast5_cfb64(),
            _ => return Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }

    fn make_cbc_cipher(self) -> Result<&'static CipherRef> {
        #[allow(deprecated)]
        Ok(match self {
            #[cfg(not(osslconf = "OPENSSL_NO_IDEA"))]
            SymmetricAlgorithm::IDEA => Cipher::idea_cbc(),

            SymmetricAlgorithm::AES128 => Cipher::aes_128_cbc(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_cbc(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_cbc(),

            SymmetricAlgorithm::TripleDES => Cipher::des_ede3_cbc(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_cbc(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia192 => Cipher::camellia192_cbc(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia256 => Cipher::camellia256_cbc(),

            #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
            SymmetricAlgorithm::Blowfish => Cipher::bf_cbc(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAST"))]
            SymmetricAlgorithm::CAST5 => Cipher::cast5_cbc(),
            _ => return Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }

    fn make_ecb_cipher(self) -> Result<&'static CipherRef> {
        #[allow(deprecated)]
        Ok(match self {
            #[cfg(not(osslconf = "OPENSSL_NO_IDEA"))]
            SymmetricAlgorithm::IDEA => Cipher::idea_ecb(),

            SymmetricAlgorithm::AES128 => Cipher::aes_128_ecb(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_ecb(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_ecb(),

            SymmetricAlgorithm::TripleDES => Cipher::des_ede3_ecb(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_ecb(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia192 => Cipher::camellia192_ecb(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia256 => Cipher::camellia256_ecb(),

            #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
            SymmetricAlgorithm::Blowfish => Cipher::bf_ecb(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAST"))]
            SymmetricAlgorithm::CAST5 => Cipher::cast5_ecb(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchors the constants used in Sequoia with the ones from
    /// OpenSSL.
    #[test]
    fn key_size() -> Result<()> {
        for a in SymmetricAlgorithm::variants() {
            if let Ok(cipher) = a.make_cfb_cipher() {
                assert_eq!(a.key_size()?, cipher.key_length());
            }
        }
        Ok(())
    }

    /// Anchors the constants used in Sequoia with the ones from
    /// OpenSSL.
    #[test]
    fn block_size() -> Result<()> {
        for a in SymmetricAlgorithm::variants() {
            if let Ok(cipher) = a.make_ecb_cipher() {
                assert_eq!(a.block_size()?, cipher.block_size());
            }
        }
        Ok(())
    }
}
