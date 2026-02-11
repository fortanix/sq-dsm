//! Implementation of AEAD using Nettle cryptographic library.
use std::cmp::Ordering;

use nettle::{
    aead::{
        self,
        Aead as _,
        typenum::consts::U16,
    },
    cipher,
};

use crate::{Error, Result};

use crate::crypto::aead::{Context, CipherOp};
use crate::crypto::mem::{Protected, secure_cmp};
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

impl<T: nettle::aead::Aead> seal::Sealed for T {}
impl<T: nettle::aead::Aead> Context for T {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        self.encrypt(dst, src);
        self.digest(&mut dst[src.len()..]);
        Ok(())
    }
    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert!(src.len() >= self.digest_size());
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());

        // Split src into ciphertext and digest.
        let l = self.digest_size();
        let ciphertext = &src[..src.len().saturating_sub(l)];
        let digest = &src[src.len().saturating_sub(l)..];

        // Decrypt the chunk.
        self.decrypt(dst, ciphertext);

        // Compute the digest, storing it on the stack.
        let mut chunk_digest_store = [0u8; 16];
        debug_assert!(chunk_digest_store.len() >= l);
        let chunk_digest = &mut chunk_digest_store[..l];
        self.digest(chunk_digest);

        // Authenticate the chunk.
        if secure_cmp(&chunk_digest[..], digest)
             != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
            {
                 return Err(Error::ManipulatedMessage.into());
            }
        Ok(())
    }
    fn digest_size(&self) -> usize {
        self.digest_size()
    }
}

impl crate::crypto::backend::interface::Aead for super::Backend {
    fn supports_algo(algo: AEADAlgorithm) -> bool {
        use AEADAlgorithm::*;
        match algo {
            EAX
                => true,
            OCB
                => nettle::aead::OCB_IS_SUPPORTED,
            GCM
                => true,
            Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_algo_with_symmetric(algo: AEADAlgorithm,
                                    symm: SymmetricAlgorithm)
                                    -> bool
    {
        match algo {
            AEADAlgorithm::EAX => match symm {
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 |
                SymmetricAlgorithm::Twofish |
                SymmetricAlgorithm::Camellia128 |
                SymmetricAlgorithm::Camellia192 |
                SymmetricAlgorithm::Camellia256 => true,
                _ => false,
            },

            AEADAlgorithm::OCB => {
                if nettle::aead::OCB_IS_SUPPORTED {
                    match symm {
                        SymmetricAlgorithm::AES128 |
                        SymmetricAlgorithm::AES192 |
                        SymmetricAlgorithm::AES256 |
                        SymmetricAlgorithm::Twofish |
                        SymmetricAlgorithm::Camellia128 |
                        SymmetricAlgorithm::Camellia192 |
                        SymmetricAlgorithm::Camellia256 => true,
                        _ => false,
                    }
                } else {
                    false
                }
            },

            AEADAlgorithm::GCM => match symm {
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 |
                SymmetricAlgorithm::Twofish |
                SymmetricAlgorithm::Camellia128 |
                SymmetricAlgorithm::Camellia192 |
                SymmetricAlgorithm::Camellia256 => true,
                _ => false,
            },

            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }
    }

    fn context(
        algo: AEADAlgorithm,
        sym_algo: SymmetricAlgorithm,
        key: &Protected,
        aad: &[u8],
        nonce: &[u8],
        _op: CipherOp,
    ) -> Result<Box<dyn Context>> {
        match algo {
            AEADAlgorithm::EAX => match sym_algo {
                SymmetricAlgorithm::AES128 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES192 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES256 => {
                    let mut ctx =
                        aead::Eax::<cipher::Aes256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Twofish => {
                    let mut ctx =
                        aead::Eax::<cipher::Twofish>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia128 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia192 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia256 => {
                    let mut ctx =
                        aead::Eax::<cipher::Camellia256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },

            AEADAlgorithm::OCB => match sym_algo {
                SymmetricAlgorithm::AES128 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Aes128, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES192 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Aes192, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES256 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Aes256, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Twofish => {
                    let mut ctx =
                        aead::Ocb::<cipher::Twofish, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia128 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Camellia128, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia192 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Camellia192, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia256 => {
                    let mut ctx =
                        aead::Ocb::<cipher::Camellia256, U16>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },

            AEADAlgorithm::GCM => match sym_algo {
                SymmetricAlgorithm::AES128 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Aes128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES192 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Aes192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::AES256 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Aes256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Twofish => {
                    let mut ctx =
                        aead::Gcm::<cipher::Twofish>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia128 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Camellia128>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia192 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Camellia192>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                SymmetricAlgorithm::Camellia256 => {
                    let mut ctx =
                        aead::Gcm::<cipher::Camellia256>::with_key_and_nonce(key, nonce)?;
                    ctx.update(aad);
                    Ok(Box::new(ctx))
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },

            _ => Err(Error::UnsupportedAEADAlgorithm(algo).into()),
        }
    }
}
