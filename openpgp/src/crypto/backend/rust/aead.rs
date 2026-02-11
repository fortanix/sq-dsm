//! Implementation of AEAD using pure Rust cryptographic libraries.

use std::cmp;
use std::cmp::Ordering;

use cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, Unsigned};
use cipher::consts::{U12, U15, U16};
use eax::online::{Eax, Encrypt, Decrypt};
use cipher::generic_array::GenericArray;

use crate::{Error, Result};
use crate::crypto::aead::{Context, CipherOp};
use crate::crypto::mem::{Protected, secure_cmp};
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use super::GenericArrayExt;

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

type TagLen = U16;

impl<Cipher> Context for Eax<Cipher, Encrypt, TagLen>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
{
    fn digest_size(&self) -> usize {
        TagLen::USIZE
    }

    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        let len = cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        Self::encrypt(self, &mut dst[..len]);
        let tag = self.tag_clone();
        dst[src.len()..].copy_from_slice(&tag[..]);
        Ok(())
    }

    fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("AEAD decryption called in the encryption context")
    }
}

impl<Cipher> Context for Eax<Cipher, Decrypt, TagLen>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
{
    fn digest_size(&self) -> usize {
        TagLen::USIZE
    }

    fn encrypt_seal(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("AEAD encryption called in the decryption context")
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());

        // Split src into ciphertext and digest.
        let l = self.digest_size();
        let digest = &src[src.len().saturating_sub(l)..];
        let src = &src[..src.len().saturating_sub(l)];

        let len = core::cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        self.decrypt_unauthenticated_hazmat(&mut dst[..len]);

        let chunk_digest = self.tag_clone();
        if secure_cmp(&chunk_digest[..], digest)
             != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
            {
                 return Err(Error::ManipulatedMessage.into());
            }
        Ok(())
    }
}

impl<Cipher, Op> seal::Sealed for Eax<Cipher, Op, TagLen>
where
    Cipher: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone + KeyInit,
    Op: eax::online::CipherOp,
{}

struct Gcm<Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt> {
    cipher: aes_gcm::AesGcm<Cipher, U12>,
    nonce: GenericArray<u8, U12>,
    aad: Vec<u8>,
}

impl<Cipher> Context for Gcm<Cipher>
where
    Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn digest_size(&self) -> usize {
        TagLen::USIZE
    }

    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        use aes_gcm::AeadInPlace;

        let len = cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        let tag =
            self.cipher.encrypt_in_place_detached(&self.nonce, &self.aad,
                                                  &mut dst[..len])?;
        debug_assert_eq!(dst[len..].len(), tag.len());
        let tag_len = cmp::min(dst[len..].len(), tag.len());
        dst[len..len + tag_len].copy_from_slice(&tag[..tag_len]);
        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());
        use aes_gcm::AeadInPlace;

        // Split src into ciphertext and digest.
        let len = src.len().saturating_sub(self.digest_size());
        let digest = &src[len..];
        let src = &src[..len];

        debug_assert_eq!(dst.len(), src.len());
        let len = core::cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        self.cipher.decrypt_in_place_detached(&self.nonce, &self.aad, dst,
                                              digest.try_into()?)?;
        Ok(())
    }
}

impl<'a, Cipher> seal::Sealed for Gcm<Cipher>
where
    Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{}

struct Ocb<Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockDecrypt + BlockEncrypt> {
    cipher: ocb3::Ocb3<Cipher, U15>,
    nonce: GenericArray<u8, U15>,
    aad: Vec<u8>,
}

impl<Cipher> Context for Ocb<Cipher>
where
    Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockDecrypt + BlockEncrypt,
{
    fn digest_size(&self) -> usize {
        TagLen::USIZE
    }

    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        use ocb3::AeadInPlace;

        let len = cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        let tag =
            self.cipher.encrypt_in_place_detached(&self.nonce, &self.aad,
                                                  &mut dst[..len])?;
        debug_assert_eq!(dst[len..].len(), tag.len());
        let tag_len = cmp::min(dst[len..].len(), tag.len());
        dst[len..len + tag_len].copy_from_slice(&tag[..tag_len]);
        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());
        use ocb3::AeadInPlace;

        // Split src into ciphertext and digest.
        let len = src.len().saturating_sub(self.digest_size());
        let digest = &src[len..];
        let src = &src[..len];

        debug_assert_eq!(dst.len(), src.len());
        let len = core::cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        self.cipher.decrypt_in_place_detached(&self.nonce, &self.aad, dst,
                                              digest.try_into()?)?;
        Ok(())
    }
}

impl<'a, Cipher> seal::Sealed for Ocb<Cipher>
where
    Cipher: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockDecrypt + BlockEncrypt,
{}


impl crate::crypto::backend::interface::Aead for super::Backend {
    fn supports_algo(algo: AEADAlgorithm) -> bool {
        use self::AEADAlgorithm::*;
        match algo {
            EAX => true,
            OCB => true,
            GCM => true,
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

            AEADAlgorithm::OCB => match symm {
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 |
                SymmetricAlgorithm::Twofish |
                SymmetricAlgorithm::Camellia128 |
                SymmetricAlgorithm::Camellia192 |
                SymmetricAlgorithm::Camellia256 => true,
                _ => false,
            },

            AEADAlgorithm::GCM => match symm {
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 => true,
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
        op: CipherOp,
    ) -> Result<Box<dyn Context>> {
        #[allow(deprecated)]
        match algo {
            AEADAlgorithm::EAX => match sym_algo {
                SymmetricAlgorithm::AES128 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes128, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes128, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES192 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes192, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes192, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES256 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes256, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes256, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::Twofish => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<twofish::Twofish, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<twofish::Twofish, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::Camellia128 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia128, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia128, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::Camellia192 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia192, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia192, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::Camellia256 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia256, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<camellia::Camellia256, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                | SymmetricAlgorithm::IDEA
                | SymmetricAlgorithm::TripleDES
                | SymmetricAlgorithm::CAST5
                | SymmetricAlgorithm::Blowfish
                | SymmetricAlgorithm::Private(_)
                | SymmetricAlgorithm::Unknown(_)
                | SymmetricAlgorithm::Unencrypted =>
                    Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },

            AEADAlgorithm::OCB => {
                use ocb3::{Ocb3, Nonce};
                match sym_algo {
                    SymmetricAlgorithm::AES128 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<aes::Aes128, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::AES192 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<aes::Aes192, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::AES256 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<aes::Aes256, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::Twofish => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<twofish::Twofish, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::Camellia128 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<camellia::Camellia128, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::Camellia192 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<camellia::Camellia192, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::Camellia256 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            Ocb3::<camellia::Camellia256, U15>::new_from_slice(key)?;
                        Ok(Box::new(Ocb { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    | SymmetricAlgorithm::IDEA
                    | SymmetricAlgorithm::TripleDES
                    | SymmetricAlgorithm::CAST5
                    | SymmetricAlgorithm::Blowfish
                    | SymmetricAlgorithm::Private(_)
                    | SymmetricAlgorithm::Unknown(_)
                    | SymmetricAlgorithm::Unencrypted =>
                        Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
                }
            },

            AEADAlgorithm::GCM => {
                use aes_gcm::{AesGcm, Nonce};
                match sym_algo {
                    SymmetricAlgorithm::AES128 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            AesGcm::<aes::Aes128, U12>::new_from_slice(key)?;
                        Ok(Box::new(Gcm { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::AES192 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            AesGcm::<aes::Aes192, U12>::new_from_slice(key)?;
                        Ok(Box::new(Gcm { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    SymmetricAlgorithm::AES256 => {
                        let nonce = Nonce::try_from_slice(nonce)?;
                        let cipher =
                            AesGcm::<aes::Aes256, U12>::new_from_slice(key)?;
                        Ok(Box::new(Gcm { cipher, nonce: *nonce, aad: aad.to_vec() }))
                    },
                    | SymmetricAlgorithm::IDEA
                    | SymmetricAlgorithm::TripleDES
                    | SymmetricAlgorithm::CAST5
                    | SymmetricAlgorithm::Blowfish
                    | SymmetricAlgorithm::Twofish
                    | SymmetricAlgorithm::Camellia128
                    | SymmetricAlgorithm::Camellia192
                    | SymmetricAlgorithm::Camellia256
                    | SymmetricAlgorithm::Private(_)
                    | SymmetricAlgorithm::Unknown(_)
                    | SymmetricAlgorithm::Unencrypted =>
                        Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
                }
            },

            AEADAlgorithm::Private(_) | AEADAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedAEADAlgorithm(algo).into()),
        }
    }
}
