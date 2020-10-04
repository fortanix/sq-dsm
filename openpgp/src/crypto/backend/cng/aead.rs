//! Implementation of AEAD using Windows CNG API.

use crate::{Error, Result};
use crate::crypto::aead::{Aead, CipherOp};
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use eax::online::{EaxOnline, Encrypt, Decrypt};
use win_crypto_ng::symmetric::{BlockCipherKey, Aes};
use win_crypto_ng::symmetric::block_cipher::generic_array::{GenericArray, ArrayLength};
use win_crypto_ng::symmetric::block_cipher::generic_array::typenum::{U128, U192, U256};

trait GenericArrayExt {
    const LEN: usize;
}

impl<T, N: ArrayLength<T>> GenericArrayExt for GenericArray<T, N> {
    const LEN: usize = N::USIZE;
}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {

        let nonce = GenericArray::from_slice(nonce);

        match self {
            AEADAlgorithm::EAX => match sym_algo {
                | SymmetricAlgorithm::AES128 => {
                    let key = GenericArray::from_slice(key);
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U128>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U128>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                SymmetricAlgorithm::AES192 => {
                    let key = GenericArray::from_slice(key);
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U192>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U192>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                SymmetricAlgorithm::AES256 => {
                    let key = GenericArray::from_slice(key);
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U256>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U256>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}

macro_rules! impl_aead {
    ($($type: ty),*) => {
        $(
        impl Aead for EaxOnline<$type, Encrypt> {
            fn update(&mut self, ad: &[u8]) { self.update_assoc(ad) }
            fn digest_size(&self) -> usize { <eax::Tag as GenericArrayExt>::LEN }
            fn digest(&mut self, digest: &mut [u8]) {
                let tag = self.tag_clone();
                digest[..tag.len()].copy_from_slice(&tag[..]);
            }
            fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
                let len = core::cmp::min(dst.len(), src.len());
                dst[..len].copy_from_slice(&src[..len]);
                EaxOnline::<$type, Encrypt>::encrypt(self, &mut dst[..len])
            }
            fn decrypt(&mut self, _dst: &mut [u8], _src: &[u8]) {
                panic!("AEAD decryption called in the encryption context")
            }
        }
        impl seal::Sealed for EaxOnline<$type, Encrypt> {}
        )*
        $(
        impl Aead for EaxOnline<$type, Decrypt> {
            fn update(&mut self, ad: &[u8]) { self.update_assoc(ad) }
            fn digest_size(&self) -> usize { <eax::Tag as GenericArrayExt>::LEN }
            fn digest(&mut self, digest: &mut [u8]) {
                let tag = self.tag_clone();
                digest[..tag.len()].copy_from_slice(&tag[..]);
            }
            fn encrypt(&mut self, _dst: &mut [u8], _src: &[u8]) {
                panic!("AEAD encryption called in the decryption context")
            }
            fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
                let len = core::cmp::min(dst.len(), src.len());
                dst[..len].copy_from_slice(&src[..len]);
                self.decrypt_unauthenticated_hazmat(&mut dst[..len])
            }
        }
        impl seal::Sealed for EaxOnline<$type, Decrypt> {}
        )*
    };
}

impl_aead!(BlockCipherKey<Aes, U128>, BlockCipherKey<Aes, U192>, BlockCipherKey<Aes, U256>);
