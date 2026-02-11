//! Implementation of AEAD using the Botan cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Context, CipherOp};
use crate::crypto::mem::Protected;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

struct Cipher(botan::Cipher, usize);

impl seal::Sealed for Cipher {}
impl Context for Cipher {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());
        self.0.finish_into(src, dst)?;
        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());
        self.0.finish_into(src, dst)?;
        Ok(())
    }
    fn digest_size(&self) -> usize {
        self.1
    }
}

impl AEADAlgorithm {
    /// Returns the name of the algorithm for use with Botan's
    /// constructor.
    fn botan_name(self) -> Result<&'static str> {
        match self {
            AEADAlgorithm::EAX => Ok("EAX"),
            AEADAlgorithm::OCB => Ok("OCB"),
            AEADAlgorithm::GCM => Ok("GCM"),
            _ => Err(Error::UnsupportedAEADAlgorithm(self).into()),
        }
    }
}


impl crate::crypto::backend::interface::Aead for super::Backend {
    fn supports_algo(algo: AEADAlgorithm) -> bool {
        use self::AEADAlgorithm::*;
        match algo {
            EAX | OCB | GCM
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

    fn context(algo: AEADAlgorithm,
               sym_algo: SymmetricAlgorithm,
               key: &Protected,
               aad: &[u8],
               nonce: &[u8],
               op: CipherOp)
               -> Result<Box<dyn Context>>
    {
        let mut cipher = botan::Cipher::new(
            &format!("{}/{}", sym_algo.botan_name()?, algo.botan_name()?),
            match op {
                CipherOp::Encrypt => botan::CipherDirection::Encrypt,
                CipherOp::Decrypt => botan::CipherDirection::Decrypt,
            })
        // XXX it could be the cipher that is not supported.
            .map_err(|_| Error::UnsupportedAEADAlgorithm(algo))?;

        cipher.set_key(key)?;
        cipher.set_associated_data(aad)?;
        cipher.start(nonce)?;

        Ok(Box::new(Cipher(cipher, algo.digest_size()?)))
    }
}
