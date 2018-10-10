use nettle::{aead, cipher};

use Error;
use Result;
use constants::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};

impl AEADAlgorithm {
    /// Returns the digest size of the AEAD algorithm.
    pub fn digest_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            &EAX =>
            // Digest size is independent of the cipher.
                Ok(aead::Eax::<cipher::Aes128>::DIGEST_SIZE),
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }

    /// Returns the initialization vector size of the AEAD algorithm.
    pub fn iv_size(&self) -> Result<usize> {
        use self::AEADAlgorithm::*;
        match self {
            &EAX =>
                Ok(16), // According to RFC4880bis, Section 5.16.1.
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }

    /// Creates a nettle context.
    pub fn context(&self, cipher: SymmetricAlgorithm, key: &[u8], nonce: &[u8])
                   -> Result<Box<aead::Aead>> {
        match self {
            AEADAlgorithm::EAX => match cipher {
                SymmetricAlgorithm::AES128 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes128>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::AES192 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes192>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::AES256 =>
                    Ok(Box::new(aead::Eax::<cipher::Aes256>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::Twofish =>
                    Ok(Box::new(aead::Eax::<cipher::Twofish>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::Camellia128 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia128>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::Camellia192 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia192>
                                ::with_key_and_nonce(key, nonce))),
                SymmetricAlgorithm::Camellia256 =>
                    Ok(Box::new(aead::Eax::<cipher::Camellia256>
                                ::with_key_and_nonce(key, nonce))),
                _ =>
                    Err(Error::UnsupportedSymmetricAlgorithm(cipher).into()),
            },
            _ =>
                Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}
