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

/// CTR mode using a block cipher. CNG doesn't implement one so roll our own
/// using CNG's ECB mode.
pub struct Ctr {
    key: cng::SymmetricAlgorithmKey,
    ctr: Option<Box<[u8]>>,
}

impl Ctr {
    pub fn with_cipher_and_iv(algo: cng::SymmetricAlgorithmId, key: &[u8], iv: &[u8]) -> Result<Ctr> {
        let algo = cng::SymmetricAlgorithm::open(algo, cng::ChainingMode::Ecb)?;
        let key = algo.new_key(key)?;
        // TODO: Check iv len
        Ok(Ctr { key, ctr: Some(iv.into()) })
    }

    pub fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let mut ctr = self.ctr.take().unwrap();
        Mode::encrypt(self, &mut ctr, dst, src)?;
        self.ctr = Some(ctr);
        Ok(())
    }

    pub fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let mut ctr = self.ctr.take().unwrap();
        Mode::decrypt(self, &mut ctr, dst, src)?;
        self.ctr = Some(ctr);
        Ok(())
    }
}

impl Mode for Ctr {
    fn block_size(&self) -> usize {
        self.key.block_size().expect("CNG not to fail internally")
    }

    fn encrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) -> Result<()> {
        let block = self.block_size();

        // Ciphertext_i <- BlockCipher(Counter_i) ⊕ Plaintext_i
        for (dst, src) in dst.chunks_mut(block).zip(src.chunks(block)) {
            let res = cng::SymmetricAlgorithmKey::encrypt(&self.key, None, iv, None)?;
            wrapping_increment_be(iv.as_mut());

            for (dst, (res, src)) in dst.iter_mut().zip(res.as_slice().iter().zip(src.iter())) {
                *dst = res ^ src;
            }
        }

        Ok(())
    }

    fn decrypt(&mut self, iv: &mut [u8], dst: &mut [u8], src: &[u8]) -> Result<()> {
        let block = self.block_size();

        // Plaintext_i <- BlockCipher(Counter_i) ⊕ Ciphertext_i
        for (dst, src) in dst.chunks_mut(block).zip(src.chunks(block)) {
            let res = cng::SymmetricAlgorithmKey::encrypt(&self.key, None, iv, None)?;
            wrapping_increment_be(iv.as_mut());

            for (dst, (res, src)) in dst.iter_mut().zip(res.as_slice().iter().zip(src.iter())) {
                *dst = res ^ src;
            }
        }

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
    /// Returns whether this algorithm is supported by the crypto backend.
    ///
    /// All backends support all the AES variants.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    ///
    /// assert!(SymmetricAlgorithm::AES256.is_supported());
    /// assert!(SymmetricAlgorithm::TripleDES.is_supported());
    ///
    /// assert!(!SymmetricAlgorithm::IDEA.is_supported());
    /// assert!(!SymmetricAlgorithm::Unencrypted.is_supported());
    /// assert!(!SymmetricAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use self::SymmetricAlgorithm::*;
        match self {
            AES128 | AES192 | AES256 | TripleDES => true,
            _ => false,
        }
    }

    /// Length of a key for this algorithm in bytes.  Fails if the crypto
    /// backend does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        Ok(match self {
            SymmetricAlgorithm::TripleDES => 24,
            SymmetricAlgorithm::AES128 => 16,
            SymmetricAlgorithm::AES192 => 24,
            SymmetricAlgorithm::AES256 => 32,
            _ => Err(UnsupportedAlgorithm(self))?,
        })
    }

    /// Length of a block for this algorithm in bytes.  Fails if the crypto
    /// backend does not support this algorithm.
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

fn wrapping_increment_be(value: &mut [u8]) -> &mut [u8] {
    for val in value.iter_mut().rev() {
        *val = val.wrapping_add(1);
        // Stop carryover
        if *val != 0x00 {
            break;
        }
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Borrow;

    trait HexSlice: Borrow<str> {
        fn as_hex(&self) -> Vec<u8> {
            let res: Vec<u8> = self.borrow().as_bytes().rchunks(2)
                .map(|slice| std::str::from_utf8(slice).unwrap())
                .map(|chr| u8::from_str_radix(chr, 16).unwrap())
                .rev()
                .collect();
            res
        }
    }
    impl<'a> HexSlice for &'a str {}

    #[test]
    fn hex_slice() {
        assert_eq!("0a".as_hex(), &[0x0A]);
        assert_eq!("a".as_hex(), &[0x0A]);
        assert_eq!("FE0a".as_hex(), &[0xFE, 0x0A]);
        assert_eq!("E0a".as_hex(), &[0x0E, 0x0A]);
    }

    #[test]
    fn wrapping_increment_be() {
        assert_eq!(super::wrapping_increment_be(&mut [0x00]), [0x01]);
        assert_eq!(super::wrapping_increment_be(&mut [0xFF, 0xFF]), [0x00, 0x00]);
        assert_eq!(super::wrapping_increment_be(&mut [0xFD, 0xFF]), [0xFE, 0x00]);

        let input = &mut "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".as_hex();
        let expected =  &"f0f1f2f3f4f5f6f7f8f9fafbfcfdff00".as_hex();

        assert_eq!(super::wrapping_increment_be(input).as_ref(), expected.as_slice());
    }

    #[test]
    fn ctr_aes_128() {
        // NIST SP800-38a test vectors
        // F.5.1       CTR-AES128.Encrypt
        let key = &"2b7e151628aed2a6abf7158809cf4f3c".as_hex();
        assert_eq!(key.len(), 16);
        let mut ctr = Ctr::with_cipher_and_iv(
            cng::SymmetricAlgorithmId::Aes,
            key,
            &"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".as_hex(),
        ).unwrap();

        let plain = &"6bc1bee22e409f96e93d7e117393172a".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.encrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"874d6191b620e3261bef6864990db6ce".as_hex());

        let plain = &"ae2d8a571e03ac9c9eb76fac45af8e51".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.encrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"9806f66b7970fdff8617187bb9fffdff".as_hex());

        let plain = &"30c81c46a35ce411e5fbc1191a0a52ef".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.encrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"5ae4df3edbd5d35e5b4f09020db03eab".as_hex());

        let plain = &"f69f2445df4f9b17ad2b417be66c3710".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.encrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"1e031dda2fbe03d1792170a0f3009cee".as_hex());

        // F.5.2       CTR-AES128.Decrypt
        let key = &"2b7e151628aed2a6abf7158809cf4f3c".as_hex();
        assert_eq!(key.len(), 16);
        let mut ctr = Ctr::with_cipher_and_iv(
            cng::SymmetricAlgorithmId::Aes,
            key,
            &"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".as_hex(),
        ).unwrap();

        let plain = &"874d6191b620e3261bef6864990db6ce".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.decrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"6bc1bee22e409f96e93d7e117393172a".as_hex());

        let plain = &"9806f66b7970fdff8617187bb9fffdff".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.decrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"ae2d8a571e03ac9c9eb76fac45af8e51".as_hex());

        let plain = &"5ae4df3edbd5d35e5b4f09020db03eab".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.decrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"30c81c46a35ce411e5fbc1191a0a52ef".as_hex());

        let plain = &"1e031dda2fbe03d1792170a0f3009cee".as_hex();
        let mut cipher = vec![0u8; 16];
        ctr.decrypt(&mut cipher, plain).unwrap();
        assert_eq!(&cipher, &"f69f2445df4f9b17ad2b417be66c3710".as_hex());
    }
}
