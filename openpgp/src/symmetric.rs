use Result;
use Error;
use SymmetricAlgo;

use nettle::Cipher;
use nettle::cipher::{Aes128, Aes192, Aes256, Twofish};
pub fn symmetric_key_size(algo: u8) -> Result<usize> {
    match SymmetricAlgo::from_numeric(algo)? {
        // SymmetricAlgo::IDEA =>
        // SymmetricAlgo::TripleDES =>
        // SymmetricAlgo::CAST5 =>
        // SymmetricAlgo::Blowfish =>
        SymmetricAlgo::AES128 => Ok(Aes128::KEY_SIZE),
        SymmetricAlgo::AES192 => Ok(Aes192::KEY_SIZE),
        SymmetricAlgo::AES256 => Ok(Aes256::KEY_SIZE),
        SymmetricAlgo::Twofish => Ok(Twofish::KEY_SIZE),
        _ => Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    }
}
