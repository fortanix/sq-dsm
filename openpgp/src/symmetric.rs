use SymmetricAlgo;

use nettle::Cipher;
use nettle::cipher::{Aes128, Aes192, Aes256, Twofish};

pub fn symmetric_key_size(algo: SymmetricAlgo) -> Option<usize> {
    match algo {
        SymmetricAlgo::IDEA => None,
        SymmetricAlgo::TripleDES => None,
        SymmetricAlgo::CAST5 => None,
        SymmetricAlgo::Blowfish => None,
        SymmetricAlgo::AES128 => Some(Aes128::KEY_SIZE),
        SymmetricAlgo::AES192 => Some(Aes192::KEY_SIZE),
        SymmetricAlgo::AES256 => Some(Aes256::KEY_SIZE),
        SymmetricAlgo::Twofish => Some(Twofish::KEY_SIZE),
        _ => None,
    }
}
