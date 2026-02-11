//! Implementation of crypto primitives using the Windows CNG (Cryptographic API: Next Generation).

use win_crypto_ng::random::RandomNumberGenerator;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        // XXX: can we include features and the version?
        "Windows CNG".to_string()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        RandomNumberGenerator::system_preferred()
            .gen_random(buf)?;
        Ok(())
    }
}
