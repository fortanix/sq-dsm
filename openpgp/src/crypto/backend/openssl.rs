//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        openssl::version::version().into()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        openssl::rand::rand_bytes(buf)?;
        Ok(())
    }
}
