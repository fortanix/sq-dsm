//! Implementation of Sequoia crypto API using the Botan cryptographic library.

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        botan::Version::current()
            .map(|v| format!("Botan {}", v.string))
            .unwrap_or_else(|_| "Botan".to_string())
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        let mut rng = botan::RandomNumberGenerator::new_system()?;
        rng.fill(buf)?;
        Ok(())
    }
}
