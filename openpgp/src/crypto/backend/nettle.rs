//! Implementation of Sequoia crypto API using the Nettle cryptographic library.

use nettle::random::{Random, Yarrow};

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        let (major, minor) = nettle::version();
        format!(
            "Nettle {}.{} (Cv448: {:?}, OCB: {:?})",
            major, minor,
            nettle::curve448::IS_SUPPORTED,
            nettle::aead::OCB_IS_SUPPORTED,
        )
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        Yarrow::default().random(buf);
        Ok(())
    }
}
