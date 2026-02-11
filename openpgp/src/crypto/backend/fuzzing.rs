//! Implementation of Sequoia crypto API using a fuzzing-friendly null
//! backend.

#[allow(unused_variables)]
pub mod aead;
#[allow(unused_variables)]
pub mod asymmetric;
#[allow(unused_variables)]
pub mod ecdh;
#[allow(unused_variables)]
pub mod hash;
#[allow(unused_variables)]
pub mod kdf;
#[allow(unused_variables)]
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        "Fuzzing".to_string()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        buf.iter_mut().for_each(|b| *b = 4);
        Ok(())
    }
}
