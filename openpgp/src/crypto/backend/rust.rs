//! Implementation of Sequoia crypto API using pure Rust cryptographic
//! libraries.

use cipher::generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};

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
        "RustCrypto".to_string()
    }

    fn random(buf: &mut [u8]) -> Result<()> {
        use rand_core::OsRng;
        use rand_core::RngCore;
        OsRng.fill_bytes(buf);
        Ok(())
    }
}

trait GenericArrayExt<T, N: ArrayLength<T>> {
    const LEN: usize;

    /// Like [`GenericArray::from_slice`], but fallible.
    fn try_from_slice(slice: &[T]) -> Result<&GenericArray<T, N>> {
        if slice.len() == Self::LEN {
            Ok(GenericArray::from_slice(slice))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid slice length, want {}, got {}",
                        Self::LEN, slice.len())).into())
        }
    }

    /// Like [`GenericArray::clone_from_slice`], but fallible.
    fn try_clone_from_slice(slice: &[T]) -> Result<GenericArray<T, N>>
        where T: Clone
    {
        if slice.len() == Self::LEN {
            Ok(GenericArray::clone_from_slice(slice))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid slice length, want {}, got {}",
                        Self::LEN, slice.len())).into())
        }
    }
}

impl<T, N: ArrayLength<T>> GenericArrayExt<T, N> for GenericArray<T, N> {
    const LEN: usize = N::USIZE;
}
