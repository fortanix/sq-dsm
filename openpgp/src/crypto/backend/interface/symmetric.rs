//! Symmetric cryptography interface.

use std::borrow::Cow;

use crate::{
    Result,
    crypto::{
	mem::Protected,
	symmetric::{BlockCipherMode, Context},
	SymmetricAlgorithm,
    },
};

/// Symmetric cryptography interface.
pub trait Symmetric {
    /// Returns whether the given symmetric cryptography algorithm is
    /// supported by this backed.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `algo`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_algo(algo: SymmetricAlgorithm) -> bool;

    /// Returns an encryption context for the given algorithm and
    /// mode.
    fn encryptor(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		 key: &Protected, iv: Option<&[u8]>)
                 -> Result<Box<dyn Context>>
    {
        const ZERO: [u8; 16] = [0; 16];
        let block_size = algo.block_size()?;
        let iv = iv.map(Cow::from).unwrap_or_else(|| {
            if block_size <= ZERO.len() {
                Cow::Borrowed(&ZERO[..block_size])
            } else {
                Cow::Owned(vec![0; block_size])
            }
        });

	Self::encryptor_impl(algo, mode, key, iv)
    }

    /// Returns an encryption context for the given algorithm and
    /// mode.
    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>;

    /// Returns a decryption context for the given algorithm and mode.
    fn decryptor(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		 key: &Protected, iv: Option<&[u8]>)
                 -> Result<Box<dyn Context>>
    {
        const ZERO: [u8; 16] = [0; 16];
        let block_size = algo.block_size()?;
        let iv = iv.map(Cow::from).unwrap_or_else(|| {
            if block_size <= ZERO.len() {
                Cow::Borrowed(&ZERO[..block_size])
            } else {
                Cow::Owned(vec![0; block_size])
            }
        });

	Self::decryptor_impl(algo, mode, key, iv)
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>;
}
