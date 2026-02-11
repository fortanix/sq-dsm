//! AEAD interface.

use crate::{
    Result,
    crypto::{
	mem::Protected,
	aead::{CipherOp, Context},
	AEADAlgorithm,
        SymmetricAlgorithm,
    },
};

/// AEAD interface.
pub trait Aead {
    /// Returns whether the given AEAD algorithm is supported by this
    /// backed.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `algo`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_algo(algo: AEADAlgorithm) -> bool;

    /// Returns whether the given AEAD algorithm and symmetric
    /// algorithm combination is supported by this backed.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `algo`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_algo_with_symmetric(algo: AEADAlgorithm,
                                    symm: SymmetricAlgorithm) -> bool;

    /// Creates a low-level AEAD context.
    fn context(algo: AEADAlgorithm,
               sym_algo: SymmetricAlgorithm,
               key: &Protected,
               aad: &[u8],
               nonce: &[u8],
               op: CipherOp,
    ) -> Result<Box<dyn Context>>;
}
