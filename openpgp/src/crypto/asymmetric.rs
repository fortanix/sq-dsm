//! Asymmetric crypto operations.

use packet::Key;
use crypto::mpis;
use constants::HashAlgorithm;

use Result;

/// Creates a signature.
pub trait Signer {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key;

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpis::Signature>;
}
