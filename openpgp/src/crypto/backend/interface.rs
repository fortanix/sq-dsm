//! The crypto-backend abstraction.

use crate::Result;

mod aead;
pub use aead::Aead;
mod asymmetric;
pub use asymmetric::Asymmetric;
mod kdf;
pub use kdf::Kdf;
mod symmetric;
pub use symmetric::Symmetric;

/// Abstracts over the cryptographic backends.
pub trait Backend: Aead + Asymmetric + Kdf + Symmetric {
    /// Returns a short, human-readable description of the backend.
    ///
    /// This starts with the name of the backend, possibly a version,
    /// and any optional features that are available.  This is meant
    /// for inclusion in version strings to improve bug reports.
    fn backend() -> String;

    /// Fills the given buffer with random data.
    ///
    /// Fills the given buffer with random data produced by a
    /// cryptographically secure pseudorandom number generator
    /// (CSPRNG).  The output may be used as session keys or to derive
    /// long-term cryptographic keys from.
    fn random(buf: &mut [u8]) -> Result<()>;
}
