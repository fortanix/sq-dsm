//! Key-Derivation-Functions.

use crate::{
    Result,
    crypto::SessionKey,
};

/// Key-Derivation-Functions.
pub trait Kdf {
    /// HKDF instantiated with SHA256.
    ///
    /// Used to derive message keys from session keys, and key
    /// encapsulating keys from S2K mechanisms.  In both cases, using
    /// a KDF that includes algorithm information in the given `info`
    /// provides key space separation between cipher algorithms and
    /// modes.
    ///
    /// `salt`, if given, SHOULD be 32 bytes of salt matching the
    /// digest size of the hash function.  If it is not given, 32
    /// zeros are used instead.
    ///
    /// `okm` must not be larger than 255 * 32 (the size of the hash
    /// digest).
    fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey) -> Result<()>;

    /// HKDF instantiated with SHA512.
    ///
    /// Used to derive message keys from session keys, and key
    /// encapsulating keys from S2K mechanisms.  In both cases, using
    /// a KDF that includes algorithm information in the given `info`
    /// provides key space separation between cipher algorithms and
    /// modes.
    ///
    /// `salt`, if given, SHOULD be 64 bytes of salt matching the
    /// digest size of the hash function.  If it is not given, 64
    /// zeros are used instead.
    ///
    /// `okm` must not be larger than 255 * 64 (the size of the hash
    /// digest).
    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey) -> Result<()>;
}
