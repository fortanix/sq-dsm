//! Common secret key related operations.

use std::time::SystemTime;

use crate::{
    Result,
    packet::key::{self, Key4, Key6, SecretParts},
    types::Curve,
};

impl<R> Key6<SecretParts, R>
    where R: key::KeyRole,
{
    /// Generates a new X25519 key.
    pub fn generate_x25519() -> Result<Self> {
        Key4::generate_x25519().map(Key6::from_common)
    }

    /// Generates a new X448 key.
    pub fn generate_x448() -> Result<Self> {
        Key4::generate_x448().map(Key6::from_common)
    }

    /// Generates a new Ed25519 key.
    pub fn generate_ed25519() -> Result<Self> {
        Key4::generate_ed25519().map(Key6::from_common)
    }

    /// Generates a new Ed448 key.
    pub fn generate_ed448() -> Result<Self> {
        Key4::generate_ed448().map(Key6::from_common)
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        Key4::generate_rsa(bits)
            .map(Key6::from_common)
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have its creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        Key4::import_secret_rsa(d, p, q, ctime)
            .map(Key6::from_common)
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        match (for_signing, curve) {
            (true, Curve::Ed25519) => Self::generate_ed25519(),
            (false, Curve::Cv25519) => Self::generate_x25519(),
            (s, c) => Key4::generate_ecc(s, c).map(Key6::from_common),
        }
    }
}
