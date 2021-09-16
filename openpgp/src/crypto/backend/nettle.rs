//! Implementation of Sequoia crypto API using the Nettle cryptographic library.

use nettle::random::{Random, Yarrow};

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Fills the given buffer with random data.
///
/// Fills the given buffer with random data produced by a
/// cryptographically secure pseudorandom number generator (CSPRNG).
/// The output may be used as session keys or to derive long-term
/// cryptographic keys from.  However, to create session keys,
/// consider using [`SessionKey::new`].
///
///   [`SessionKey::new`]: crate::crypto::SessionKey::new()
pub fn random<B: AsMut<[u8]>>(mut buf: B) {
    Yarrow::default().random(buf.as_mut());
}
