//! Implementation of crypto primitives using the Windows CNG (Cryptographic API: Next Generation).

use win_crypto_ng::random::RandomNumberGenerator;

pub mod hash;
pub mod symmetric;

/// Fills the given buffer with random data.
pub fn random<B: AsMut<[u8]>>(mut buf: B) {
    RandomNumberGenerator::system_preferred()
        .gen_random(buf.as_mut())
        .expect("system-preferred RNG not to fail")
}
