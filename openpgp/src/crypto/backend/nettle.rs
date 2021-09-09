//! Implementation of Sequoia crypto API using the Nettle cryptographic library.

use crate::types::*;

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

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA
                => true,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP512 | Unknown(_)
                => false,
        }
    }
}

impl AEADAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX
                => true,
            OCB | Private(_) | Unknown(_)
                => false,
        }
    }
}
