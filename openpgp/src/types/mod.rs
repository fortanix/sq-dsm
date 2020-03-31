//! Primitive types.
//!
//! This module provides types used in OpenPGP, like enumerations
//! describing algorithms.

use std::fmt;
use std::str::FromStr;
use std::result;

use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::Result;

mod features;
pub use self::features::Features;
mod key_flags;
pub use self::key_flags::KeyFlags;
mod revocation_key;
pub use revocation_key::RevocationKey;
mod server_preferences;
pub use self::server_preferences::KeyServerPreferences;
mod timestamp;
pub use timestamp::{Timestamp, Duration};
pub(crate) use timestamp::normalize_systemtime;

/// Removes padding bytes from bitfields.
///
/// Returns the size of the original bitfield, i.e. the number of
/// bytes the output has to be padded to when serialized.
pub(crate) fn bitfield_remove_padding(b: &mut Vec<u8>) -> usize {
    let pad_to = b.len();
    while b.last() == Some(&0) {
        b.pop();
    }
    pad_to
}

/// The OpenPGP public key algorithms as defined in [Section 9.1 of
/// RFC 4880], and [Section 5 of RFC 6637].
///
///   [Section 9.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.1
///   [Section 5 of RFC 6637]: https://tools.ietf.org/html/rfc6637
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt or Sign)
    RSAEncryptSign,
    /// RSA Encrypt-Only
    #[deprecated(since = "rfc4880",
                 note = "Use `PublicKeyAlgorithm::RSAEncryptSign`.")]
    RSAEncrypt,
    /// RSA Sign-Only
    #[deprecated(since = "rfc4880",
                 note = "Use `PublicKeyAlgorithm::RSAEncryptSign`.")]
    RSASign,
    /// ElGamal (Encrypt-Only)
    ElGamalEncrypt,
    /// DSA (Digital Signature Algorithm)
    DSA,
    /// Elliptic curve DH
    ECDH,
    /// Elliptic curve DSA
    ECDSA,
    /// ElGamal (Encrypt or Sign)
    #[deprecated(since = "rfc4880",
                 note = "If you really must, use \
                         `PublicKeyAlgorithm::ElGamalEncrypt`.")]
    ElGamalEncryptSign,
    /// "Twisted" Edwards curve DSA
    EdDSA,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl PublicKeyAlgorithm {
    /// Returns true if the algorithm can sign data.
    pub fn for_signing(&self) -> bool {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSASign | DSA | ECDSA | ElGamalEncryptSign
                | EdDSA => true,
            __Nonexhaustive => unreachable!(),
            _ => false,
        }
    }

    /// Returns true if the algorithm can encrypt data.
    pub fn can_encrypt(&self) -> bool {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | ElGamalEncrypt | ECDH
                | ElGamalEncryptSign => true,
            __Nonexhaustive => unreachable!(),
            _ => false,
        }
    }

    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA
                => true,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(u: u8) -> Self {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match u {
            1 => RSAEncryptSign,
            2 => RSAEncrypt,
            3 => RSASign,
            16 => ElGamalEncrypt,
            17 => DSA,
            18 => ECDH,
            19 => ECDSA,
            20 => ElGamalEncryptSign,
            22 => EdDSA,
            100..=110 => Private(u),
            u => Unknown(u),
        }
    }
}

impl From<PublicKeyAlgorithm> for u8 {
    fn from(p: PublicKeyAlgorithm) -> u8 {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match p {
            RSAEncryptSign => 1,
            RSAEncrypt => 2,
            RSASign => 3,
            ElGamalEncrypt => 16,
            DSA => 17,
            ECDH => 18,
            ECDSA => 19,
            ElGamalEncryptSign => 20,
            EdDSA => 22,
            Private(u) => u,
            Unknown(u) => u,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for PublicKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match *self {
            RSAEncryptSign => f.write_str("RSA (Encrypt or Sign)"),
            RSAEncrypt => f.write_str("RSA Encrypt-Only"),
            RSASign => f.write_str("RSA Sign-Only"),
            ElGamalEncrypt => f.write_str("ElGamal (Encrypt-Only)"),
            DSA => f.write_str("DSA (Digital Signature Algorithm)"),
            ECDSA => f.write_str("ECDSA public key algorithm"),
            ElGamalEncryptSign => f.write_str("ElGamal (Encrypt or Sign)"),
            ECDH => f.write_str("ECDH public key algorithm"),
            EdDSA => f.write_str("EdDSA Edwards-curve Digital Signature Algorithm"),
            Private(u) =>
                f.write_fmt(format_args!("Private/Experimental public key algorithm {}", u)),
            Unknown(u) =>
                f.write_fmt(format_args!("Unknown public key algorithm {}", u)),
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for PublicKeyAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

impl PublicKeyAlgorithm {
    pub(crate) fn arbitrary_for_signing<G: Gen>(g: &mut G) -> Self {
        use rand::Rng;
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        let a = match g.gen_range(0, 5) {
            0 => RSAEncryptSign,
            1 => RSASign,
            2 => DSA,
            3 => ECDSA,
            4 => EdDSA,
            _ => unreachable!(),
        };
        assert!(a.for_signing());
        a
    }
}

/// Elliptic curves used in OpenPGP.
///
/// `PublicKeyAlgorithm` does not differentiate between elliptic
/// curves.  Instead, the curve is specified using an OID prepended to
/// the key material.  We provide this type to be able to match on the
/// curves.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Curve {
    /// NIST curve P-256.
    NistP256,
    /// NIST curve P-384.
    NistP384,
    /// NIST curve P-521.
    NistP521,
    /// brainpoolP256r1.
    BrainpoolP256,
    /// brainpoolP512r1.
    BrainpoolP512,
    /// D.J. Bernstein's "Twisted" Edwards curve Ed25519.
    Ed25519,
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519.
    Cv25519,
    /// Unknown curve.
    Unknown(Box<[u8]>),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Curve {
    /// Returns the length of public keys over this curve in bits.
    ///
    /// For the Kobliz curves this is the size of the underlying
    /// finite field.  For X25519 it is 256.
    ///
    /// Note: This information is useless and should not be used to
    /// gauge the security of a particular curve. This function exists
    /// only because some legacy PGP application like HKP need it.
    ///
    /// Returns `None` for unknown curves.
    pub fn bits(&self) -> Option<usize> {
        use self::Curve::*;

        match self {
            NistP256 => Some(256),
            NistP384 => Some(384),
            NistP521 => Some(521),
            BrainpoolP256 => Some(256),
            BrainpoolP512 => Some(512),
            Ed25519 => Some(256),
            Cv25519 => Some(256),
            Unknown(_) => None,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Curve::*;
        match *self {
            NistP256 => f.write_str("NIST curve P-256"),
            NistP384 => f.write_str("NIST curve P-384"),
            NistP521 => f.write_str("NIST curve P-521"),
            BrainpoolP256 => f.write_str("brainpoolP256r1"),
            BrainpoolP512 => f.write_str("brainpoolP512r1"),
            Ed25519
                => f.write_str("D.J. Bernstein's \"Twisted\" Edwards curve Ed25519"),
            Cv25519
                => f.write_str("Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519"),
            Unknown(ref oid)
             => write!(f, "Unknown curve (OID: {:?})", oid),
            __Nonexhaustive => unreachable!(),
        }
    }
}

const NIST_P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const NIST_P384_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const NIST_P521_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const BRAINPOOL_P256_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const BRAINPOOL_P512_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
const ED25519_OID: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const CV25519_OID: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

impl Curve {
    /// Parses the given OID.
    pub fn from_oid(oid: &[u8]) -> Curve {
        // Match on OIDs, see section 11 of RFC6637.
        match oid {
            NIST_P256_OID => Curve::NistP256,
            NIST_P384_OID => Curve::NistP384,
            NIST_P521_OID => Curve::NistP521,
            BRAINPOOL_P256_OID => Curve::BrainpoolP256,
            BRAINPOOL_P512_OID => Curve::BrainpoolP512,
            ED25519_OID => Curve::Ed25519,
            CV25519_OID => Curve::Cv25519,
            oid => Curve::Unknown(Vec::from(oid).into_boxed_slice()),
        }
    }

    /// Returns this curve's OID.
    pub fn oid(&self) -> &[u8] {
        match self {
            &Curve::NistP256 => NIST_P256_OID,
            &Curve::NistP384 => NIST_P384_OID,
            &Curve::NistP521 => NIST_P521_OID,
            &Curve::BrainpoolP256 => BRAINPOOL_P256_OID,
            &Curve::BrainpoolP512 => BRAINPOOL_P512_OID,
            &Curve::Ed25519 => ED25519_OID,
            &Curve::Cv25519 => CV25519_OID,
            &Curve::Unknown(ref oid) => oid,
            Curve::__Nonexhaustive => unreachable!(),
        }
    }

    /// Returns the length of a coordinate in bits.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedEllipticCurve` if the curve is not
    /// supported.
    pub fn len(&self) -> Result<usize> {
        match self {
            &Curve::NistP256 => Ok(256),
            &Curve::NistP384 => Ok(384),
            &Curve::NistP521 => Ok(521),
            &Curve::BrainpoolP256 => Ok(256),
            &Curve::BrainpoolP512 => Ok(512),
            &Curve::Ed25519 => Ok(256),
            &Curve::Cv25519 => Ok(256),
            &Curve::Unknown(_) =>
                Err(Error::UnsupportedEllipticCurve(self.clone())
                    .into()),
            Curve::__Nonexhaustive => unreachable!(),
        }
    }

    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP512 | Unknown(_)
                => false,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for Curve {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match u8::arbitrary(g) % 8 {
            0 => Curve::NistP256,
            1 => Curve::NistP384,
            2 => Curve::NistP521,
            3 => Curve::BrainpoolP256,
            4 => Curve::BrainpoolP512,
            5 => Curve::Ed25519,
            6 => Curve::Cv25519,
            7 => Curve::Unknown(Vec::<u8>::arbitrary(g).into_boxed_slice()),
            _ => unreachable!(),
        }
    }
}

/// The symmetric-key algorithms as defined in [Section 9.2 of RFC 4880].
///
///   [Section 9.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.2
///
/// The values can be converted into and from their corresponding values of the serialized format.
///
/// Use [`SymmetricAlgorithm::from`] to translate a numeric value to a
/// symbolic one.
///
///   [`SymmetricAlgorithm::from`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum SymmetricAlgorithm {
    /// Null encryption.
    Unencrypted,
    /// IDEA block cipher.
    IDEA,
    /// 3-DES in EDE configuration.
    TripleDES,
    /// CAST5/CAST128 block cipher.
    CAST5,
    /// Schneier et.al. Blowfish block cipher.
    Blowfish,
    /// 10-round AES.
    AES128,
    /// 12-round AES.
    AES192,
    /// 14-round AES.
    AES256,
    /// Twofish block cipher.
    Twofish,
    /// 18 rounds of NESSIEs Camellia.
    Camellia128,
    /// 24 rounds of NESSIEs Camellia w/192 bit keys.
    Camellia192,
    /// 24 rounds of NESSIEs Camellia w/256 bit keys.
    Camellia256,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Default for SymmetricAlgorithm {
    fn default() -> Self {
        SymmetricAlgorithm::AES256
    }
}

impl SymmetricAlgorithm {
    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        use self::SymmetricAlgorithm::*;
        match &self {
            TripleDES | CAST5 | Blowfish | AES128 | AES192 | AES256 | Twofish
                | Camellia128 | Camellia192 | Camellia256
                => true,
            Unencrypted | IDEA | Private(_) | Unknown(_)
                => false,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl From<u8> for SymmetricAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            0 => SymmetricAlgorithm::Unencrypted,
            1 => SymmetricAlgorithm::IDEA,
            2 => SymmetricAlgorithm::TripleDES,
            3 => SymmetricAlgorithm::CAST5,
            4 => SymmetricAlgorithm::Blowfish,
            7 => SymmetricAlgorithm::AES128,
            8 => SymmetricAlgorithm::AES192,
            9 => SymmetricAlgorithm::AES256,
            10 => SymmetricAlgorithm::Twofish,
            11 => SymmetricAlgorithm::Camellia128,
            12 => SymmetricAlgorithm::Camellia192,
            13 => SymmetricAlgorithm::Camellia256,
            100..=110 => SymmetricAlgorithm::Private(u),
            u => SymmetricAlgorithm::Unknown(u),
        }
    }
}

impl From<SymmetricAlgorithm> for u8 {
    fn from(s: SymmetricAlgorithm) -> u8 {
        match s {
            SymmetricAlgorithm::Unencrypted => 0,
            SymmetricAlgorithm::IDEA => 1,
            SymmetricAlgorithm::TripleDES => 2,
            SymmetricAlgorithm::CAST5 => 3,
            SymmetricAlgorithm::Blowfish => 4,
            SymmetricAlgorithm::AES128 => 7,
            SymmetricAlgorithm::AES192 => 8,
            SymmetricAlgorithm::AES256 => 9,
            SymmetricAlgorithm::Twofish => 10,
            SymmetricAlgorithm::Camellia128 => 11,
            SymmetricAlgorithm::Camellia192 => 12,
            SymmetricAlgorithm::Camellia256 => 13,
            SymmetricAlgorithm::Private(u) => u,
            SymmetricAlgorithm::Unknown(u) => u,
            SymmetricAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymmetricAlgorithm::Unencrypted =>
                f.write_str("Unencrypted"),
            SymmetricAlgorithm::IDEA =>
                f.write_str("IDEA"),
            SymmetricAlgorithm::TripleDES =>
                f.write_str("TripleDES (EDE-DES, 168 bit key derived from 192))"),
            SymmetricAlgorithm::CAST5 =>
                f.write_str("CAST5 (128 bit key, 16 rounds)"),
            SymmetricAlgorithm::Blowfish =>
                f.write_str("Blowfish (128 bit key, 16 rounds)"),
            SymmetricAlgorithm::AES128 =>
                f.write_str("AES with 128-bit key"),
            SymmetricAlgorithm::AES192 =>
                f.write_str("AES with 192-bit key"),
            SymmetricAlgorithm::AES256 =>
                f.write_str("AES with 256-bit key"),
            SymmetricAlgorithm::Twofish =>
                f.write_str("Twofish with 256-bit key"),
            SymmetricAlgorithm::Camellia128 =>
                f.write_str("Camellia with 128-bit key"),
            SymmetricAlgorithm::Camellia192 =>
                f.write_str("Camellia with 192-bit key"),
            SymmetricAlgorithm::Camellia256 =>
                f.write_str("Camellia with 256-bit key"),
            SymmetricAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental symmetric key algorithm {}", u)),
            SymmetricAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown symmetric key algorithm {}", u)),
            SymmetricAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for SymmetricAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The AEAD algorithms as defined in [Section 9.6 of RFC 4880bis].
///
///   [Section 9.6 of RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-9.6
///
/// The values can be converted into and from their corresponding values of the serialized format.
///
/// Use [`AEADAlgorithm::from`] to translate a numeric value to a
/// symbolic one.
///
///   [`AEADAlgorithm::from`]: https://doc.rust-lang.org/std/convert/trait.From.html
///
/// This feature is [experimental](../index.html#experimental-features).
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum AEADAlgorithm {
    /// EAX mode.
    EAX,
    /// OCB mode.
    OCB,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl AEADAlgorithm {
    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX
                => true,
            OCB | Private(_) | Unknown(_)
                => false,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl From<u8> for AEADAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            1 => AEADAlgorithm::EAX,
            2 => AEADAlgorithm::OCB,
            100..=110 => AEADAlgorithm::Private(u),
            u => AEADAlgorithm::Unknown(u),
        }
    }
}

impl From<AEADAlgorithm> for u8 {
    fn from(s: AEADAlgorithm) -> u8 {
        match s {
            AEADAlgorithm::EAX => 1,
            AEADAlgorithm::OCB => 2,
            AEADAlgorithm::Private(u) => u,
            AEADAlgorithm::Unknown(u) => u,
            AEADAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for AEADAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AEADAlgorithm::EAX =>
                f.write_str("EAX mode"),
            AEADAlgorithm::OCB =>
                f.write_str("OCB mode"),
            AEADAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental AEAD algorithm {}", u)),
            AEADAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown AEAD algorithm {}", u)),
            AEADAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for AEADAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The OpenPGP compression algorithms as defined in [Section 9.3 of RFC 4880].
///
///   [Section 9.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.3
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum CompressionAlgorithm {
    /// Null compression.
    Uncompressed,
    /// DEFLATE Compressed Data.
    ///
    /// See [RFC 1951] for details.  [Section 9.3 of RFC 4880]
    /// recommends that this algorithm should be implemented.
    ///
    /// [RFC 1951]: https://tools.ietf.org/html/rfc1951
    /// [Section 9.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.3
    Zip,
    /// ZLIB Compressed Data.
    ///
    /// See [RFC 1950] for details.
    ///
    /// [RFC 1950]: https://tools.ietf.org/html/rfc1950
    Zlib,
    /// bzip2
    BZip2,
    /// Private compression algorithm identifier.
    Private(u8),
    /// Unknown compression algorithm identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        use self::CompressionAlgorithm::*;
        #[cfg(feature = "compression-deflate")]
        { Zip }
        #[cfg(all(feature = "compression-bzip2",
                  not(feature = "compression-deflate")))]
        { BZip2 }
        #[cfg(all(not(feature = "compression-bzip2"),
                  not(feature = "compression-deflate")))]
        { Uncompressed }
    }
}

impl CompressionAlgorithm {
    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        use self::CompressionAlgorithm::*;
        match &self {
            Uncompressed => true,
            #[cfg(feature = "compression-deflate")]
            Zip | Zlib => true,
            #[cfg(feature = "compression-bzip2")]
            BZip2 => true,
            __Nonexhaustive => unreachable!(),
            _ => false,
        }
    }
}

impl From<u8> for CompressionAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            0 => CompressionAlgorithm::Uncompressed,
            1 => CompressionAlgorithm::Zip,
            2 => CompressionAlgorithm::Zlib,
            3 => CompressionAlgorithm::BZip2,
            100..=110 => CompressionAlgorithm::Private(u),
            u => CompressionAlgorithm::Unknown(u),
        }
    }
}

impl From<CompressionAlgorithm> for u8 {
    fn from(c: CompressionAlgorithm) -> u8 {
        match c {
            CompressionAlgorithm::Uncompressed => 0,
            CompressionAlgorithm::Zip => 1,
            CompressionAlgorithm::Zlib => 2,
            CompressionAlgorithm::BZip2 => 3,
            CompressionAlgorithm::Private(u) => u,
            CompressionAlgorithm::Unknown(u) => u,
            CompressionAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CompressionAlgorithm::Uncompressed => f.write_str("Uncompressed"),
            CompressionAlgorithm::Zip => f.write_str("ZIP"),
            CompressionAlgorithm::Zlib => f.write_str("ZLIB"),
            CompressionAlgorithm::BZip2 => f.write_str("BZip2"),
            CompressionAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental compression algorithm {}", u)),
            CompressionAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown comppression algorithm {}", u)),
            CompressionAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for CompressionAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The OpenPGP hash algorithms as defined in [Section 9.4 of RFC 4880].
///
///   [Section 9.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.4
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum HashAlgorithm {
    /// Rivest et.al. message digest 5.
    MD5,
    /// NIST Secure Hash Algorithm (deprecated)
    SHA1,
    /// RIPEMD-160
    RipeMD,
    /// 256-bit version of SHA2
    SHA256,
    /// 384-bit version of SHA2
    SHA384,
    /// 512-bit version of SHA2
    SHA512,
    /// 224-bit version of SHA2
    SHA224,
    /// Private hash algorithm identifier.
    Private(u8),
    /// Unknown hash algorithm identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        // SHA512 is almost twice as fast as SHA256 on 64-bit
        // architectures because it operates on 64-bit words.
        HashAlgorithm::SHA512
    }
}

impl From<u8> for HashAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            1 => HashAlgorithm::MD5,
            2 => HashAlgorithm::SHA1,
            3 => HashAlgorithm::RipeMD,
            8 => HashAlgorithm::SHA256,
            9 => HashAlgorithm::SHA384,
            10 => HashAlgorithm::SHA512,
            11 => HashAlgorithm::SHA224,
            100..=110 => HashAlgorithm::Private(u),
            u => HashAlgorithm::Unknown(u),
        }
    }
}

impl From<HashAlgorithm> for u8 {
    fn from(h: HashAlgorithm) -> u8 {
        match h {
            HashAlgorithm::MD5 => 1,
            HashAlgorithm::SHA1 => 2,
            HashAlgorithm::RipeMD => 3,
            HashAlgorithm::SHA256 => 8,
            HashAlgorithm::SHA384 => 9,
            HashAlgorithm::SHA512 => 10,
            HashAlgorithm::SHA224 => 11,
            HashAlgorithm::Private(u) => u,
            HashAlgorithm::Unknown(u) => u,
            HashAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = ();

    fn from_str(s: &str) -> result::Result<Self, ()> {
        if s == "MD5" {
            Ok(HashAlgorithm::MD5)
        } else if s == "SHA1" {
            Ok(HashAlgorithm::SHA1)
        } else if s == "RipeMD160" {
            Ok(HashAlgorithm::RipeMD)
        } else if s == "SHA256" {
            Ok(HashAlgorithm::SHA256)
        } else if s == "SHA384" {
            Ok(HashAlgorithm::SHA384)
        } else if s == "SHA512" {
            Ok(HashAlgorithm::SHA512)
        } else if s == "SHA224" {
            Ok(HashAlgorithm::SHA224)
        } else {
            Err(())
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgorithm::MD5 => f.write_str("MD5"),
            HashAlgorithm::SHA1 => f.write_str("SHA1"),
            HashAlgorithm::RipeMD => f.write_str("RipeMD160"),
            HashAlgorithm::SHA256 => f.write_str("SHA256"),
            HashAlgorithm::SHA384 => f.write_str("SHA384"),
            HashAlgorithm::SHA512 => f.write_str("SHA512"),
            HashAlgorithm::SHA224 => f.write_str("SHA224"),
            HashAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental hash algorithm {}", u)),
            HashAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown hash algorithm {}", u)),
            HashAlgorithm::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for HashAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// Signature type as defined in [Section 5.2.1 of RFC 4880].
///
///   [Section 5.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.1
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum SignatureType {
    /// Signature over a binary document.
    Binary,
    /// Signature over a canonical text document.
    Text,
    /// Standalone signature.
    Standalone,

    /// Generic certification of a User ID and Public-Key packet.
    GenericCertification,
    /// Persona certification of a User ID and Public-Key packet.
    PersonaCertification,
    /// Casual certification of a User ID and Public-Key packet.
    CasualCertification,
    /// Positive certification of a User ID and Public-Key packet.
    PositiveCertification,

    /// Subkey Binding Signature
    SubkeyBinding,
    /// Primary Key Binding Signature
    PrimaryKeyBinding,
    /// Signature directly on a key
    DirectKey,

    /// Key revocation signature
    KeyRevocation,
    /// Subkey revocation signature
    SubkeyRevocation,
    /// Certification revocation signature
    CertificationRevocation,

    /// Timestamp signature.
    Timestamp,
    /// Third-Party Confirmation signature.
    Confirmation,

    /// Catchall.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl From<u8> for SignatureType {
    fn from(u: u8) -> Self {
        match u {
            0x00 => SignatureType::Binary,
            0x01 => SignatureType::Text,
            0x02 => SignatureType::Standalone,
            0x10 => SignatureType::GenericCertification,
            0x11 => SignatureType::PersonaCertification,
            0x12 => SignatureType::CasualCertification,
            0x13 => SignatureType::PositiveCertification,
            0x18 => SignatureType::SubkeyBinding,
            0x19 => SignatureType::PrimaryKeyBinding,
            0x1f => SignatureType::DirectKey,
            0x20 => SignatureType::KeyRevocation,
            0x28 => SignatureType::SubkeyRevocation,
            0x30 => SignatureType::CertificationRevocation,
            0x40 => SignatureType::Timestamp,
            0x50 => SignatureType::Confirmation,
            _ => SignatureType::Unknown(u),
        }
    }
}

impl From<SignatureType> for u8 {
    fn from(t: SignatureType) -> Self {
        match t {
            SignatureType::Binary => 0x00,
            SignatureType::Text => 0x01,
            SignatureType::Standalone => 0x02,
            SignatureType::GenericCertification => 0x10,
            SignatureType::PersonaCertification => 0x11,
            SignatureType::CasualCertification => 0x12,
            SignatureType::PositiveCertification => 0x13,
            SignatureType::SubkeyBinding => 0x18,
            SignatureType::PrimaryKeyBinding => 0x19,
            SignatureType::DirectKey => 0x1f,
            SignatureType::KeyRevocation => 0x20,
            SignatureType::SubkeyRevocation => 0x28,
            SignatureType::CertificationRevocation => 0x30,
            SignatureType::Timestamp => 0x40,
            SignatureType::Confirmation => 0x50,
            SignatureType::Unknown(u) => u,
            SignatureType::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SignatureType::Binary =>
                f.write_str("Binary"),
            SignatureType::Text =>
                f.write_str("Text"),
            SignatureType::Standalone =>
                f.write_str("Standalone"),
            SignatureType::GenericCertification =>
                f.write_str("GenericCertification"),
            SignatureType::PersonaCertification =>
                f.write_str("PersonaCertification"),
            SignatureType::CasualCertification =>
                f.write_str("CasualCertification"),
            SignatureType::PositiveCertification =>
                f.write_str("PositiveCertification"),
            SignatureType::SubkeyBinding =>
                f.write_str("SubkeyBinding"),
            SignatureType::PrimaryKeyBinding =>
                f.write_str("PrimaryKeyBinding"),
            SignatureType::DirectKey =>
                f.write_str("DirectKey"),
            SignatureType::KeyRevocation =>
                f.write_str("KeyRevocation"),
            SignatureType::SubkeyRevocation =>
                f.write_str("SubkeyRevocation"),
            SignatureType::CertificationRevocation =>
                f.write_str("CertificationRevocation"),
            SignatureType::Timestamp =>
                f.write_str("Timestamp"),
            SignatureType::Confirmation =>
                f.write_str("Confirmation"),
            SignatureType::Unknown(u) =>
                f.write_fmt(format_args!("Unknown signature type 0x{:x}", u)),
            SignatureType::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for SignatureType {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// Describes the reason for a revocation.
///
/// See the description of revocation subpackets [Section 5.2.3.23 of RFC 4880].
///
///   [Section 5.2.3.23 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.23
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum ReasonForRevocation {
    /// No reason specified (key revocations or cert revocations)
    Unspecified,

    /// Key is superseded (key revocations)
    KeySuperseded,

    /// Key material has been compromised (key revocations)
    KeyCompromised,

    /// Key is retired and no longer used (key revocations)
    KeyRetired,

    /// User ID information is no longer valid (cert revocations)
    UIDRetired,

    /// Private reason identifier.
    Private(u8),

    /// Unknown reason identifier.
    Unknown(u8),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl From<u8> for ReasonForRevocation {
    fn from(u: u8) -> Self {
        use self::ReasonForRevocation::*;
        match u {
            0 => Unspecified,
            1 => KeySuperseded,
            2 => KeyCompromised,
            3 => KeyRetired,
            32 => UIDRetired,
            100..=110 => Private(u),
            u => Unknown(u),
        }
    }
}

impl From<ReasonForRevocation> for u8 {
    fn from(r: ReasonForRevocation) -> u8 {
        use self::ReasonForRevocation::*;
        match r {
            Unspecified => 0,
            KeySuperseded => 1,
            KeyCompromised => 2,
            KeyRetired => 3,
            UIDRetired => 32,
            Private(u) => u,
            Unknown(u) => u,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for ReasonForRevocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ReasonForRevocation::*;
        match *self {
            Unspecified =>
                f.write_str("No reason specified"),
            KeySuperseded =>
                f.write_str("Key is superseded"),
            KeyCompromised =>
                f.write_str("Key material has been compromised"),
            KeyRetired =>
                f.write_str("Key is retired and no longer used"),
            UIDRetired =>
                f.write_str("User ID information is no longer valid"),
            Private(u) =>
                f.write_fmt(format_args!(
                    "Private/Experimental revocation reason {}", u)),
            Unknown(u) =>
                f.write_fmt(format_args!(
                    "Unknown revocation reason {}", u)),
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for ReasonForRevocation {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// Describes whether a `ReasonForRevocation` should be consider hard
/// or soft.
///
/// A hard revocation is a revocation that indicates that the key was
/// somehow compromised, and the provence of *all* artifacts should be
/// called into question.
///
/// A soft revocation is a revocation that indicates that the key
/// should be considered invalid *after* the revocation signature's
/// creation time.  `KeySuperseded`, `KeyRetired`, and `UIDRetired`
/// are considered soft revocations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RevocationType {
    /// A hard revocation.
    ///
    /// Artifacts stemming from the revoked object should not be
    /// trusted.
    Hard,
    /// A soft revocation.
    ///
    /// Artifacts stemming from the revoked object *after* the
    /// revocation time should not be trusted.  Earlier objects should
    /// be considered okay.
    ///
    /// Only `KeySuperseded`, `KeyRetired`, and `UIDRetired` are
    /// considered soft revocations.  All other reasons for
    /// revocations including unknown reasons are considered hard
    /// revocations.
    Soft,
}

impl ReasonForRevocation {
    /// Returns the revocation's `RevocationType`.
    pub fn revocation_type(&self) -> RevocationType {
        match self {
            ReasonForRevocation::Unspecified => RevocationType::Hard,
            ReasonForRevocation::KeySuperseded => RevocationType::Soft,
            ReasonForRevocation::KeyCompromised => RevocationType::Hard,
            ReasonForRevocation::KeyRetired => RevocationType::Soft,
            ReasonForRevocation::UIDRetired => RevocationType::Soft,
            ReasonForRevocation::Private(_) => RevocationType::Hard,
            ReasonForRevocation::Unknown(_) => RevocationType::Hard,
            ReasonForRevocation::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Describes the format of the body of a literal data packet.
///
/// See the description of literal data packets [Section 5.9 of RFC 4880].
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum DataFormat {
    /// Binary data.
    ///
    /// This is a hint that the content is probably binary data.
    Binary,

    /// Text data.
    ///
    /// This is a hint that the content is probably text; the encoding
    /// is not specified.
    Text,

    /// Text data, probably valid UTF-8.
    ///
    /// This is a hint that the content is probably UTF-8 encoded.
    Unicode,

    /// MIME message.
    ///
    /// This is defined in [Section 5.10 of RFC4880bis].
    ///
    ///   [Section 5.10 of RFC4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.10
    MIME,

    /// Unknown format specifier.
    Unknown(char),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Default for DataFormat {
    fn default() -> Self {
        DataFormat::Binary
    }
}

impl From<u8> for DataFormat {
    fn from(u: u8) -> Self {
        (u as char).into()
    }
}

impl From<char> for DataFormat {
    fn from(c: char) -> Self {
        use self::DataFormat::*;
        match c {
            'b' => Binary,
            't' => Text,
            'u' => Unicode,
            'm' => MIME,
            c => Unknown(c),
        }
    }
}

impl From<DataFormat> for u8 {
    fn from(f: DataFormat) -> u8 {
        char::from(f) as u8
    }
}

impl From<DataFormat> for char {
    fn from(f: DataFormat) -> char {
        use self::DataFormat::*;
        match f {
            Binary => 'b',
            Text => 't',
            Unicode => 'u',
            MIME => 'm',
            Unknown(c) => c,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for DataFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DataFormat::*;
        match *self {
            Binary =>
                f.write_str("Binary data"),
            Text =>
                f.write_str("Text data"),
            Unicode =>
                f.write_str("Text data (UTF-8)"),
            MIME =>
                f.write_str("MIME message body part"),
            Unknown(c) =>
                f.write_fmt(format_args!(
                    "Unknown data format identifier {:?}", c)),
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Arbitrary for DataFormat {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The revocation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus<'a> {
    /// The key is definitely revoked.
    ///
    /// The relevant self-revocations are returned.
    Revoked(Vec<&'a crate::packet::Signature>),
    /// There is a revocation certificate from a possible designated
    /// revoker.
    CouldBe(Vec<&'a crate::packet::Signature>),
    /// The key does not appear to be revoked.
    ///
    /// An attacker could still have performed a DoS, which prevents
    /// us from seeing the revocation certificate.
    NotAsFarAsWeKnow,
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn comp_roundtrip(comp: CompressionAlgorithm) -> bool {
            let val: u8 = comp.clone().into();
            comp == CompressionAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn comp_display(comp: CompressionAlgorithm) -> bool {
            let s = format!("{}", comp);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn comp_parse(comp: CompressionAlgorithm) -> bool {
            match comp {
                CompressionAlgorithm::Unknown(u) => u > 110 || (u > 3 && u < 100),
                CompressionAlgorithm::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }


    quickcheck! {
        fn sym_roundtrip(sym: SymmetricAlgorithm) -> bool {
            let val: u8 = sym.clone().into();
            sym == SymmetricAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn sym_display(sym: SymmetricAlgorithm) -> bool {
            let s = format!("{}", sym);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn sym_parse(sym: SymmetricAlgorithm) -> bool {
            match sym {
                SymmetricAlgorithm::Unknown(u) =>
                    u == 5 || u == 6 || u > 110 || (u > 10 && u < 100),
                SymmetricAlgorithm::Private(u) =>
                    u >= 100 && u <= 110,
                _ => true
            }
        }
    }


    quickcheck! {
        fn aead_roundtrip(aead: AEADAlgorithm) -> bool {
            let val: u8 = aead.clone().into();
            aead == AEADAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn aead_display(aead: AEADAlgorithm) -> bool {
            let s = format!("{}", aead);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn aead_parse(aead: AEADAlgorithm) -> bool {
            match aead {
                AEADAlgorithm::Unknown(u) =>
                    u == 0 || u > 110 || (u > 2 && u < 100),
                AEADAlgorithm::Private(u) =>
                    u >= 100 && u <= 110,
                _ => true
            }
        }
    }


    quickcheck! {
        fn pk_roundtrip(pk: PublicKeyAlgorithm) -> bool {
            let val: u8 = pk.clone().into();
            pk == PublicKeyAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn pk_display(pk: PublicKeyAlgorithm) -> bool {
            let s = format!("{}", pk);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn pk_parse(pk: PublicKeyAlgorithm) -> bool {
            match pk {
                PublicKeyAlgorithm::Unknown(u) =>
                    u == 0 || u > 110 || (u >= 4 && u <= 15)
                    || (u >= 18 && u < 100),
                PublicKeyAlgorithm::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }


    quickcheck! {
        fn curve_roundtrip(curve: Curve) -> bool {
            curve == Curve::from_oid(curve.oid())
        }
    }


    quickcheck! {
        fn signature_type_roundtrip(t: SignatureType) -> bool {
            let val: u8 = t.clone().into();
            t == SignatureType::from(val)
        }
    }

    quickcheck! {
        fn signature_type_display(t: SignatureType) -> bool {
            let s = format!("{}", t);
            !s.is_empty()
        }
    }


    quickcheck! {
        fn hash_roundtrip(hash: HashAlgorithm) -> bool {
            let val: u8 = hash.clone().into();
            hash == HashAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn hash_roundtrip_str(hash: HashAlgorithm) -> bool {
            match hash {
                HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) => true,
                hash => {
                    let s = format!("{}", hash);
                    hash == HashAlgorithm::from_str(&s).unwrap()
                }
            }
        }
    }

    quickcheck! {
        fn hash_display(hash: HashAlgorithm) -> bool {
            let s = format!("{}", hash);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn hash_parse(hash: HashAlgorithm) -> bool {
            match hash {
                HashAlgorithm::Unknown(u) => u == 0 || (u > 11 && u < 100) ||
                    u > 110 || (u >= 4 && u <= 7) || u == 0,
                HashAlgorithm::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }

    quickcheck! {
        fn rfr_roundtrip(rfr: ReasonForRevocation) -> bool {
            let val: u8 = rfr.clone().into();
            rfr == ReasonForRevocation::from(val)
        }
    }

    quickcheck! {
        fn rfr_display(rfr: ReasonForRevocation) -> bool {
            let s = format!("{}", rfr);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn rfr_parse(rfr: ReasonForRevocation) -> bool {
            match rfr {
                ReasonForRevocation::Unknown(u) =>
                    (u > 3 && u < 32)
                    || (u > 32 && u < 100)
                    || u > 110,
                ReasonForRevocation::Private(u) =>
                    u >= 100 && u <= 110,
                _ => true
            }
        }
    }

    quickcheck! {
        fn df_roundtrip(df: DataFormat) -> bool {
            let val: u8 = df.clone().into();
            df == DataFormat::from(val)
        }
    }

    quickcheck! {
        fn df_display(df: DataFormat) -> bool {
            let s = format!("{}", df);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn df_parse(df: DataFormat) -> bool {
            match df {
                DataFormat::Unknown(u) =>
                    u != 'b' && u != 't' && u != 'u' && u != 'm',
                _ => true
            }
        }
    }
}
