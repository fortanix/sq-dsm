//! Constants used in OpenPGP.
//!
//! This module defines enumerations describing algorithms used in
//! OpenPGP.

use std::fmt;
use std::str::FromStr;
use std::result;

use quickcheck::{Arbitrary, Gen};

use Error;
use Result;

/// The OpenPGP public key algorithms as defined in [Section 9.1 of
/// RFC 4880], and [Section 5 of RFC 6637].
///
///   [Section 9.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.1
///   [Section 5 of RFC 6637]: https://tools.ietf.org/html/rfc6637
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug,PartialOrd,Ord)]
pub enum PublicKeyAlgorithm {
    RSAEncryptSign,
    RSAEncrypt,
    RSASign,
    ElgamalEncrypt,
    DSA,
    ECDH,
    ECDSA,
    ElgamalEncryptSign,
    EdDSA,
    Private(u8),
    Unknown(u8),
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(u: u8) -> Self {
        use PublicKeyAlgorithm::*;
        match u {
            1 => RSAEncryptSign,
            2 => RSAEncrypt,
            3 => RSASign,
            16 => ElgamalEncrypt,
            17 => DSA,
            18 => ECDH,
            19 => ECDSA,
            20 => ElgamalEncryptSign,
            22 => EdDSA,
            100...110 => Private(u),
            u => Unknown(u),
        }
    }
}

impl From<PublicKeyAlgorithm> for u8 {
    fn from(p: PublicKeyAlgorithm) -> u8 {
        use PublicKeyAlgorithm::*;
        match p {
            RSAEncryptSign => 1,
            RSAEncrypt => 2,
            RSASign => 3,
            ElgamalEncrypt => 16,
            DSA => 17,
            ECDH => 18,
            ECDSA => 19,
            ElgamalEncryptSign => 20,
            EdDSA => 22,
            Private(u) => u,
            Unknown(u) => u,
        }
    }
}

impl fmt::Display for PublicKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PublicKeyAlgorithm::*;
        match *self {
            RSAEncryptSign => f.write_str("RSA (Encrypt or Sign)"),
            RSAEncrypt => f.write_str("RSA Encrypt-Only"),
            RSASign => f.write_str("RSA Sign-Only"),
            ElgamalEncrypt => f.write_str("Elgamal (Encrypt-Only)"),
            DSA => f.write_str("DSA (Digital Signature Algorithm)"),
            ECDSA => f.write_str("ECDSA public key algorithm"),
            ElgamalEncryptSign => f.write_str("Elgamal (Encrypt or Sign)"),
            ECDH => f.write_str("ECDH public key algorithm"),
            EdDSA => f.write_str("EdDSA Edwards-curve Digital Signature Algorithm)"),
            Private(u) =>
                f.write_fmt(format_args!("Private/Experimental public key algorithm {}",u)),
            Unknown(u) =>
                f.write_fmt(format_args!("Unknown public key algorithm {}",u)),
        }
    }
}

impl Arbitrary for PublicKeyAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
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

    /// Returns this curves OID.
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
#[derive(Clone,Copy,PartialEq,Eq,Debug,PartialOrd,Ord)]
pub enum SymmetricAlgorithm {
    Unencrypted,
    IDEA,
    TripleDES,
    CAST5,
    Blowfish,
    AES128,
    AES192,
    AES256,
    Twofish,
    Camellia128,
    Camellia192,
    Camellia256,
    Private(u8),
    Unknown(u8),
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
            100...110 => SymmetricAlgorithm::Private(u),
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
                f.write_str("TipleDES (EDE-DES, 168 bit key derived from 192))"),
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
                f.write_fmt(format_args!("Private/Experimental symmetric key algorithm {}",u)),
            SymmetricAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown symmetric key algorithm {}",u)),
        }
    }
}

impl Arbitrary for SymmetricAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The OpenPGP compression algorithms as defined in [Section 9.3 of RFC 4880].
///
///   [Section 9.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.3
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug,PartialOrd,Ord)]
pub enum CompressionAlgorithm {
    Uncompressed,
    Zip,
    Zlib,
    BZip2,
    Private(u8),
    Unknown(u8),
}

impl From<u8> for CompressionAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            0 => CompressionAlgorithm::Uncompressed,
            1 => CompressionAlgorithm::Zip,
            2 => CompressionAlgorithm::Zlib,
            3 => CompressionAlgorithm::BZip2,
            100...110 => CompressionAlgorithm::Private(u),
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
                f.write_fmt(format_args!("Private/Experimental compression algorithm {}",u)),
            CompressionAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown comppression algorithm {}",u)),
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
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug,PartialOrd,Ord)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    RipeMD,
    SHA256,
    SHA384,
    SHA512,
    SHA224,
    Private(u8),
    Unknown(u8),
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
            100...110 => HashAlgorithm::Private(u),
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
                f.write_fmt(format_args!("Private/Experimental hash algorithm {}",u)),
            HashAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown hash algorithm {}",u)),
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
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum SignatureType {
    // Signatures over data.
    Binary,
    Text,
    Standalone,

    // Certifications (signatures over keys).
    GenericCertificate,
    PersonaCertificate,
    CasualCertificate,
    PositiveCertificate,

    // Binding signatures.
    SubkeyBinding,
    PrimaryKeyBinding,
    DirectKey,

    // Revocations.
    KeyRevocation,
    SubkeyRevocation,
    CertificateRevocation,

    // Miscellaneous.
    Timestamp,
    Confirmation,

    // Catchall.
    Unknown(u8),
}

impl From<u8> for SignatureType {
    fn from(u: u8) -> Self {
        match u {
            0x00 => SignatureType::Binary,
            0x01 => SignatureType::Text,
            0x02 => SignatureType::Standalone,
            0x10 => SignatureType::GenericCertificate,
            0x11 => SignatureType::PersonaCertificate,
            0x12 => SignatureType::CasualCertificate,
            0x13 => SignatureType::PositiveCertificate,
            0x18 => SignatureType::SubkeyBinding,
            0x19 => SignatureType::PrimaryKeyBinding,
            0x1f => SignatureType::DirectKey,
            0x20 => SignatureType::KeyRevocation,
            0x28 => SignatureType::SubkeyRevocation,
            0x30 => SignatureType::CertificateRevocation,
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
            SignatureType::GenericCertificate => 0x10,
            SignatureType::PersonaCertificate => 0x11,
            SignatureType::CasualCertificate => 0x12,
            SignatureType::PositiveCertificate => 0x13,
            SignatureType::SubkeyBinding => 0x18,
            SignatureType::PrimaryKeyBinding => 0x19,
            SignatureType::DirectKey => 0x1f,
            SignatureType::KeyRevocation => 0x20,
            SignatureType::SubkeyRevocation => 0x28,
            SignatureType::CertificateRevocation => 0x30,
            SignatureType::Timestamp => 0x40,
            SignatureType::Confirmation => 0x50,
            SignatureType::Unknown(u) => u,
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
            SignatureType::GenericCertificate =>
                f.write_str("GenericCertificate"),
            SignatureType::PersonaCertificate =>
                f.write_str("PersonaCertificate"),
            SignatureType::CasualCertificate =>
                f.write_str("CasualCertificate"),
            SignatureType::PositiveCertificate =>
                f.write_str("PositiveCertificate"),
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
            SignatureType::CertificateRevocation =>
                f.write_str("CertificateRevocation"),
            SignatureType::Timestamp =>
                f.write_str("Timestamp"),
            SignatureType::Confirmation =>
                f.write_str("Confirmation"),
            SignatureType::Unknown(u) =>
                f.write_fmt(format_args!("Unknown signature type {}",u)),
        }
    }
}

impl Arbitrary for SignatureType {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
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
            let s = format!("{}",comp);
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
            let s = format!("{}",sym);
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
        fn pk_roundtrip(pk: PublicKeyAlgorithm) -> bool {
            let val: u8 = pk.clone().into();
            pk == PublicKeyAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn pk_display(pk: PublicKeyAlgorithm) -> bool {
            let s = format!("{}",pk);
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
        fn sigtype_roundtrip(t: SignatureType) -> bool {
            let val: u8 = t.clone().into();
            t == SignatureType::from(val)
        }
    }

    quickcheck! {
        fn sigtype_display(t: SignatureType) -> bool {
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
                    let s = format!("{}",hash);
                    hash == HashAlgorithm::from_str(&s).unwrap()
                }
            }
        }
    }

    quickcheck! {
        fn hash_display(hash: HashAlgorithm) -> bool {
            let s = format!("{}",hash);
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
}
