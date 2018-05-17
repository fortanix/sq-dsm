use std::fmt;
use std::str::FromStr;
use std::result;

use quickcheck::{Arbitrary, Gen};

/// The OpenPGP public key algorithms as defined in [Section 9.1 of RFC 4880].
///
///   [Section 9.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.1
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum PublicKeyAlgorithm {
    RsaEncryptSign,
    RsaEncrypt,
    RsaSign,
    Elgamal,
    Dsa,
    Private(u8),
    Unknown(u8),
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            1 => PublicKeyAlgorithm::RsaEncryptSign,
            2 => PublicKeyAlgorithm::RsaEncrypt,
            3 => PublicKeyAlgorithm::RsaSign,
            16 => PublicKeyAlgorithm::Elgamal,
            17 => PublicKeyAlgorithm::Dsa,
            100...110 => PublicKeyAlgorithm::Private(u),
            u => PublicKeyAlgorithm::Unknown(u),
        }
    }
}

impl From<PublicKeyAlgorithm> for u8 {
    fn from(p: PublicKeyAlgorithm) -> u8 {
        match p {
            PublicKeyAlgorithm::RsaEncryptSign => 1,
            PublicKeyAlgorithm::RsaEncrypt => 2,
            PublicKeyAlgorithm::RsaSign => 3,
            PublicKeyAlgorithm::Elgamal => 16,
            PublicKeyAlgorithm::Dsa => 17,
            PublicKeyAlgorithm::Private(u) => u,
            PublicKeyAlgorithm::Unknown(u) => u,
        }
    }
}

impl fmt::Display for PublicKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PublicKeyAlgorithm::RsaEncryptSign =>
                f.write_str("RSA (Encrypt or Sign)"),
            PublicKeyAlgorithm::RsaEncrypt =>
                f.write_str("RSA Encrypt-Only"),
            PublicKeyAlgorithm::RsaSign =>
                f.write_str("RSA Sign-Only"),
            PublicKeyAlgorithm::Elgamal =>
                f.write_str("Elgamal (Encrypt-Only)"),
            PublicKeyAlgorithm::Dsa =>
                f.write_str("DSA (Digital Signature Algorithm)"),
            PublicKeyAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental public key algorithm {}",u)),
            PublicKeyAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown public key algorithm {}",u)),
        }
    }
}

impl Arbitrary for PublicKeyAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

/// The OpenPGP compression algorithms as defined in [Section 9.3 of RFC 4880].
///
///   [Section 9.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.3
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
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
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
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
                    u == 0 || u > 110 || (u >= 4 && u <= 15) || (u >= 18 && u < 100),
                PublicKeyAlgorithm::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
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
