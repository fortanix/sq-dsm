use std::fmt;

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

impl Into<u8> for PublicKeyAlgorithm {
    fn into(self) -> u8 {
        match self {
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

impl Into<u8> for CompressionAlgorithm {
    fn into(self) -> u8 {
        match self {
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
}
