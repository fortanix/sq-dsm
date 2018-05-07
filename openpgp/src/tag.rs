use std::fmt;

use quickcheck::{Arbitrary, Gen};

/// The OpenPGP packet tags as defined in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
///
/// The values correspond to the serialized format.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tag {
    Reserved,
    /// Public-Key Encrypted Session Key Packet.
    PKESK,
    Signature,
    /// Symmetric-Key Encrypted Session Key Packet.
    SKESK,
    /// One-Pass Signature Packet.
    OnePassSig,
    SecretKey,
    PublicKey,
    SecretSubkey,
    CompressedData,
    /// Symmetrically Encrypted Data Packet.
    SED,
    Marker,
    Literal,
    Trust,
    UserID,
    PublicSubkey,
    UserAttribute,
    /// Sym. Encrypted and Integrity Protected Data Packet.
    SEIP ,
    /// Modification Detection Code Packet.
    MDC,
    /// Unassigned packets (as of RFC4880).
    Unknown(u8),
    /// Experimental packets.
    Private(u8),
}

impl From<u8> for Tag {
    fn from(u: u8) -> Self {
        use Tag::*;

        match u {
            0 => Reserved,
            1 => PKESK,
            2 => Signature,
            3 => SKESK,
            4 => OnePassSig,
            5 => SecretKey,
            6 => PublicKey,
            7 => SecretSubkey,
            8 => CompressedData,
            9 => SED,
            10 => Marker,
            11 => Literal,
            12 => Trust,
            13 => UserID,
            14 => PublicSubkey,
            17 => UserAttribute,
            18 => SEIP,
            19 => MDC,
            60...63 => Private(u),
            _ => Unknown(u),
        }
    }
}

impl From<Tag> for u8 {
    fn from(t: Tag) -> u8 {
        match t {
            Tag::Reserved => 0,
            Tag::PKESK => 1,
            Tag::Signature => 2,
            Tag::SKESK => 3,
            Tag::OnePassSig => 4,
            Tag::SecretKey => 5,
            Tag::PublicKey => 6,
            Tag::SecretSubkey => 7,
            Tag::CompressedData => 8,
            Tag::SED => 9,
            Tag::Marker => 10,
            Tag::Literal => 11,
            Tag::Trust => 12,
            Tag::UserID => 13,
            Tag::PublicSubkey => 14,
            Tag::UserAttribute => 17,
            Tag::SEIP => 18,
            Tag::MDC => 19,
            Tag::Private(x) => x,
            Tag::Unknown(x) => x,
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Tag::Reserved =>
                f.write_str("Reserved - a packet tag MUST NOT have this value"),
            Tag::PKESK =>
                f.write_str("Public-Key Encrypted Session Key Packet"),
            Tag::Signature =>
                f.write_str("Signature Packet"),
            Tag::SKESK =>
                f.write_str("Symmetric-Key Encrypted Session Key Packet"),
            Tag::OnePassSig =>
                f.write_str("One-Pass Signature Packet"),
            Tag::SecretKey =>
                f.write_str("Secret-Key Packet"),
            Tag::PublicKey =>
                f.write_str("Public-Key Packet"),
            Tag::SecretSubkey =>
                f.write_str("Secret-Subkey Packet"),
            Tag::CompressedData =>
                f.write_str("Compressed Data Packet"),
            Tag::SED =>
                f.write_str("Symmetrically Encrypted Data Packet"),
            Tag::Marker =>
                f.write_str("Marker Packet"),
            Tag::Literal =>
                f.write_str("Literal Data Packet"),
            Tag::Trust =>
                f.write_str("Trust Packet"),
            Tag::UserID =>
                f.write_str("User ID Packet"),
            Tag::PublicSubkey =>
                f.write_str("Public-Subkey Packet"),
            Tag::UserAttribute =>
                f.write_str("User Attribute Packet"),
            Tag::SEIP =>
                f.write_str("Sym. Encrypted and Integrity Protected Data Packet"),
            Tag::MDC =>
                f.write_str("Modification Detection Code Packet"),
            Tag::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental Packet {}",u)),
            Tag::Unknown(u) =>
                f.write_fmt(format_args!("Unknown Packet {}",u)),
        }
    }
}

impl Arbitrary for Tag {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn roundtrip(tag: Tag) -> bool {
            let val: u8 = tag.into();
            tag == Tag::from(val)
        }
    }

    quickcheck! {
        fn display(tag: Tag) -> bool {
            let s = format!("{}",tag);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn unknown_private(tag: Tag) -> bool {
            match tag {
                Tag::Unknown(u) => u > 19 || u == 15 || u == 16,
                Tag::Private(u) => u >= 60 && u <= 63,
                _ => true
            }
        }
    }

    #[test]
    fn parse() {
        for i in 0..0x100usize {
            Tag::from(i as u8);
        }
    }
}
