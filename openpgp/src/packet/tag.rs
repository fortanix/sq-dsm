use std::fmt;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::packet::Packet;

/// The OpenPGP packet tags as defined in [Section 5 of RFC 9580].
///
///   [Section 5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
///
/// The values correspond to the serialized format.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Tag {
    /// Reserved Packet tag.
    Reserved,
    /// Public-Key Encrypted Session Key Packet.
    PKESK,
    /// Signature Packet.
    Signature,
    /// Symmetric-Key Encrypted Session Key Packet.
    SKESK,
    /// One-Pass Signature Packet.
    OnePassSig,
    /// Secret-Key Packet.
    SecretKey,
    /// Public-Key Packet.
    PublicKey,
    /// Secret-Subkey Packet.
    SecretSubkey,
    /// Compressed Data Packet.
    CompressedData,
    /// Symmetrically Encrypted Data Packet.
    SED,
    /// Marker Packet (Obsolete Literal Packet).
    Marker,
    /// Literal Data Packet.
    Literal,
    /// Trust Packet.
    Trust,
    /// User ID Packet.
    UserID,
    /// Public-Subkey Packet.
    PublicSubkey,
    /// User Attribute Packet.
    UserAttribute,
    /// Sym. Encrypted and Integrity Protected Data Packet.
    SEIP,
    /// Modification Detection Code Packet.
    MDC,
    /// Reserved ("AEAD Encrypted Data Packet").
    AED,
    /// Padding packet.
    Padding,
    /// Unassigned packets (as of RFC4880).
    Unknown(u8),
    /// Experimental packets.
    Private(u8),
}
assert_send_and_sync!(Tag);

impl Eq for Tag {}

impl PartialEq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for Tag
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag
{
    fn cmp(&self, other: &Self) -> Ordering {
        let a : u8 = (*self).into();
        let b : u8 = (*other).into();
        a.cmp(&b)
    }
}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let t: u8 = (*self).into();
        t.hash(state);
    }
}

impl From<u8> for Tag {
    fn from(u: u8) -> Self {
        use crate::packet::Tag::*;

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
            20 => AED,
            21 => Padding,
            60..=63 => Private(u),
            _ => Unknown(u),
        }
    }
}

impl From<Tag> for u8 {
    fn from(t: Tag) -> u8 {
        (&t).into()
    }
}

impl From<&Tag> for u8 {
    fn from(t: &Tag) -> u8 {
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
            Tag::AED => 20,
            Tag::Padding => 21,
            Tag::Private(x) => *x,
            Tag::Unknown(x) => *x,
        }
    }
}

impl From<&Packet> for Tag {
    fn from(p: &Packet) -> Tag {
        p.tag()
    }
}

impl From<Packet> for Tag {
    fn from(p: Packet) -> Tag {
        p.tag()
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
            Tag::AED =>
                f.write_str("AEAD Encrypted Data Packet"),
            Tag::Padding =>
                f.write_str("Padding Packet"),
            Tag::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental Packet {}", u)),
            Tag::Unknown(u) =>
                f.write_fmt(format_args!("Unknown Packet {}", u)),
        }
    }
}

const PACKET_TAG_VARIANTS: [Tag; 19] = [
    Tag::PKESK,
    Tag::Signature,
    Tag::SKESK,
    Tag::OnePassSig,
    Tag::SecretKey,
    Tag::PublicKey,
    Tag::SecretSubkey,
    Tag::CompressedData,
    Tag::SED,
    Tag::Marker,
    Tag::Literal,
    Tag::Trust,
    Tag::UserID,
    Tag::PublicSubkey,
    Tag::UserAttribute,
    Tag::SEIP,
    Tag::MDC,
    Tag::AED,
    Tag::Padding,
];

#[cfg(test)]
impl Arbitrary for Tag {
    fn arbitrary(g: &mut Gen) -> Self {
        loop {
            match u8::arbitrary(g) {
                n @ 0..=63 => break n.into(),
                _ => (), // try again
            }
        }
    }
}

impl Tag {
    /// Returns whether the `Tag` denotes a critical packet.
    ///
    /// Upon encountering an unknown critical packet, implementations
    /// MUST reject the whole packet sequence.  On the other hand,
    /// unknown non-critical packets MUST be ignored.  See [Section
    /// 4.3 of RFC 9580].
    ///
    /// [Section 4.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.3
    pub fn is_critical(&self) -> bool {
        match u8::from(self) {
            0..=39 => true,
            40..=63 => false,
            // Should never happen, but let's map this to critical as
            // a conservative choice.
            64..=255 => true,
        }
    }

    /// Returns whether the `Tag` can be at the start of a valid
    /// message.
    ///
    /// [Certs] can start with `PublicKey`, [TSKs] with a `SecretKey`.
    ///
    ///   [Certs]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.1
    ///   [TSKs]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.2
    ///
    /// [Messages] start with a `OnePassSig`, `Signature` (old style
    /// non-one pass signatures), `PKESK`, `SKESK`, `CompressedData`,
    /// or `Literal`.
    ///
    ///   [Messages]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
    ///
    /// Signatures can stand alone either as a [detached signature], a
    /// third-party certification, or a revocation certificate.
    ///
    ///   [detached signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
    pub fn valid_start_of_message(&self) -> bool {
        // Cert
        *self == Tag::PublicKey || *self == Tag::SecretKey
            // Message.
            || *self == Tag::PKESK || *self == Tag::SKESK
            || *self == Tag::Literal || *self == Tag::CompressedData
            // Signed message.
            || *self == Tag::OnePassSig
            // Standalone signature, old-style signature.
            || *self == Tag::Signature
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`Tag::Reserved`], [`Tag::Private`], or
    /// [`Tag::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Tag> {
        PACKET_TAG_VARIANTS.iter().cloned()
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
            let s = format!("{}", tag);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn unknown_private(tag: Tag) -> bool {
            match tag {
                Tag::Unknown(u) => u > 19 || u == 15 || u == 16,
                Tag::Private(u) => (60..=63).contains(&u),
                _ => true
            }
        }
    }

    #[test]
    fn parse() {
        for i in 0..u8::MAX {
            let _ = Tag::from(i);
        }
    }

    #[test]
    fn tag_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // PACKET_TAG_VARIANTS is a list.  Derive it in a different way
        // to double-check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(Tag::from)
            .filter(|t| {
                match t {
                    Tag::Reserved => false,
                    Tag::Private(_) => false,
                    Tag::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(PACKET_TAG_VARIANTS.iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
