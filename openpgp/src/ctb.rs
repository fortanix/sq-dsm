//! Cipher Type Byte.
//!
//! See [Section 4.2 of RFC 4880] for more details.
//!
//!   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2

use std::ops::Deref;

use {
    Tag,
    Error,
    Result
};
use packet::BodyLength;

/// OpenPGP defines two packet formats: the old and the new format.
/// They both include the packet's so-called tag.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBCommon {
    /// RFC4880 Packet tag
    pub tag: Tag,
}

/// The new CTB format.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBNew {
    /// Packet CTB fields
    pub common: CTBCommon,
}

impl CTBNew {
    /// Constructs a new-style CTB.
    pub fn new(tag: Tag) -> Self {
        CTBNew {
            common: CTBCommon {
                tag: tag,
            },
        }
    }
}

// Allow transparent access of common fields.
impl Deref for CTBNew {
    type Target = CTBCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

/// The PacketLengthType is used as part of the [old CTB], and is
/// partially used to determine the packet's size.
///
/// See [Section 4.2.1 of RFC 4880] for more details.
///
///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
///   [old CTB]: ./CTBOld.t.html
#[derive(Debug)]
#[derive(Clone, Copy, PartialEq)]
pub enum PacketLengthType {
    /// A one-octet Body Length header encodes a length of 0 to 191 octets.
    OneOctet,
    /// A two-octet Body Length header encodes a length of 192 to 8383 octets.
    TwoOctets,
    /// A five-octet Body Length header consists of a single octet holding
    /// the value 255, followed by a four-octet scalar.
    FourOctets,
    /// A Partial Body Length header is one octet long and encodes the length
    /// of only part of the data packet.
    Indeterminate,
}

// XXX: TryFrom is nightly only.
impl /* TryFrom<u8> for */ PacketLengthType {
    /* type Error = failure::Error; */
    /// Mirrors the nightly only TryFrom trait.
    pub fn try_from(u: u8) -> Result<Self> {
        match u {
            0 => Ok(PacketLengthType::OneOctet),
            1 => Ok(PacketLengthType::TwoOctets),
            2 => Ok(PacketLengthType::FourOctets),
            3 => Ok(PacketLengthType::Indeterminate),
            _ => Err(Error::InvalidArgument(
                format!("Invalid packet length: {}", u)).into()),
        }
    }
}

impl From<PacketLengthType> for u8 {
    fn from(l: PacketLengthType) -> Self {
        match l {
            PacketLengthType::OneOctet => 0,
            PacketLengthType::TwoOctets => 1,
            PacketLengthType::FourOctets => 2,
            PacketLengthType::Indeterminate => 3,
        }
    }
}

/// The old CTB format.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBOld {
    /// Common CTB fields.
    pub common: CTBCommon,
    /// Type of length sepcifier.
    pub length_type: PacketLengthType,
}

impl CTBOld {
    /// Constructs a old-style CTB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the tag or body length
    /// cannot be expressed using an old-style CTB.
    ///
    /// [`Error::InvalidArgument`]: ../enum.Error.html#variant.InvalidArgument
    pub fn new(tag: Tag, length: BodyLength) -> Result<Self> {
        let n: u8 = tag.into();

        // Only tags 0-15 are supported.
        if n > 15 {
            return Err(Error::InvalidArgument(
                format!("Only tags 0-15 are supported, got: {:?} ({})",
                        tag, n)).into());
        }

        let length_type = match length {
            // Assume an optimal encoding.
            BodyLength::Full(l) => {
                match l {
                    // One octet length.
                    0 ... 0xFF => PacketLengthType::OneOctet,
                    // Two octet length.
                    0x1_00 ... 0xFF_FF => PacketLengthType::TwoOctets,
                    // Four octet length,
                    _ => PacketLengthType::FourOctets,
                }
            },
            BodyLength::Partial(_) =>
                return Err(Error::InvalidArgument(
                    "Partial body lengths are not support for old format packets".
                        into()).into()),
            BodyLength::Indeterminate =>
                PacketLengthType::Indeterminate,
        };
        Ok(CTBOld {
            common: CTBCommon {
                tag: tag,
            },
            length_type: length_type,
        })
    }
}

// Allow transparent access of common fields.
impl Deref for CTBOld {
    type Target = CTBCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

/// A sum type for the different CTB variants.
///
/// There are two CTB variants: the [old CTB format] and the [new CTB
/// format].
///
///   [old CTB format]: ./CTBOld.t.html
///   [new CTB format]: ./CTBNew.t.html
///
/// Note: CTB stands for Cipher Type Byte.
#[derive(Debug)]
pub enum CTB {
    /// New (current) packet header format.
    New(CTBNew),
    /// Old PGP 2.6 header format.
    Old(CTBOld),
}

impl CTB {
    /// Constructs a new-style CTB.
    pub fn new(tag: Tag) -> Self {
        CTB::New(CTBNew::new(tag))
    }
}

// Allow transparent access of common fields.
impl Deref for CTB {
    type Target = CTBCommon;

    fn deref(&self) -> &Self::Target {
        match self {
            &CTB::New(ref ctb) => return &ctb.common,
            &CTB::Old(ref ctb) => return &ctb.common,
        }
    }
}

impl CTB {
    /// Parses a CTB as described in [Section 4.2 of RFC 4880].  This
    /// function parses both new and old format CTBs.
    ///
    ///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
    pub fn from_ptag(ptag: u8) -> Result<CTB> {
        // The top bit of the ptag must be set.
        if ptag & 0b1000_0000 == 0 {
            // XXX: Use a proper error.
            return Err(
                Error::MalformedPacket(
                    format!("Malformed CTB: MSB of ptag ({:#010b}) not set{}.",
                            ptag,
                            if ptag == '-' as u8 {
                                " (ptag is a dash, perhaps this is an \
                                 ASCII-armored encoded message)"
                            } else {
                                ""
                            })).into());
        }

        let new_format = ptag & 0b0100_0000 != 0;
        let ctb = if new_format {
            let tag = ptag & 0b0011_1111;
            CTB::New(CTBNew {
                common: CTBCommon {
                    tag: tag.into()
                }})
        } else {
            let tag = (ptag & 0b0011_1100) >> 2;
            let length_type = ptag & 0b0000_0011;

            CTB::Old(CTBOld {
                common: CTBCommon {
                    tag: tag.into(),
                },
                length_type: PacketLengthType::try_from(length_type)?,
            })
        };

        Ok(ctb)
    }
}

#[test]
fn ctb() {
    // 0x99 = public key packet
    if let CTB::Old(ctb) = CTB::from_ptag(0x99).unwrap() {
        assert_eq!(ctb.tag, Tag::PublicKey);
        assert_eq!(ctb.length_type, PacketLengthType::TwoOctets);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xa3 = old compressed packet
    if let CTB::Old(ctb) = CTB::from_ptag(0xa3).unwrap() {
        assert_eq!(ctb.tag, Tag::CompressedData);
        assert_eq!(ctb.length_type, PacketLengthType::Indeterminate);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xcb: new literal
    if let CTB::New(ctb) = CTB::from_ptag(0xcb).unwrap() {
        assert_eq!(ctb.tag, Tag::Literal);
    } else {
        panic!("Expected a new format packet.");
    }
}
