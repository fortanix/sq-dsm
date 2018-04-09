//! Cipher Type Byte.
//!
//! See [Section 4.2 of RFC 4880] for more details.
//!
//!   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2

use num;
use std::ops::Deref;
use super::{Tag};

/// OpenPGP defines two packet formats: the old and the new format.
/// They both include the packet's so-called tag.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBCommon {
    pub tag: Tag,
}

/// The new CTB format.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBNew {
    pub common: CTBCommon,
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
#[derive(FromPrimitive)]
#[derive(Clone, Copy, PartialEq)]
pub enum PacketLengthType {
    OneOctet = 0,
    TwoOctets = 1,
    FourOctets = 2,
    Indeterminate = 3,
}

impl PacketLengthType {
    /// Converts a numeric value to an `Option<PacketLengthType>`.
    ///
    /// Returns None, if the value is out of range (outside of 0-3).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openpgp::ctb::PacketLengthType;
    ///
    /// assert_eq!(PacketLengthType::from_numeric(1),
    ///            Some(PacketLengthType::TwoOctets));
    /// ```
    pub fn from_numeric(value: u8) -> Option<Self> {
        num::FromPrimitive::from_u8(value)
    }
}

/// The old CTB format.
///
/// See [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
#[derive(Debug)]
pub struct CTBOld {
    pub common: CTBCommon,
    pub length_type: PacketLengthType,
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
    New(CTBNew),
    Old(CTBOld),
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
