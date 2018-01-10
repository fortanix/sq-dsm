//! OpenPGP data types and associated machinery.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 4880] as well as several extensions (e.g., [RFC
//! 6637], which describes ECC cryptography for OpenPGP).  This
//! includes support for unbuffered message processing.
//!
//! A few features that the OpenPGP community considers to be
//! deprecated (e.g., version 3 compatibility) have been left out as
//! well as support for functionality that we consider to be not only
//! completely useless, but also dangerous (e.g., support for
//! [unhashed signature subpackets]).  We have also updated some
//! OpenPGP defaults to avoid foot guns (e.g., this crate does not
//! fallback to IDEA, but instead assumes all OpenPGP implementations
//! understand AES).  If some functionality is missing, please file a
//! bug report.
//!
//! A non-goal of this crate is support for any sort of high-level,
//! bolted-on functionality.  For instance, [RFC 4880] does not define
//! trust models, such as the web of trust, direct trust, or TOFU.
//! Neither does this crate.  [RFC 4880] does provide some mechanisms
//! for creating trust models (specifically, UserID certifications),
//! and this crate does expose those mechanisms.
//!
//! We also try hard to avoid dictating how OpenPGP should be used.
//! This doesn't mean that we don't have opinions about how OpenPGP
//! should be used in a number of common scenarios (for instance,
//! message validation).  But, in this crate, we refrain from
//! expressing those opinions; we expose an opinionated, high-level
//! interface in the [sequoia-core] and related crates.  In our
//! opinion, you should generally use those crates instead of this
//! one.
//!
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880
//! [RFC 6637]: https://tools.ietf.org/html/rfc6637
//! [unhashed signature subpackets]: https://tools.ietf.org/html/rfc4880#section-5.2.3.2
//! [sequoia-core]: ../sequoia_core

extern crate buffered_reader;

// For #[derive(FromPrimitive)]
extern crate num;

#[macro_use]
extern crate num_derive;

extern crate sha1;

extern crate flate2;
extern crate bzip2;

use std::fmt;
use std::ops::Deref;

use std::cell::RefCell;
use std::collections::HashMap;

pub mod armor;
pub mod parse;
pub mod tpk;
pub mod types;
pub mod serialize;

mod unknown;
mod signature;
mod key;
mod userid;
mod user_attribute;
mod literal;
mod compressed_data;
mod packet;
mod container;
mod message;
mod iter;

/// The OpenPGP packet tags as defined in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
///
/// The values correspond to the serialized format.  The packet types
/// named `UnassignedXX` are not in use as of RFC 4880.
///
/// Use [`Tag::from_numeric`] to translate a numeric value to a symbolic
/// one.
///
///   [`Tag::from_numeric`]: enum.Tag.html#method.from_numeric
#[derive(Debug)]
#[derive(FromPrimitive)]
#[derive(ToPrimitive)]
// We need PartialEq so that assert_eq! works.
#[derive(PartialEq)]
#[derive(Clone, Copy)]
pub enum Tag {
    Reserved0 = 0,
    /* Public-Key Encrypted Session Key Packet.  */
    PKESK = 1,
    Signature = 2,
    /* Symmetric-Key Encrypted Session Key Packet.  */
    SKESK = 3,
    /* One-Pass Signature Packet.  */
    OnePassSig = 4,
    SecretKey = 5,
    PublicKey = 6,
    SecretSubkey = 7,
    CompressedData = 8,
    /* Symmetrically Encrypted Data Packet.  */
    SED = 9,
    Marker = 10,
    Literal = 11,
    Trust = 12,
    UserID = 13,
    PublicSubkey = 14,

    Unassigned15 = 15,
    Unassigned16 = 16,

    UserAttribute = 17,
    /* Sym. Encrypted and Integrity Protected Data Packet.  */
    SEIP = 18,
    /* Modification Detection Code Packet.  */
    MDC = 19,

    /* Unassigned packets (as of RFC4880).  */
    Unassigned20 = 20,
    Unassigned21 = 21,
    Unassigned22 = 22,
    Unassigned23 = 23,
    Unassigned24 = 24,
    Unassigned25 = 25,
    Unassigned26 = 26,
    Unassigned27 = 27,
    Unassigned28 = 28,
    Unassigned29 = 29,

    Unassigned30 = 30,
    Unassigned31 = 31,
    Unassigned32 = 32,
    Unassigned33 = 33,
    Unassigned34 = 34,
    Unassigned35 = 35,
    Unassigned36 = 36,
    Unassigned37 = 37,
    Unassigned38 = 38,
    Unassigned39 = 39,

    Unassigned40 = 40,
    Unassigned41 = 41,
    Unassigned42 = 42,
    Unassigned43 = 43,
    Unassigned44 = 44,
    Unassigned45 = 45,
    Unassigned46 = 46,
    Unassigned47 = 47,
    Unassigned48 = 48,
    Unassigned49 = 49,

    Unassigned50 = 50,
    Unassigned51 = 51,
    Unassigned52 = 52,
    Unassigned53 = 53,
    Unassigned54 = 54,
    Unassigned55 = 55,
    Unassigned56 = 56,
    Unassigned57 = 57,
    Unassigned58 = 58,
    Unassigned59 = 59,

    /* Experimental packets.  */
    Private0 = 60,
    Private1 = 61,
    Private2 = 62,
    Private3 = 63,
}

impl Tag {
    /// Converts a numeric value to an `Option<Tag>`.
    ///
    /// Returns None, if the value is out of range (outside of 0-63).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openpgp::Tag;
    ///
    /// assert_eq!(Tag::from_numeric(1), Some(Tag::PKESK));
    /// ```
    pub fn from_numeric(value: u8) -> Option<Self> {
        num::FromPrimitive::from_u8(value)
    }

    /// Converts a `Tag` to its corresponding numeric value.
    pub fn to_numeric(self) -> u8 {
        num::ToPrimitive::to_u8(&self).unwrap()
    }
}

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
    /// use openpgp::PacketLengthType;
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

/// The size of a packet.
///
/// A packet's size can be expressed in three different ways.  Either
/// the size of the packet is fully known (Full), the packet is
/// chunked using OpenPGP's partial body encoding (Partial), or the
/// packet extends to the end of the file (Indeterminate).  See
/// [Section 4.2 of RFC 4880] for more details.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
///
/// If the packet is chunked, then the `x` in `Partial(x)` indicates
/// the number of bytes remaining in the current chunk.  The chunk is
/// followed by another new format length header, which can be read
/// using [`body_length_new_format`()].
///
///   [`body_length_new_format`()]: ./parse/fn.body_length_new_format.html
#[derive(Debug)]
// We need PartialEq so that assert_eq! works.
#[derive(PartialEq)]
#[derive(Clone, Copy)]
pub enum BodyLength {
    Full(u32),
    /// The parameter is the number of bytes in the current chunk.
    /// This type is only used with new format packets.
    Partial(u32),
    /// The packet extends until an EOF is encountered.  This type is
    /// only used with old format packets.
    Indeterminate,
}

/// Fields used by multiple packet types.
#[derive(PartialEq, Clone)]
pub struct PacketCommon {
    /// Used by container packets (such as the encryption and
    /// compression packets) to reference their immediate children.
    /// This results in a tree structure.
    ///
    /// This is automatically populated when using the `Message`
    /// deserialization routines, e.g., [`Message::from_file`].  By
    /// default, it is *not* automatically filled in by the
    /// [`PacketParser`] deserialization routines; this needs to be
    /// done manually.
    ///
    ///   [`Message`]: ./struct.Message.html
    ///   [`Message::from_file`]: ./struct.Message.html#method.from_file
    ///   [`PacketParser`]: ./struct.PacketParser.html
    pub children: Option<Container>,

    /// Holds a packet's body.
    ///
    /// We conceptually divide packets into two parts: the header and
    /// the body.  Whereas the header is read eagerly when the packet
    /// is deserialized, the body is only read on demand.
    ///
    /// A packet's body is stored here either when configured via
    /// [`PacketParserBuilder::buffer_unread_content`], when one of
    /// the [`Message`] deserialization routines is used, or on demand
    /// for a particular packet using the
    /// [`PacketParser::buffer_unread_content`] method.
    ///
    ///   [`PacketParserBuilder::buffer_unread_content`]: parse/struct.PacketParserBuilder.html#method.buffer_unread_content
    ///   [`Message`]: struct.Message.html
    ///   [`PacketParser::buffer_unread_content`]: parse/struct.PacketParser.html#method.buffer_unread_content
    ///
    /// There are three different types of packets:
    ///
    ///   - Packets like the [`UserID`] and [`Signature`] packets,
    ///     don't actually have a body.  These packets don't use this
    ///     field.
    ///
    ///   [`UserID`]: struct.UserID.html
    ///   [`Signature`]: struct.Signature.html
    ///
    ///   - One packet, the literal data packet, includes unstructured
    ///     data.  That data can be stored here.
    ///
    ///   - Some packets are containers.  If the parser does not parse
    ///     the packet's child, either because the caller used
    ///     [`PacketParser::next`] to get the next packet, or the
    ///     maximum recursion depth was reached, then the packets can
    ///     be stored here as a byte stream.  (If the caller so
    ///     chooses, the content can be parsed later using the regular
    ///     deserialization routines, since the content is just an
    ///     OpenPGP message.)
    ///
    ///   [`PacketParser::next`]: parse/struct.PacketParser.html#method.next
    ///
    /// Note: if some of a packet's data is processed, and the
    /// `PacketParser` is configured to buffer unread content, then
    /// this is not the packet's entire content; it is just the unread
    /// content.
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for PacketCommon {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketCommon")
            .field("children", &self.children)
            .field("body (bytes)",
                   &self.body.as_ref().map(|body| body.len()))
            .finish()
    }
}

impl Default for PacketCommon {
    fn default() -> PacketCommon {
        PacketCommon {
            children: None,
            body: None,
        }
    }
}

/// An OpenPGP packet's header.
#[derive(Debug)]
pub struct Header {
    /// The packet's CTB.
    pub ctb: CTB,
    /// The packet's length.
    pub length: BodyLength,
}

/// Holds an unknown packet.
///
/// This is used by the parser to hold packets that it doesn't know
/// how to process rather than abort.
///
/// This packet effectively holds a binary blob.
#[derive(PartialEq, Clone, Debug)]
pub struct Unknown {
    pub common: PacketCommon,
    pub tag: Tag,
}

/// Holds a signature packet.
///
/// Signature packets are used both for certification purposes as well
/// as for document signing purposes.
///
/// See [Section 5.2 of RFC 4880] for details.
///
///   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2
// Note: we can't derive PartialEq, because it includes the cached data.
#[derive(Clone)]
pub struct Signature {
    pub common: PacketCommon,
    pub version: u8,
    pub sigtype: u8,
    pub pk_algo: u8,
    pub hash_algo: u8,
    pub hashed_area: Vec<u8>,
    // We parse the subpackets on demand.  Since self-referential
    // structs are a no-no, we use (start, len) to reference the
    // content in hashed_area.
    hashed_area_parsed: RefCell<Option<HashMap<u8, (bool, u16, u16)>>>,
    pub unhashed_area: Vec<u8>,
    unhashed_area_parsed: RefCell<Option<HashMap<u8, (bool, u16, u16)>>>,
    pub hash_prefix: [u8; 2],
    pub mpis: Vec<u8>,
}

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
#[derive(PartialEq, Clone)]
pub struct Key {
    pub common: PacketCommon,
    pub version: u8,
    /* When the key was created.  */
    pub creation_time: u32,
    pub pk_algo: u8,
    pub mpis: Vec<u8>,
}

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
#[derive(PartialEq, Clone)]
pub struct UserID {
    pub common: PacketCommon,
    /// The user id.
    ///
    /// According to [RFC 4880], the text is by convention UTF-8 encoded
    /// and in "mail name-addr" form, i.e., "Name (Comment)
    /// <email@example.com>".
    ///
    ///   [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
    ///
    /// Use `UserID::default()` to get a UserID with a default settings.
    pub value: Vec<u8>,
}

/// Holds a UserAttribute packet.
///
/// See [Section 5.12 of RFC 4880] for details.
///
///   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12
#[derive(PartialEq, Clone)]
pub struct UserAttribute {
    pub common: PacketCommon,

    /// The user attribute.
    pub value: Vec<u8>,
}

/// Holds a literal packet.
///
/// A literal packet contains unstructured data.  Since the size can
/// be very large, it is advised to process messages containing such
/// packets using a `PacketParser` or a `MessageParser` and process
/// the data in a streaming manner rather than the using the
/// `Message::from_file` and related interfaces.
///
/// See [Section 5.9 of RFC 4880] for details.
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(PartialEq, Clone)]
pub struct Literal {
    pub common: PacketCommon,
    pub format: u8,
    /// filename is a string, but strings in Rust are valid UTF-8.
    /// There is no guarantee, however, that the filename is valid
    /// UTF-8.  Thus, we leave filename as a byte array.  It can be
    /// converted to a string using String::from_utf8() or
    /// String::from_utf8_lossy().
    pub filename: Option<Vec<u8>>,
    pub date: u32,
}

/// Holds a compressed data packet.
///
/// A compressed data packet is a container.  See [Section 5.6 of RFC
/// 4880] for details.
///
/// When the parser encounters a compressed data packet with an
/// unknown compress algorithm, it returns an `Unknown` packet instead
/// of a `CompressedData` packet.
///
/// [Section 5.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.6
#[derive(PartialEq, Clone)]
pub struct CompressedData {
    pub common: PacketCommon,
    pub algo: u8,
}

/// The OpenPGP packets that Sequoia understands.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 4880].
///
/// The `Unknown` packet allows Sequoia to deal with packets that it
/// doesn't understand.  The `Unknown` packet is basically a binary
/// blob that includes the packet's tag.
///
/// The unknown packet is also used for packets that are understood,
/// but use unsupported options.  For instance, when the packet parser
/// encounters a compressed data packet with an unknown compression
/// algorithm, it returns the packet in an `Unknown` packet rather
/// than a `CompressedData` packet.
///
///   [Section 5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5
#[derive(Debug)]
#[derive(PartialEq, Clone)]
pub enum Packet {
    Unknown(Unknown),
    Signature(Signature),
    PublicKey(Key),
    PublicSubkey(Key),
    SecretKey(Key),
    SecretSubkey(Key),
    UserID(UserID),
    UserAttribute(UserAttribute),
    Literal(Literal),
    CompressedData(CompressedData),
}

impl Packet {
    /// Returns the `Packet's` corresponding OpenPGP tag.
    ///
    /// Tags are explained in [Section 4.3 of RFC 4880].
    ///
    ///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
    pub fn tag(&self) -> Tag {
        match self {
            &Packet::Unknown(ref packet) => packet.tag,
            &Packet::Signature(_) => Tag::Signature,
            &Packet::PublicKey(_) => Tag::PublicKey,
            &Packet::PublicSubkey(_) => Tag::PublicSubkey,
            &Packet::SecretKey(_) => Tag::SecretKey,
            &Packet::SecretSubkey(_) => Tag::SecretSubkey,
            &Packet::UserID(_) => Tag::UserID,
            &Packet::UserAttribute(_) => Tag::UserAttribute,
            &Packet::Literal(_) => Tag::Literal,
            &Packet::CompressedData(_) => Tag::CompressedData,
        }
    }
}

/// Holds zero or more OpenPGP packets.
///
/// This is used by OpenPGP container packets, like the compressed
/// data packet, to store the containing packets.
#[derive(PartialEq, Clone)]
pub struct Container {
    packets: Vec<Packet>,
}

// This impl is here and not in the container module, because it is
// supposed to private to the outside world, but functionality in this
// crate should be able to use it.
impl Container {
    fn new() -> Container {
        Container { packets: Vec::with_capacity(8) }
    }

    // Adds a new packet to the container.
    fn push(&mut self, packet: Packet) {
        self.packets.push(packet);
    }

    // Inserts a new packet to the container at a particular index.
    // If `i` is 0, the new packet is insert at the front of the
    // container.  If `i` is one, it is inserted after the first
    // packet, etc.
    fn insert(&mut self, i: usize, packet: Packet) {
        self.packets.insert(i, packet);
    }

    // Converts an indentation level to whitespace.
    fn indent(depth: usize) -> &'static str {
        use std::cmp;

        let s = "                                                  ";
        return &s[0..cmp::min(depth, s.len())];
    }

    // Pretty prints the container to stderr.
    //
    // This function is primarily intended for debugging purposes.
    //
    // `indent` is the number of spaces to indent the output.
    fn pretty_print(&self, indent: usize) {
        for (i, p) in self.packets.iter().enumerate() {
            eprintln!("{}{}: {:?}",
                      Self::indent(indent), i + 1, p);
            if let Some(ref children) = self.packets[i].children {
                children.pretty_print(indent + 1);
            }
        }
    }
}


/// A `Message` holds a deserialized OpenPGP message.
///
/// To deserialize an OpenPGP usage, use either [`PacketParser`],
/// [`MessageParser`], or [`Message::from_file`] (or related
/// routines).
///
///   [`PacketParser`]: parse/struct.PacketParser.html
///   [`MessageParser`]: parse/struct.MessageParser.html
///   [`Message::from_file`]: struct.Message.html#method.from_file
#[derive(PartialEq, Clone)]
pub struct Message {
    // At the top level, we have a sequence of packets, which may be
    // containers.
    top_level: Container,
}

/// A `PacketIter` iterates over the *contents* of a packet in
/// depth-first order.  It starts by returning the current packet.
pub struct PacketIter<'a> {
    // An iterator over the current message's children.
    children: std::slice::Iter<'a, Packet>,
    // The current child (i.e., the last value returned by
    // children.next()).
    child: Option<&'a Packet>,
    // The an iterator over the current child's children.
    grandchildren: Option<Box<PacketIter<'a>>>,

    // The depth of the last returned packet.  This is used by the
    // `paths` iter.
    depth: usize,
}

/// Like `enumerate`, this augments the packet returned by a
/// `PacketIter` with its `Path`.
pub struct PacketPathIter<'a> {
    iter: PacketIter<'a>,

    // The path to the most recently returned node relative to the
    // start of the iterator.
    path: Option<Vec<usize>>,
}

/// Holds a fingerprint.
///
/// A fingerprint uniquely identifies a public key.  For more details
/// about how a fingerprint is generated, see [Section 12.2 of RFC
/// 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
#[derive(PartialEq)]
pub enum Fingerprint {
    V4([u8;20]),
    // Used for holding fingerprints that we don't understand.  For
    // instance, we don't grok v3 fingerprints.  And, it is possible
    // that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl Fingerprint {
    /// Reads a binary fingerprint.
    pub fn from_bytes(raw: &[u8]) -> Fingerprint {
        if raw.len() == 20 {
            let mut fp : [u8; 20] = Default::default();
            fp.copy_from_slice(raw);
            Fingerprint::V4(fp)
        } else {
            Fingerprint::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Reads a hexadecimal fingerprint.
    ///
    /// # Example
    ///
    /// ```
    /// # use openpgp::Fingerprint;
    /// let hex = "3E8877C877274692975189F5D03F6F865226FE8B";
    /// let fp = Fingerprint::from_hex(hex);
    /// assert!(fp.is_some());
    /// assert_eq!(fp.unwrap().to_hex(), hex);
    /// ```
    pub fn from_hex(hex: &str) -> Option<Fingerprint> {
        if hex.len() % 2 != 0 {
            return None;
        }

        let mut raw = vec![];
        for i in 0 .. hex.len() / 2 {
            if let Ok(b) = u8::from_str_radix(&hex[i * 2 .. (i + 1) * 2], 16) {
                raw.push(b);
            } else {
                return None;
            }
        }

        Some(Fingerprint::from_bytes(&raw))
    }

    /// Converts the fingerprint to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the fingerprint to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &Fingerprint::V4(ref fp) => &fp[..],
            &Fingerprint::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 fingerprints, which look like:
        //
        //   8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid fingerprint,
        // just format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
                // After 5 groups, there is another space.
                + raw.len() / 10
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            if pretty && i > 0 && i % 10 == 0 {
                output.push(' ' as u8);
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
    }

    /// Converts the fingerprint to a key ID.
    pub fn to_keyid(&self) -> KeyID {
        match self {
            &Fingerprint::V4(ref fp) =>
                KeyID::from_bytes(&fp[fp.len() - 8..]),
            &Fingerprint::Invalid(ref fp) => {
                if fp.len() < 8 {
                    KeyID::from_bytes(&[0; 8])
                } else {
                    KeyID::from_bytes(&fp[fp.len() - 8..])
                }
            }
        }
    }
}

/// Holds a KeyID.
///
/// A KeyID is a fingerprint fragment.  It identifies a public key,
/// but is easy to forge.  For more details about how a KeyID is
/// generated, see [Section 12.2 of RFC 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
#[derive(PartialEq)]
pub enum KeyID {
    V4([u8;8]),
    // Used for holding fingerprints that we don't understand.  For
    // instance, we don't grok v3 fingerprints.  And, it is possible
    // that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

impl fmt::Debug for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("KeyID")
            .field(&self.to_string())
            .finish()
    }
}

impl KeyID {
    /// Reads a binary key ID.
    pub fn from_bytes(raw: &[u8]) -> KeyID {
        if raw.len() == 8 {
            let mut keyid : [u8; 8] = Default::default();
            keyid.copy_from_slice(raw);
            KeyID::V4(keyid)
        } else {
            KeyID::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Converts the key ID to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the key ID to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &KeyID::V4(ref fp) => &fp[..],
            &KeyID::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 key IDs, which look like:
        //
        //   AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid key ID, just
        // format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
    }
}
