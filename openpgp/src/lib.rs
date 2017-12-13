//! OpenPGP data types and machinery.

extern crate buffered_reader;

// For #[derive(FromPrimitive)]
extern crate num;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate nom;

extern crate sha1;

pub mod armor;
pub mod parse;
pub mod tpk;
pub mod types;
pub mod partial_body;

use std::ops::{Deref,DerefMut};

use std::cell::RefCell;
use std::collections::HashMap;

mod subpackets;

/// The OpenPGP packet types.  The values correspond to the serialized
/// format.  The packet types named UnassignedXX are not in use as of
/// RFC 4880.
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
    OnePassSig,
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

/// OpenPGP defines two packet formats: the old and the new format.
/// They both include the packet's so-called tag.
#[derive(Debug)]
pub struct CTBCommon {
    pub tag: Tag,
}

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

#[derive(Debug)]
#[derive(FromPrimitive)]
#[derive(Clone, Copy)]
pub enum PacketLengthType {
    OneOctet = 0,
    TwoOctets = 1,
    FourOctets = 2,
    Indeterminate = 3,
}

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

/// The size of a packet.  If Partial(x), then x indicates the number
/// of bytes remaining in the current chunk.  The chunk is followed by
/// another new format length header, which can be read using
/// body_length_new_format().  If Indeterminate, then the packet
/// continues until the end of the input.
#[derive(Debug)]
// We need PartialEq so that assert_eq! works.
#[derive(PartialEq)]
#[derive(Clone, Copy)]
pub enum BodyLength {
    Full(u32),
    /* The size parameter is the size of the initial block.  */
    Partial(u32),
    Indeterminate,
}

#[derive(PartialEq)]
pub struct PacketCommon {
    pub children: Option<Container>,
    pub content: Option<Vec<u8>>,
}

impl std::fmt::Debug for PacketCommon {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("children", &self.children)
            .field("content (bytes)",
                   &self.content.as_ref().map(|content| content.len()))
            .finish()
    }
}

/// An OpenPGP packet's header.
#[derive(Debug)]
pub struct Header {
    pub ctb: CTB,
    pub length: BodyLength,
}

#[derive(PartialEq,Debug)]
pub struct Unknown {
    pub common: PacketCommon,
    pub tag: Tag,
}

#[derive(PartialEq)]
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
    pub hash_prefix: [u8; 2],
    pub mpis: Vec<u8>,
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hashed_area = format!("{} bytes", self.hashed_area.len());
        let unhashed_area = format!("{} bytes", self.unhashed_area.len());
        let mpis = format!("{} bytes", self.mpis.len());

        f.debug_struct("Signature")
            .field("version", &self.version)
            .field("sigtype", &self.sigtype)
            .field("pk_algo", &self.pk_algo)
            .field("hash_algo", &self.hash_algo)
            .field("hashed_area", &hashed_area)
            .field("unhashed_area", &unhashed_area)
            .field("hash_prefix", &self.hash_prefix)
            .field("mpis", &mpis)
            .finish()
    }
}

#[derive(PartialEq)]
pub struct Key {
    pub common: PacketCommon,
    pub version: u8,
    /* When the key was created.  */
    pub creation_time: u32,
    pub pk_algo: u8,
    pub mpis: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mpis = format!("{} bytes", self.mpis.len());

        f.debug_struct("Key")
            .field("version", &self.version)
            .field("creation_time", &self.creation_time)
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &mpis)
            .finish()
    }
}

#[derive(PartialEq)]
pub struct UserID {
    pub common: PacketCommon,
    pub value: Vec<u8>,
}

impl std::fmt::Debug for UserID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);

        f.debug_struct("UserID")
            .field("value", &userid)
            .finish()
    }
}

#[derive(PartialEq)]
pub struct Literal {
    pub common: PacketCommon,
    pub format: u8,
    // filename is a string, but strings in Rust are valid UTF-8.
    // There is no guarantee, however, that the filename is valid
    // UTF-8.  Thus, we leave filename as a byte array.  It can be
    // converted to a string using String::from_utf8() or
    // String::from_utf8_lossy().
    pub filename: Option<Vec<u8>>,
    pub date: u32,
}

impl std::fmt::Debug for Literal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let filename = if let Some(ref filename) = self.filename {
            Some(String::from_utf8_lossy(filename))
        } else {
            None
        };

        let content = if let Some(ref content) = self.common.content {
            &content[..]
        } else {
            &b""[..]
        };

        let threshold = 36;
        let prefix =
            &content[..std::cmp::min(threshold, content.len())];
        let mut prefix_fmt = String::from_utf8_lossy(prefix).into_owned();
        if content.len() > threshold {
            prefix_fmt.push_str("...");
        }
        prefix_fmt.push_str(&format!(" ({} bytes)", content.len())[..]);

        f.debug_struct("Literal")
            .field("format", &(self.format as char))
            .field("filename", &filename)
            .field("date", &self.date)
            .field("content", &prefix_fmt)
            .finish()
    }
}

#[derive(PartialEq)]
pub struct CompressedData {
    pub common: PacketCommon,
    pub algo: u8,
}

impl std::fmt::Debug for CompressedData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("CompressedData")
            .field("algo", &self.algo)
            .finish()
    }
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Packet {
    Unknown(Unknown),
    Signature(Signature),
    PublicKey(Key),
    PublicSubkey(Key),
    SecretKey(Key),
    SecretSubkey(Key),
    UserID(UserID),
    Literal(Literal),
    CompressedData(CompressedData),
}

// Allow transparent access of common fields.
impl<'a> Deref for Packet {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        match self {
            &Packet::Unknown(ref packet) => &packet.common,
            &Packet::Signature(ref packet) => &packet.common,
            &Packet::PublicKey(ref packet) => &packet.common,
            &Packet::PublicSubkey(ref packet) => &packet.common,
            &Packet::SecretKey(ref packet) => &packet.common,
            &Packet::SecretSubkey(ref packet) => &packet.common,
            &Packet::UserID(ref packet) => &packet.common,
            &Packet::Literal(ref packet) => &packet.common,
            &Packet::CompressedData(ref packet) => &packet.common,
        }
    }
}

impl<'a> DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut PacketCommon {
        match self {
            &mut Packet::Unknown(ref mut packet) => &mut packet.common,
            &mut Packet::Signature(ref mut packet) => &mut packet.common,
            &mut Packet::PublicKey(ref mut packet) => &mut packet.common,
            &mut Packet::PublicSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretKey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::UserID(ref mut packet) => &mut packet.common,
            &mut Packet::Literal(ref mut packet) => &mut packet.common,
            &mut Packet::CompressedData(ref mut packet) => &mut packet.common,
        }
    }
}

/// A `Container` is a container that holds zero or more OpenPGP
/// packets.  This is used both as a top-level for an OpenPGP message
/// as well as by Packets that are containers (like a compressed data
/// packet).
#[derive(PartialEq)]
pub struct Container {
    pub packets: Vec<Packet>,
}

impl std::fmt::Debug for Container {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Container")
            .field("packets", &self.packets)
            .finish()
    }
}

/// A `Message` holds a deserialized OpenPGP message.
pub struct Message {
    // At the top level, we have a sequence of packets, which may be
    // containers.
    pub packets: Vec<Packet>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("packets", &self.packets)
            .finish()
    }
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
}

impl Message {
    pub fn from_packets(p: Vec<Packet>) -> Self {
        Message { packets: p }
    }

    pub fn iter(&self) -> PacketIter {
        return PacketIter {
            // Iterate over each packet in the message.
            children: self.packets.iter(),
            child: None,
            grandchildren: None,
        };
    }

    pub fn into_iter(self) -> std::vec::IntoIter<Packet> {
        self.packets.into_iter()
    }
}

impl Packet {
    pub fn iter(&self) -> PacketIter {
        match self {
            &Packet::CompressedData(ref cd) => return cd.iter(),
            // The rest of the packets aren't containers.
            _ => {
                let empty_packet_slice : &[Packet] = &[][..];
                return PacketIter {
                    children: empty_packet_slice.iter(),
                    child: None,
                    grandchildren: None,
                }
            },
        }
    }
}

impl CompressedData {
    pub fn iter(&self) -> PacketIter {
        return PacketIter {
            children: if let Some(ref container) = self.common.children {
                container.packets.iter()
            } else {
                let empty_packet_slice : &[Packet] = &[][..];
                empty_packet_slice.iter()
            },
            child: None,
            grandchildren: None,
        }
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = &'a Packet;

    fn next(&mut self) -> Option<Self::Item> {
        // If we don't have a grandchild iterator (self.grandchildren
        // is None), then we are just starting, and we need to get the
        // next child.
        if let Some(ref mut grandchildren) = self.grandchildren {
            let grandchild = grandchildren.next();
            // If the grandchild iterator is exhausted (grandchild is
            // None), then we need the next child.
            if grandchild.is_some() {
                return grandchild;
            }
        }

        // Get the next child and the iterator for its children.
        self.child = self.children.next();
        if let Some(child) = self.child {
            self.grandchildren = Some(Box::new(child.iter()));
        }

        // First return the child itself.  Subsequent calls will
        // return its grandchildren.
        return self.child;
    }
}

pub enum Fingerprint {
    V4([u8;20]),
    // Used for holding fingerprints that we don't understand.  For
    // instance, we don't grok v3 fingerprints.  And, it is possible
    // that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
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

    // Converts the fingerprint to its standard representation.
    pub fn to_string(&self) -> String {
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
            // Every 2 bytes of output, we insert a space.
            + raw.len() / 2
            // After 5 groups, there is another space.
            + raw.len() / 10);

        for (i, b) in raw.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            if i > 0 && i % 10 == 0 {
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
