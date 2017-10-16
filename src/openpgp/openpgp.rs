// Machinery for parsing and serializing OpenPGP packet headers.

use std::ops::Deref;

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
    Compressed = 8,
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
    tag: Tag,
}

#[derive(Debug)]
pub struct CTBNew {
    common: CTBCommon,
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
    common: CTBCommon,
    length_type: PacketLengthType,
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
pub enum BodyLength {
    Full(u32),
    /* The size parameter is the size of the initial block.  */
    Partial(u32),
    Indeterminate,
}

#[derive(Debug)]
pub struct PacketCommon {
    tag: Tag,
}

/// An OpenPGP packet's header.
#[derive(Debug)]
pub struct Header {
    ctb: CTB,
    length: BodyLength,
}

#[derive(Debug)]
pub struct Signature<'a> {
    common: PacketCommon,
    version: u8,
    sigtype: u8,
    pk_algo: u8,
    hash_algo: u8,
    hashed_area: &'a[u8],
    unhashed_area: &'a[u8],
    hash_prefix: [u8; 2],
    mpis: &'a[u8],
}

// Allow transparent access of common fields.
impl<'a> Deref for Signature<'a> {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug)]
pub struct Key<'a> {
    common: PacketCommon,
    version: u8,
    /* When the key was created.  */
    creation_time: u32,
    pk_algo: u8,
    mpis: &'a [u8],
}

// Allow transparent access of common fields.
impl<'a> Deref for Key<'a> {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug)]
pub struct UserID<'a> {
    common: PacketCommon,
    value: &'a [u8],
}

// Allow transparent access of common fields.
impl<'a> Deref for UserID<'a> {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug)]
pub struct Literal<'a> {
    common: PacketCommon,
    format: u8,
    /* filename is a string, but strings in Rust are valid UTF-8.
     * But, there is no guarantee that the filename is valid UTF-8.
     * Thus, we leave filename as a byte array.  It can be converted
     * to a string using String::from_utf8() or
     * String::from_utf8_lossy(). */
    filename: &'a [u8],
    date: u32,
    content: &'a [u8],
}

// Allow transparent access of common fields.
impl<'a> Deref for Literal<'a> {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    Signature(Signature<'a>),
    PublicKey(Key<'a>),
    PublicSubkey(Key<'a>),
    SecretKey(Key<'a>),
    SecretSubkey(Key<'a>),
    UserID(UserID<'a>),
    Literal(Literal<'a>),
}

// Allow transparent access of common fields.
impl<'a> Deref for Packet<'a> {
    type Target = PacketCommon;

    fn deref(&self) -> &Self::Target {
        match self {
            &Packet::Signature(ref packet) => &packet.common,
            &Packet::Literal(ref packet) => &packet.common,
            _ => unimplemented!(),
        }
    }
}
