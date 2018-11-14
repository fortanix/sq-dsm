//! Packet-related types.
//!
//! See [Section 4 of RFC 4880] for more details.
//!
//!   [Section 4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::vec;
use std::io;

use Result;
use Packet;

pub mod ctb;
use self::ctb::{CTB, PacketLengthType};

use buffered_reader::BufferedReader;

mod tag;
pub use self::tag::Tag;

mod unknown;
pub use self::unknown::Unknown;
pub mod signature;
pub use self::signature::Signature;
mod one_pass_sig;
pub use self::one_pass_sig::OnePassSig;
pub(crate) mod key;
pub use self::key::Key;
mod userid;
pub use self::userid::UserID;
mod user_attribute;
pub use self::user_attribute::UserAttribute;
mod literal;
pub use self::literal::Literal;
mod compressed_data;
pub use self::compressed_data::CompressedData;
mod seip;
pub use self::seip::SEIP;
mod skesk;
pub use self::skesk::{SKESK, SKESK4, SKESK5};
mod pkesk;
pub use self::pkesk::PKESK;
mod mdc;
pub use self::mdc::MDC;
mod aed;
pub use self::aed::AED;

// Allow transparent access of common fields.
impl<'a> Deref for Packet {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        match self {
            &Packet::Unknown(ref packet) => &packet.common,
            &Packet::Signature(ref packet) => &packet.common,
            &Packet::OnePassSig(ref packet) => &packet.common,
            &Packet::PublicKey(ref packet) => &packet.common,
            &Packet::PublicSubkey(ref packet) => &packet.common,
            &Packet::SecretKey(ref packet) => &packet.common,
            &Packet::SecretSubkey(ref packet) => &packet.common,
            &Packet::UserID(ref packet) => &packet.common,
            &Packet::UserAttribute(ref packet) => &packet.common,
            &Packet::Literal(ref packet) => &packet.common,
            &Packet::CompressedData(ref packet) => &packet.common,
            &Packet::PKESK(ref packet) => &packet.common,
            &Packet::SKESK(SKESK::V4(ref packet)) => &packet.common,
            &Packet::SKESK(SKESK::V5(ref packet)) => &packet.skesk4.common,
            &Packet::SEIP(ref packet) => &packet.common,
            &Packet::MDC(ref packet) => &packet.common,
            &Packet::AED(ref packet) => &packet.common,
        }
    }
}

impl<'a> DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut Common {
        match self {
            &mut Packet::Unknown(ref mut packet) => &mut packet.common,
            &mut Packet::Signature(ref mut packet) => &mut packet.common,
            &mut Packet::OnePassSig(ref mut packet) => &mut packet.common,
            &mut Packet::PublicKey(ref mut packet) => &mut packet.common,
            &mut Packet::PublicSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretKey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::UserID(ref mut packet) => &mut packet.common,
            &mut Packet::UserAttribute(ref mut packet) => &mut packet.common,
            &mut Packet::Literal(ref mut packet) => &mut packet.common,
            &mut Packet::CompressedData(ref mut packet) => &mut packet.common,
            &mut Packet::PKESK(ref mut packet) => &mut packet.common,
            &mut Packet::SKESK(SKESK::V4(ref mut packet)) => &mut packet.common,
            &mut Packet::SKESK(SKESK::V5(ref mut packet)) => &mut packet.skesk4.common,
            &mut Packet::SEIP(ref mut packet) => &mut packet.common,
            &mut Packet::MDC(ref mut packet) => &mut packet.common,
            &mut Packet::AED(ref mut packet) => &mut packet.common,
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
#[derive(Debug)]
// We need PartialEq so that assert_eq! works.
#[derive(PartialEq)]
#[derive(Clone, Copy)]
pub enum BodyLength {
    /// Packet size is fully known.
    Full(u32),
    /// The parameter is the number of bytes in the current chunk.
    /// This type is only used with new format packets.
    Partial(u32),
    /// The packet extends until an EOF is encountered.  This type is
    /// only used with old format packets.
    Indeterminate,
}

impl BodyLength {
    /// Decodes a new format body length as described in [Section
    /// 4.2.2 of RFC 4880].
    ///
    ///   [Section 4.2.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.2
    pub(crate) fn parse_new_format<T: BufferedReader<C>, C> (bio: &mut T)
        -> io::Result<BodyLength>
    {
        let octet1 : u8 = bio.data_consume_hard(1)?[0];
        match octet1 {
            0...191 => // One octet.
                Ok(BodyLength::Full(octet1 as u32)),
            192...223 => { // Two octets length.
                let octet2 = bio.data_consume_hard(1)?[0];
                Ok(BodyLength::Full(((octet1 as u32 - 192) << 8)
                                    + octet2 as u32 + 192))
            },
            224...254 => // Partial body length.
                Ok(BodyLength::Partial(1 << (octet1 & 0x1F))),
            255 => // Five octets.
                Ok(BodyLength::Full(bio.read_be_u32()?)),
            _ =>
                // The rust compiler doesn't yet check whether an
                // integer is covered.
                //
                // https://github.com/rust-lang/rfcs/issues/1550
                unreachable!(),
        }
    }

    /// Decodes an old format body length as described in [Section
    /// 4.2.1 of RFC 4880].
    ///
    ///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
    pub(crate) fn parse_old_format<T: BufferedReader<C>, C>
        (bio: &mut T, length_type: PacketLengthType)
         -> Result<BodyLength>
    {
        match length_type {
            PacketLengthType::OneOctet =>
                Ok(BodyLength::Full(bio.data_consume_hard(1)?[0] as u32)),
            PacketLengthType::TwoOctets =>
                Ok(BodyLength::Full(bio.read_be_u16()? as u32)),
            PacketLengthType::FourOctets =>
                Ok(BodyLength::Full(bio.read_be_u32()? as u32)),
            PacketLengthType::Indeterminate =>
                Ok(BodyLength::Indeterminate),
        }
    }
}

#[test]
fn body_length_new_format() {
    use buffered_reader::BufferedReaderMemory;

    fn test(input: &[u8], expected_result: BodyLength) {
        assert_eq!(
            BodyLength::parse_new_format(
                &mut BufferedReaderMemory::new(input)).unwrap(),
            expected_result);
    }

    // Examples from Section 4.2.3 of RFC4880.

    // Example #1.
    test(&[0x64][..], BodyLength::Full(100));

    // Example #2.
    test(&[0xC5, 0xFB][..], BodyLength::Full(1723));

    // Example #3.
    test(&[0xFF, 0x00, 0x01, 0x86, 0xA0][..], BodyLength::Full(100000));

    // Example #4.
    test(&[0xEF][..], BodyLength::Partial(32768));
    test(&[0xE1][..], BodyLength::Partial(2));
    test(&[0xF0][..], BodyLength::Partial(65536));
    test(&[0xC5, 0xDD][..], BodyLength::Full(1693));
}

#[test]
fn body_length_old_format() {
    use buffered_reader::BufferedReaderMemory;

    fn test(input: &[u8], plt: PacketLengthType,
            expected_result: BodyLength, expected_rest: &[u8]) {
        let mut bio = BufferedReaderMemory::new(input);
        assert_eq!(BodyLength::parse_old_format(&mut bio, plt).unwrap(),
                   expected_result);
        let rest = bio.data_eof();
        assert_eq!(rest.unwrap(), expected_rest);
    }

    test(&[1], PacketLengthType::OneOctet, BodyLength::Full(1), &b""[..]);
    test(&[1, 2], PacketLengthType::TwoOctets,
         BodyLength::Full((1 << 8) + 2), &b""[..]);
    test(&[1, 2, 3, 4], PacketLengthType::FourOctets,
         BodyLength::Full((1 << 24) + (2 << 16) + (3 << 8) + 4), &b""[..]);
    test(&[1, 2, 3, 4, 5, 6], PacketLengthType::FourOctets,
         BodyLength::Full((1 << 24) + (2 << 16) + (3 << 8) + 4), &[5, 6][..]);
    test(&[1, 2, 3, 4], PacketLengthType::Indeterminate,
         BodyLength::Indeterminate, &[1, 2, 3, 4][..]);
}

/// Fields used by multiple packet types.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Common {
    /// Used by container packets (such as the encryption and
    /// compression packets) to reference their immediate children.
    /// This results in a tree structure.
    ///
    /// This is automatically populated when using the `PacketPile`
    /// deserialization routines, e.g., [`PacketPile::from_file`].  By
    /// default, it is *not* automatically filled in by the
    /// [`PacketParser`] deserialization routines; this needs to be
    /// done manually.
    ///
    ///   [`PacketPile`]: ../struct.PacketPile.html
    ///   [`PacketPile::from_file`]: ../struct.PacketPile.html#method.from_file
    ///   [`PacketParser`]: ../parse/struct.PacketParser.html
    pub children: Option<Container>,

    /// Holds a packet's body.
    ///
    /// We conceptually divide packets into two parts: the header and
    /// the body.  Whereas the header is read eagerly when the packet
    /// is deserialized, the body is only read on demand.
    ///
    /// A packet's body is stored here either when configured via
    /// [`PacketParserBuilder::buffer_unread_content`], when one of
    /// the [`PacketPile`] deserialization routines is used, or on demand
    /// for a particular packet using the
    /// [`PacketParser::buffer_unread_content`] method.
    ///
    ///   [`PacketParserBuilder::buffer_unread_content`]: ../parse/struct.PacketParserBuilder.html#method.buffer_unread_content
    ///   [`PacketPile`]: ../struct.PacketPile.html
    ///   [`PacketParser::buffer_unread_content`]: ../parse/struct.PacketParser.html#method.buffer_unread_content
    ///
    /// There are three different types of packets:
    ///
    ///   - Packets like the [`UserID`] and [`Signature`] packets,
    ///     don't actually have a body.  These packets don't use this
    ///     field.
    ///
    ///   [`UserID`]: ../packet/struct.UserID.html
    ///   [`Signature`]: ../packet/struct.Signature.html
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
    ///   [`PacketParser::next`]: ../parse/struct.PacketParser.html#method.next
    ///
    /// Note: if some of a packet's data is processed, and the
    /// `PacketParser` is configured to buffer unread content, then
    /// this is not the packet's entire content; it is just the unread
    /// content.
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for Common {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Common")
            .field("children", &self.children)
            .field("body (bytes)",
                   &self.body.as_ref().map(|body| body.len()))
            .finish()
    }
}

impl Default for Common {
    fn default() -> Common {
        Common {
            children: None,
            body: None,
        }
    }
}

impl Common {
    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub fn descendants(&self) -> PacketIter {
        return PacketIter {
            children: if let Some(ref container) = self.children {
                container.packets.iter()
            } else {
                let empty_packet_slice : &[Packet] = &[];
                empty_packet_slice.iter()
            },
            child: None,
            grandchildren: None,
            depth: 0,
        }
    }

    /// Retrieves the packet's body.
    ///
    /// Packets can store a sequence of bytes as body, e.g. if the
    /// maximum recursion level is reached while parsing a sequence of
    /// packets, the container's body is stored as is.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_ref().map(|b| b.as_slice())
    }

    /// Sets the packet's body.
    ///
    /// Setting the body clears the old body, or any of the packet's
    /// descendants.
    pub fn set_body(&mut self, data: Vec<u8>) {
        self.children = None;
        self.body = Some(data);
    }
}

/// An OpenPGP packet's header.
#[derive(Clone, Debug)]
pub struct Header {
    /// The packet's CTB.
    pub ctb: CTB,
    /// The packet's length.
    pub length: BodyLength,
}

impl Header {
    /// Parses an OpenPGP packet's header as described in [Section 4.2
    /// of RFC 4880].
    ///
    ///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
    pub(crate) fn parse<R: BufferedReader<C>, C> (bio: &mut R)
        -> Result<Header>
    {
        let ctb = CTB::from_ptag(bio.data_consume_hard(1)?[0])?;
        let length = match ctb {
            CTB::New(_) => BodyLength::parse_new_format(bio)?,
            CTB::Old(ref ctb) =>
                BodyLength::parse_old_format(bio, ctb.length_type)?,
        };
        return Ok(Header { ctb: ctb, length: length });
    }
}

/// Holds zero or more OpenPGP packets.
///
/// This is used by OpenPGP container packets, like the compressed
/// data packet, to store the containing packets.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Container {
    pub(crate) packets: Vec<Packet>,
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Container")
            .field("packets", &self.packets)
            .finish()
    }
}

impl Container {
    pub(crate) fn new() -> Container {
        Container { packets: Vec::with_capacity(8) }
    }

    // Adds a new packet to the container.
    pub(crate) fn push(&mut self, packet: Packet) {
        self.packets.push(packet);
    }

    // Inserts a new packet to the container at a particular index.
    // If `i` is 0, the new packet is insert at the front of the
    // container.  If `i` is one, it is inserted after the first
    // packet, etc.
    pub(crate) fn insert(&mut self, i: usize, packet: Packet) {
        self.packets.insert(i, packet);
    }

    /// Returns an iterator over the packet's descendants.  The
    /// descendants are visited in depth-first order.
    pub fn descendants(&self) -> PacketIter {
        return PacketIter {
            // Iterate over each packet in the message.
            children: self.children(),
            child: None,
            grandchildren: None,
            depth: 0,
        };
    }

    /// Returns an iterator over the packet's immediate children.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.packets.iter()
    }

    /// Returns an `IntoIter` over the packet's immediate children.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.packets.into_iter()
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
    pub(crate) fn pretty_print(&self, indent: usize) {
        for (i, p) in self.packets.iter().enumerate() {
            eprintln!("{}{}: {:?}",
                      Self::indent(indent), i + 1, p);
            if let Some(ref children) = self.packets[i].children {
                children.pretty_print(indent + 1);
            }
        }
    }
}

/// A `PacketIter` iterates over the *contents* of a packet in
/// depth-first order.  It starts by returning the current packet.
pub struct PacketIter<'a> {
    // An iterator over the current message's children.
    children: slice::Iter<'a, Packet>,
    // The current child (i.e., the last value returned by
    // children.next()).
    child: Option<&'a Packet>,
    // The an iterator over the current child's children.
    grandchildren: Option<Box<PacketIter<'a>>>,

    // The depth of the last returned packet.  This is used by the
    // `paths` iter.
    depth: usize,
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
                self.depth = grandchildren.depth + 1;
                return grandchild;
            }
        }

        // Get the next child and the iterator for its children.
        self.child = self.children.next();
        if let Some(child) = self.child {
            self.grandchildren = Some(Box::new(child.descendants()));
        }

        // First return the child itself.  Subsequent calls will
        // return its grandchildren.
        self.depth = 0;
        return self.child;
    }
}

impl<'a> PacketIter<'a> {
    /// Extends a `PacketIter` to also return each packet's path.
    ///
    /// This is similar to `enumerate`, but instead of counting, this
    /// returns each packet's path in addition to a reference to the
    /// packet.
    pub fn paths(self) -> PacketPathIter<'a> {
        PacketPathIter {
            iter: self,
            path: None,
        }
    }
}


/// Like `enumerate`, this augments the packet returned by a
/// `PacketIter` with its `Path`.
pub struct PacketPathIter<'a> {
    iter: PacketIter<'a>,

    // The path to the most recently returned node relative to the
    // start of the iterator.
    path: Option<Vec<usize>>,
}

impl<'a> Iterator for PacketPathIter<'a> {
    type Item = (Vec<usize>, &'a Packet);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(packet) = self.iter.next() {
            if self.path.is_none() {
                // Init.
                let mut path = Vec::with_capacity(4);
                path.push(0);
                self.path = Some(path);
            } else {
                let mut path = self.path.take().unwrap();
                let old_depth = path.len() - 1;

                let depth = self.iter.depth;
                if old_depth > depth {
                    // We popped.
                    path.truncate(depth + 1);
                    path[depth] += 1;
                } else if old_depth == depth {
                    // Sibling.
                    path[old_depth] += 1;
                } else if old_depth + 1 == depth {
                    // Recursion.
                    path.push(0);
                }
                self.path = Some(path);
            }
            Some((self.path.as_ref().unwrap().clone(), packet))
        } else {
            None
        }
    }
}

// Tests the `paths`() iter and `path_ref`().
#[test]
fn packet_path_iter() {
    use std::path::PathBuf;

    use PacketPile;

    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
            .iter().collect()
    }

    fn paths(iter: slice::Iter<Packet>) -> Vec<Vec<usize>> {
        let mut lpaths : Vec<Vec<usize>> = Vec::new();
        for (i, packet) in iter.enumerate() {
            let mut v = Vec::new();
            v.push(i);
            lpaths.push(v);

            if let Some(ref children) = packet.children {
                for mut path in paths(children.packets.iter()).into_iter() {
                    path.insert(0, i);
                    lpaths.push(path);
                }
            }
        }
        lpaths
    }

    for i in 1..5 {
        let pile = PacketPile::from_file(
            path_to(&format!("recursive-{}.gpg", i)[..])).unwrap();

        let mut paths1 : Vec<Vec<usize>> = Vec::new();
        for path in paths(pile.children()).iter() {
            paths1.push(path.clone());
        }

        let mut paths2 : Vec<Vec<usize>> = Vec::new();
        for (path, packet) in pile.descendants().paths() {
            assert_eq!(Some(packet), pile.path_ref(&path[..]));
            paths2.push(path);
        }

        if paths1 != paths2 {
            eprintln!("PacketPile:");
            pile.pretty_print();

            eprintln!("Expected paths:");
            for p in paths1 {
                eprintln!("  {:?}", p);
            }

            eprintln!("Got paths:");
            for p in paths2 {
                eprintln!("  {:?}", p);
            }

            panic!("Something is broken.  Don't panic.");
        }
    }
}
