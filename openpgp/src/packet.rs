//! Packet-related types.
//!
//! See [Section 4 of RFC 4880] for more details.
//!
//!   [Section 4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4

use std::fmt;
use std::ops::{Deref,DerefMut};
use ctb::{CTB};
use Container;
use Packet;

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
            &Packet::UserAttribute(ref packet) => &packet.common,
            &Packet::Literal(ref packet) => &packet.common,
            &Packet::CompressedData(ref packet) => &packet.common,
            &Packet::SKESK(ref packet) => &packet.common,
            &Packet::SEIP(ref packet) => &packet.common,
            &Packet::MDC(ref packet) => &packet.common,
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
            &mut Packet::UserAttribute(ref mut packet) => &mut packet.common,
            &mut Packet::Literal(ref mut packet) => &mut packet.common,
            &mut Packet::CompressedData(ref mut packet) => &mut packet.common,
            &mut Packet::SKESK(ref mut packet) => &mut packet.common,
            &mut Packet::SEIP(ref mut packet) => &mut packet.common,
            &mut Packet::MDC(ref mut packet) => &mut packet.common,
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

impl fmt::Debug for PacketCommon {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
