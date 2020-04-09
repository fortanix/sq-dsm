use std::convert::TryFrom;
use std::io;
use std::path::Path;

use crate::{
    Result,
    Packet,
    PacketPile,
};
use crate::parse::{
    PacketParserBuilder,
    PacketParserResult,
    PacketParser,
    Parse,
    Cookie
};
use buffered_reader::BufferedReader;

/// A `PacketPileParser` parses an OpenPGP message with the convenience
/// of `PacketPile::from_file` and the flexibility of a `PacketParser`.
///
/// Like `PacketPile::from_file` (and unlike `PacketParser`), a
/// `PacketPileParser` parses an OpenPGP message and returns a `PacketPile`.
/// But, unlike `PacketPile::from_file` (and like `PacketParser`), it
/// allows the caller to inspect each packet as it is being parsed.
///
/// Thus, using a `PacketPileParser`, it is possible to decide on a
/// per-packet basis whether to stream, buffer or drop the packet's
/// body, whether to recurse into a container, or whether to abort
/// processing, for example.  And, `PacketPileParser` conveniently packs
/// the packets into a `PacketPile`.
///
/// If old packets don't need to be retained, then `PacketParser`
/// should be preferred.  If no per-packet processing needs to be
/// done, then `PacketPile::from_file` will be slightly faster.
///
/// # Examples
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketPileParser};
/// # let _ = f(include_bytes!("../../tests/data/keys/public-key.gpg"));
/// #
/// # fn f(message_data: &[u8]) -> Result<()> {
/// let mut ppp = PacketPileParser::from_bytes(message_data)?;
/// let mut ppr = ppp.recurse()?;
/// while let Some(pp) = ppr.as_ref() {
///     eprintln!("{:?}", pp);
///     ppr = ppp.recurse()?;
/// }
/// let message = ppp.finish();
/// message.pretty_print();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PacketPileParser<'a> {
    /// The current packet.
    ppr: PacketParserResult<'a>,

    /// Whether the first packet has been returned.
    returned_first: bool,

    /// The packet pile that has been assembled so far.
    pile: PacketPile,
}

impl<'a> TryFrom<PacketParserBuilder<'a>> for PacketPileParser<'a> {
    type Error = anyhow::Error;

    /// Finishes configuring the `PacketParser` and returns a
    /// `PacketPileParser`.
    fn try_from(ppb: PacketParserBuilder<'a>) -> Result<PacketPileParser<'a>> {
        Self::from_packet_parser(ppb.build()?)
    }
}

impl<'a> Parse<'a, PacketPileParser<'a>> for PacketPileParser<'a> {
    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the `io::Read` object.
    fn from_reader<R: io::Read + 'a>(reader: R)
             -> Result<PacketPileParser<'a>> {
        let bio = Box::new(buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default()));
        PacketPileParser::from_buffered_reader(bio)
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the file named by `path`.
    fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketPileParser<'a>> {
        PacketPileParser::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path, Cookie::default())?))
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the provided buffer.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D)
            -> Result<PacketPileParser<'a>> {
        let bio = Box::new(buffered_reader::Memory::with_cookie(
            data.as_ref(), Cookie::default()));
        PacketPileParser::from_buffered_reader(bio)
    }
}

impl<'a> PacketPileParser<'a> {
    /// Creates a `PacketPileParser` from a *fresh* `PacketParser`.
    fn from_packet_parser(ppr: PacketParserResult<'a>)
        -> Result<PacketPileParser<'a>>
    {
        Ok(PacketPileParser {
            pile: Default::default(),
            ppr: ppr,
            returned_first: false,
        })
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the `BufferedReader` object.
    pub(crate) fn from_buffered_reader(bio: Box<dyn BufferedReader<Cookie> + 'a>)
            -> Result<PacketPileParser<'a>> {
        Self::from_packet_parser(PacketParser::from_buffered_reader(bio)?)
    }

    /// Inserts the next packet into the `PacketPile`.
    fn insert_packet(&mut self, packet: Packet, position: isize) {
        // Find the right container.
        let mut container = self.pile.top_level_mut();

        assert!(position >= 0);

        for i in 0..position {
            // The most recent child.
            let tmp = container;
            let packets_len = tmp.children_ref().expect("is a container").len();
            let p = &mut tmp.children_mut()
                .expect("is a container")
                [packets_len - 1];
            if p.children().expect("is a container").next().is_none() {
                assert!(i == position - 1,
                        "Internal inconsistency while building message.");
            }

            container = p.container_mut().unwrap();
        }

        container.children_mut().unwrap().push(packet);
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.  This function recurses, if possible.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  It then creates a new
    /// packet parser for the next packet.  If the current packet is a
    /// container, this function tries to recurse into it.  Otherwise,
    /// it returns the following packet.
    pub fn recurse(&mut self) -> Result<&mut PacketParserResult<'a>> {
        if self.returned_first {
            match self.ppr.take() {
                PacketParserResult::Some(pp) => {
                    let (packet, ppr) = pp.recurse()?;
                    self.insert_packet(
                        packet,
                        ppr.last_recursion_depth().unwrap() as isize);
                    self.ppr = ppr;
                }
                eof @ PacketParserResult::EOF(_) => {
                    self.ppr = eof;
                }
            }
        } else {
            self.returned_first = true;
        }

        Ok(&mut self.ppr)
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.  This function does not recurse.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  It then creates a new
    /// packet parser for the following packet.  If the current packet
    /// is a container, this function does *not* recurse into the
    /// container; it skips any packets that it may contain.
    pub fn next(&mut self) -> Result<&mut PacketParserResult<'a>> {
        if self.returned_first {
            match self.ppr.take() {
                PacketParserResult::Some(pp) => {
                    let (packet, ppr) = pp.next()?;
                    self.insert_packet(
                        packet,
                        ppr.last_recursion_depth().unwrap() as isize);
                    self.ppr = ppr;
                },
                eof @ PacketParserResult::EOF(_) => {
                    self.ppr = eof
                },
            }
        } else {
            self.returned_first = true;
        }

        Ok(&mut self.ppr)
    }

    /// Returns the current packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1.  Etc.
    pub fn recursion_depth(&self) -> Option<u8> {
        if let PacketParserResult::Some(ref pp) = self.ppr {
            Some(pp.recursion_depth() as u8)
        } else {
            None
        }
    }

    /// Returns whether the message has been completely parsed.
    pub fn is_done(&self) -> bool {
        self.ppr.is_none()
    }

    /// Finishes parsing the message and returns the assembled
    /// `PacketPile`.
    ///
    /// This function can be called at any time, not only when the
    /// message has been completely parsed.  If the packet sequence has not
    /// been completely parsed, this function aborts processing, and
    /// the returned `PacketPile` just contains those packets that were
    /// completely processed; the packet that is currently being
    /// processed is not included in the `PacketPile`.
    pub fn finish(self) -> PacketPile {
        return self.pile;
    }
}

#[test]
fn test_recurse() -> Result<()> {
    let mut count = 0;
    let mut ppp =
        PacketPileParser::from_bytes(crate::tests::key("public-key.gpg"))?;
    let mut ppr = ppp.recurse().unwrap();
    while ppr.is_some() {
        count += 1;
        ppr = ppp.recurse().unwrap();
    }
    assert_eq!(count, 61);
    Ok(())
}

#[test]
fn test_next() -> Result<()> {
    let mut count = 0;
    let mut ppp =
        PacketPileParser::from_bytes(crate::tests::key("public-key.gpg"))?;
    let mut ppr = ppp.recurse().unwrap();
    while ppr.is_some() {
        count += 1;
        ppr = ppp.next().unwrap();
    }
    assert_eq!(count, 61);
    Ok(())
}

/// Check that we can use the read interface to stream the contents of
/// a packet.
#[cfg(feature = "compression-deflate")]
#[test]
fn message_parser_reader_interface() {
    use std::io::Read;

    let expected = crate::tests::manifesto();

    // A message containing a compressed packet that contains a
    // literal packet.
    let mut ppp = PacketPileParser::from_bytes(
        crate::tests::message("compressed-data-algo-1.gpg")).unwrap();
    let mut count = 0;
    let mut ppr = ppp.recurse().unwrap();
    while let Some(pp) = ppr.as_mut() {
        count += 1;
        if let Packet::Literal(_) = pp.packet {
            assert_eq!(count, 2);

            // Check that we can read the packet's contents.  We do this one
            // byte at a time to exercise the cursor implementation.
            for i in 0..expected.len() {
                let mut buf = [0u8; 1];
                let r = pp.read(&mut buf).unwrap();
                assert_eq!(r, 1);
                assert_eq!(buf[0], expected[i]);
            }
            // And, now an EOF.
            let mut buf = [0u8; 1];
            let r = pp.read(&mut buf).unwrap();
            assert_eq!(r, 0);
        }
        ppr = ppp.recurse().unwrap();
    }
    assert_eq!(count, 2);
}
