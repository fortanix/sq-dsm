use std::io;
use std::fs::File;
use std::path::Path;

use super::{PacketParserBuilder, PacketParser, Packet, Container, Message,
            BufferedReaderState};
use buffered_reader::{BufferedReader, BufferedReaderGeneric,
                      BufferedReaderMemory};

#[cfg(test)]
macro_rules! bytes {
    ( $x:expr ) => { include_bytes!(concat!("../../tests/data/messages/", $x)) };
}

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

/// A `MessageParser` parses an OpenPGP message with the convenience
/// of `Message::from_file` and the flexibility of a `PacketParser`.
///
/// Like `Message::from_file` (and unlike `PacketParser`), a
/// `MessageParser` parses an OpenPGP message and returns a `Message`.
/// But, unlike `Message::from_file` (and like `PacketParser`), it
/// allows the caller to inspect each packet as it is being parsed.
///
/// Thus, using a `MessageParser`, it is possible to decide on a
/// per-packet basis whether to stream, buffer or drop the packet's
/// body, whether to recurse into a container, or whether to abort
/// processing, for example.  And, `MessageParser` conveniently packs
/// the packets into a `Message`.
///
/// If old packets don't need to be retained, then `PacketParser`
/// should be preferred.  If no per-packet processing needs to be
/// done, then `Message::from_file` will be slightly faster.
///
/// Note: due to how lifetimes interact, it is not possible for the
/// [`next()`] and [`recurse()`] methods to return a mutable reference
/// to the packet (`&mut Packet`) that is currently being processed
/// while continuing to support streaming operations.  It is also not
/// possible to return a mutable reference to the `PacketParser`.
/// Thus, we expose the `Option<PacketParser>` directly to the user.
/// *However*, do *not* directly call `PacketParser::next()` or
/// `PacketParser::recurse()`.  This will break the `MessageParser`
/// implementation.
///
///   [`next()`]: #method.next
///   [`recurse()`]: #method.recurse
///
/// # Examples
///
/// ```rust
/// # use openpgp::parse::MessageParser;
/// # let _ = f(include_bytes!("../../tests/data/messages/public-key.gpg"));
/// #
/// # fn f(message_data: &[u8]) -> Result<(), std::io::Error> {
/// let mut mp = MessageParser::from_bytes(message_data)?;
/// while mp.recurse() {
///     let pp = mp.ppo.as_mut().unwrap();
///     eprintln!("{:?}", pp);
/// }
/// let message = mp.finish();
/// message.pretty_print();
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MessageParser<'a> {
    // The current packet.
    pub ppo: Option<PacketParser<'a>>,

    // Whether the first packet has been returned.
    returned_first: bool,

    // The message that has be assembled so far.
    message: Message,
}

impl<R: BufferedReader<BufferedReaderState>> PacketParserBuilder<R> {
    /// Finishes configuring the `PacketParser` and returns a
    /// `MessageParser`.
    pub fn to_message_parser<'a>(self)
            -> Result<MessageParser<'a>, io::Error>
            where Self: 'a {
        MessageParser::from_packet_parser(self.finalize()?)
    }
}

impl<'a> MessageParser<'a> {
    // Creates a `MessageParser` from a *fresh* `PacketParser`.
    fn from_packet_parser(ppo: Option<PacketParser<'a>>)
            -> Result<MessageParser<'a>, io::Error> {
        Ok(MessageParser {
            message: Message { top_level: Container::new() },
            ppo: ppo,
            returned_first: false,
        })
    }

    /// Creates a `MessageParser` to parse the OpenPGP message stored
    /// in the `BufferedReader` object.
    pub fn from_buffered_reader<R: BufferedReader<BufferedReaderState> + 'a>(bio: R)
            -> Result<MessageParser<'a>, io::Error> {
        Self::from_packet_parser(PacketParser::from_buffered_reader(bio)?)
    }

    /// Creates a `MessageParser` to parse the OpenPGP message stored
    /// in the `io::Read` object.
    pub fn from_reader<R: io::Read + 'a>(reader: R)
             -> Result<MessageParser<'a>, io::Error> {
        let bio = BufferedReaderGeneric::with_cookie(
            reader, None, BufferedReaderState::default());
        MessageParser::from_buffered_reader(bio)
    }

    /// Creates a `MessageParser` to parse the OpenPGP message stored
    /// in the file named by `path`.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<MessageParser<'a>, io::Error> {
        MessageParser::from_reader(File::open(path)?)
    }

    /// Creates a `MessageParser` to parse the OpenPGP message stored
    /// in the provided buffer.
    pub fn from_bytes(data: &'a [u8])
            -> Result<MessageParser<'a>, io::Error> {
        let bio = BufferedReaderMemory::with_cookie(
            data, BufferedReaderState::default());
        MessageParser::from_buffered_reader(bio)
    }

    // Inserts the next packet into the `Message`.
    fn insert_packet(&mut self, packet: Packet, position: isize) {
        // Find the right container.
        let mut container = &mut self.message.top_level;

        assert!(position >= 0);

        for i in 0..position {
            // The most recent child.
            let tmp = container;
            let packets_len = tmp.packets.len();
            let p = &mut tmp.packets[packets_len - 1];
            if p.children.is_none() {
                if i == position - 1 {
                    // This is the leaf.  Create a new container
                    // here.
                    p.children = Some(Container::new());
                } else {
                    panic!("Internal inconsistency while building message.");
                }
            }

            container = p.children.as_mut().unwrap();
        }

        container.packets.push(packet);
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.  This function recurses, if possible.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  It then creates a new
    /// packet parser for the next packet.  If the current packet is a
    /// container, this function tries to recurse into it.  Otherwise,
    /// it returns the following packet.
    ///
    /// Due to lifetime issues, this function does not return a
    /// reference to the `PacketParser`, but a boolean indicating
    /// whether a new packet is available.  Instead, the
    /// `PacketParser` can be accessed as `self.ppo`.
    pub fn recurse(&mut self) -> bool {
        if self.returned_first {
            match self.ppo.take() {
                Some (pp) => {
                    match pp.recurse() {
                        Ok((packet, position, ppo, _)) => {
                            self.insert_packet(packet, position);
                            self.ppo = ppo;
                        },
                        Err(_) => {
                            self.ppo = None;
                        }
                    }
                },
                None => {},
            }
        } else {
            self.returned_first = true;
        }

        !self.is_done()
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.  This function does not recurse.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  It then creates a new
    /// packet parser for the following packet.  If the current packet
    /// is a container, this function does *not* recurse into the
    /// container; it skips any packets that it may contain.
    ///
    /// Due to lifetime issues, this function does not return a
    /// reference to the `PacketParser`, but a boolean indicating
    /// whether a new packet is available.  Instead, the
    /// `PacketParser` can be accessed as `self.ppo`.
    pub fn next(&mut self) -> bool {
        if self.returned_first {
            match self.ppo.take() {
                Some (pp) => {
                    match pp.next() {
                        Ok((packet, position, ppo, _)) => {
                            self.insert_packet(packet, position);
                            self.ppo = ppo;
                        },
                        Err(_) => {
                            self.ppo = None;
                        }
                    }
                },
                None => {},
            }
        } else {
            self.returned_first = true;
        }

        !self.is_done()
    }

    /// Returns the current packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1.  Etc.
    pub fn recursion_depth(&self) -> Option<u8> {
        if let Some(ref pp) = self.ppo {
            Some(pp.recursion_depth)
        } else {
            None
        }
    }

    /// Returns whether the message has been completely parsed.
    pub fn is_done(&self) -> bool {
        self.ppo.is_none()
    }

    /// Finishes parsing the message and returns the assembled
    /// `Message`.
    ///
    /// This function can be called at any time, not only when the
    /// message has been completely parsed.  If the message has not
    /// been completely parsed, this function aborts processing, and
    /// the returned `Message` just contains those packets that were
    /// completely processed; the packet that is currently being
    /// processed is not included in the `Message`.
    pub fn finish(self) -> Message {
        return self.message;
    }
}

#[test]
fn message_parser_test() {
    let mut count = 0;
    let mut mp = MessageParser::from_file(path_to("public-key.gpg")).unwrap();
    while mp.recurse() {
        count += 1;
    }
    assert_eq!(count, 61);
}

// Check that we can use the read interface to stream the contents of
// a packet.
#[test]
fn message_parser_reader_interface() {
    use std::io::Read;

    let expected = bytes!("a-cypherpunks-manifesto.txt");

    // A message containing a compressed packet that contains a
    // literal packet.
    let path = path_to("compressed-data-algo-1.gpg");
    let mut mp = MessageParser::from_file(path).unwrap();
    let mut count = 0;
    while mp.recurse() {
        let pp = mp.ppo.as_mut().unwrap();
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
    }
    assert_eq!(count, 2);
}
