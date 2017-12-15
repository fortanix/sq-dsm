use std;
use std::io;
use std::str;
use std::path::Path;
use std::fs::File;

use num::FromPrimitive;

use ::buffered_reader::*;
use super::partial_body::BufferedReaderPartialBodyFilter;

use super::*;

pub mod subpacket;
pub mod key;

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

/// The default amount of acceptable nesting.  Typically, we expect a
/// message to looking like:
///
///   [ encryption container: [ signature: [ compressioned data: [ literal data ]]]]
///
/// So, this should be more than enough.
const MAX_RECURSION_DEPTH : u8 = 16;

// Packet headers.

/// Parse a CTB (as described in Section 4.2 of RFC4880) and return a
/// 'struct CTB'.  This function parses both new and old format ctbs.
fn ctb(ptag: u8) -> Result<CTB, io::Error> {
    // The top bit of the ptag must be set.
    if ptag & 0b1000_0000 == 0 {
        // XXX: Use a proper error.
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                                  "Malformed: msb of ptag not set."));
    }

    let new_format = ptag & 0b0100_0000 != 0;
    let ctb = if new_format {
        let tag = ptag & 0b0011_1111;
        CTB::New(CTBNew {
            common: CTBCommon {
                tag: FromPrimitive::from_u8(tag).unwrap()
            }})
    } else {
        let tag = (ptag & 0b0011_1100) >> 2;
        let length_type = ptag & 0b0000_0011;

        CTB::Old(CTBOld {
            common: CTBCommon {
                tag: FromPrimitive::from_u8(tag).unwrap()
            },
            length_type: FromPrimitive::from_u8(length_type).unwrap(),
        })
    };

    Ok(ctb)
}

#[test]
fn ctb_test() {
    // 0x99 = public key packet
    if let CTB::Old(ctb) = ctb(0x99).unwrap() {
        assert_eq!(ctb.tag, Tag::PublicKey);
        assert_eq!(ctb.length_type, PacketLengthType::TwoOctets);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xa3 = old compressed packet
    if let CTB::Old(ctb) = ctb(0xa3).unwrap() {
        assert_eq!(ctb.tag, Tag::CompressedData);
        assert_eq!(ctb.length_type, PacketLengthType::Indeterminate);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xcb: new literal
    if let CTB::New(ctb) = ctb(0xcb).unwrap() {
        assert_eq!(ctb.tag, Tag::Literal);
    } else {
        panic!("Expected a new format packet.");
    }
}

/// Decode a new format body length as described in Section 4.2.2 of RFC 4880.
pub fn body_length_new_format<T: BufferedReader> (bio: &mut T)
      -> Result<BodyLength, std::io::Error> {
    let octet1 = bio.data_consume_hard(1)?[0];
    if octet1 < 192 {
        // One octet.
        return Ok(BodyLength::Full(octet1 as u32));
    }
    if 192 <= octet1 && octet1 < 224 {
        // Two octets length.
        let octet2 = bio.data_consume_hard(1)?[0];
        return Ok(BodyLength::Full(((octet1 as u32 - 192) << 8) + octet2 as u32 + 192));
    }
    if 224 <= octet1 && octet1 < 255 {
        // Partial body length.
        return Ok(BodyLength::Partial(1 << (octet1 & 0x1F)));
    }

    assert_eq!(octet1, 255);
    // Five octets.
    return Ok(BodyLength::Full(bio.read_be_u32()?));
}

#[test]
fn body_length_new_format_test() {
    fn test(input: &[u8], expected_result: BodyLength) {
        assert_eq!(
            body_length_new_format(&mut BufferedReaderMemory::new(input)).unwrap(),
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

/// Decode an old format body length as described in Section 4.2.1 of RFC 4880.
fn body_length_old_format<T: BufferedReader> (bio: &mut T,
                                              length_type: PacketLengthType)
                                              -> Result<BodyLength, std::io::Error> {
    match length_type {
        PacketLengthType::OneOctet =>
            return Ok(BodyLength::Full(bio.data_consume_hard(1)?[0] as u32)),
        PacketLengthType::TwoOctets =>
            return Ok(BodyLength::Full(bio.read_be_u16()? as u32)),
        PacketLengthType::FourOctets =>
            return Ok(BodyLength::Full(bio.read_be_u32()? as u32)),
        PacketLengthType::Indeterminate =>
            return Ok(BodyLength::Indeterminate),
    }
}

#[test]
fn body_length_old_format_test() {
    fn test(input: &[u8], plt: PacketLengthType,
            expected_result: BodyLength, expected_rest: &[u8]) {
        let mut bio = BufferedReaderMemory::new(input);
        assert_eq!(body_length_old_format(&mut bio, plt).unwrap(), expected_result);
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

/// INPUT is a byte array that presumably contains an OpenPGP packet.
/// This function parses the packet's header and returns a
/// deserialized version and the rest input.
fn header<R: BufferedReader> (bio: &mut R)
        -> Result<Header, std::io::Error> {
    let ctb = ctb(bio.data_consume_hard(1)?[0])?;
    let length = match ctb {
        CTB::New(_) => body_length_new_format(bio)?,
        CTB::Old(ref ctb) => body_length_old_format(bio, ctb.length_type)?,
    };
    return Ok(Header { ctb: ctb, length: length });
}

fn unknown_parser<'a, R: BufferedReader + 'a>(bio: R, tag: Tag)
        -> Result<PacketParser<'a>, std::io::Error> {
    return Ok(PacketParser {
        packet: Packet::Unknown(Unknown {
            common: PacketCommon {
                children: None,
                content: None,
            },
            tag: tag,
        }),
        reader: Box::new(bio),
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

fn signature_parser<'a, R: BufferedReader + 'a>(mut bio: R)
        -> Result<PacketParser<'a>, std::io::Error> {
    let version = bio.data_consume_hard(1)?[0];
    let sigtype = bio.data_consume_hard(1)?[0];
    let pk_algo = bio.data_consume_hard(1)?[0];
    let hash_algo = bio.data_consume_hard(1)?[0];
    let hashed_area_len = bio.read_be_u16()?;
    let hashed_area = bio.steal(hashed_area_len as usize)?;
    let unhashed_area_len = bio.read_be_u16()?;
    let unhashed_area = bio.steal(unhashed_area_len as usize)?;
    let hash_prefix1 = bio.data_consume_hard(1)?[0];
    let hash_prefix2 = bio.data_consume_hard(1)?[0];
    let mpis = bio.steal_eof()?;

    return Ok(PacketParser {
        packet: Packet::Signature(Signature {
            common: PacketCommon {
                children: None,
                content: None,
            },
            version: version,
            sigtype: sigtype,
            pk_algo: pk_algo,
            hash_algo: hash_algo,
            hashed_area: hashed_area,
            hashed_area_parsed: RefCell::new(None),
            unhashed_area: unhashed_area,
            hash_prefix: [hash_prefix1, hash_prefix2],
            mpis: mpis,
        }),
        reader: Box::new(bio),
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

#[test]
fn signature_parser_test () {
    let data = bytes!("sig.gpg");

    {
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Signature);
        assert_eq!(header.length, BodyLength::Full(307));

        let mut pp = signature_parser(bio).unwrap();
        let p = pp.finish();
        // eprintln!("packet: {:?}", p);

        if let &Packet::Signature(ref p) = p {
            assert_eq!(p.version, 4);
            assert_eq!(p.sigtype, 0);
            assert_eq!(p.pk_algo, 1);
            assert_eq!(p.hash_algo, 10);
            assert_eq!(p.hashed_area.len(), 29);
            assert_eq!(p.unhashed_area.len(), 10);
            assert_eq!(p.hash_prefix, [0x65u8, 0x74]);
            assert_eq!(p.mpis.len(), 258);
        } else {
            unreachable!();
        }
    }
}

// Parse the body of a public key, public subkey, secret key or secret
// subkey packet.
fn key_parser<'a, R: BufferedReader + 'a>(mut bio: R, tag: Tag)
        -> Result<PacketParser<'a>, std::io::Error> {
    assert!(tag == Tag::PublicKey
            || tag == Tag::PublicSubkey
            || tag == Tag::SecretKey
            || tag == Tag::SecretSubkey);

    let version = bio.data_consume_hard(1)?[0];
    let creation_time = bio.read_be_u32()?;
    let pk_algo = bio.data_consume_hard(1)?[0];
    let mpis = bio.steal_eof()?;

    let key = Key {
        common: PacketCommon {
            children: None,
            content: None,
        },
        version: version,
        creation_time: creation_time,
        pk_algo: pk_algo,
        mpis: mpis,
    };

    return Ok(PacketParser {
        packet: match tag {
            Tag::PublicKey => Packet::PublicKey(key),
            Tag::PublicSubkey => Packet::PublicSubkey(key),
            Tag::SecretKey => Packet::SecretKey(key),
            Tag::SecretSubkey => Packet::SecretSubkey(key),
            _ => unreachable!(),
        },
        reader: Box::new(bio),
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

// Parse the body of a user id packet.
fn userid_parser<'a, R: BufferedReader + 'a>(mut bio: R)
        -> Result<PacketParser<'a>, std::io::Error> {
    return Ok(PacketParser {
        packet: Packet::UserID(UserID {
            common: PacketCommon {
                children: None,
                content: None,
            },
            value: bio.steal_eof()?,
        }),
        reader: Box::new(bio),
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

/// Parse the body of a literal packet.
fn literal_parser<'a, R: BufferedReader + 'a>(mut bio: R)
        -> Result<PacketParser<'a>, std::io::Error> {
    let format = bio.data_consume_hard(1)?[0];
    let filename_len = bio.data_consume_hard(1)?[0];

    let filename = if filename_len > 0 {
        Some(bio.data_consume_hard(filename_len as usize)?
               [0..filename_len as usize].to_vec())
    } else {
        None
    };

    let date = bio.read_be_u32()?;

    return Ok(PacketParser {
        packet: Packet::Literal(Literal {
            common: PacketCommon {
                children: None,
                content: None,
            },
            format: format,
            filename: filename,
            date: date,
        }),
        reader: Box::new(bio),
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

#[test]
fn literal_parser_test () {
    {
        let data = bytes!("literal-mode-b.gpg");
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Full(18));

        let mut pp = literal_parser(bio).unwrap();
        let p = pp.finish();
        // eprintln!("{:?}", p);
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format, 'b' as u8);
            assert_eq!(p.filename.as_ref().unwrap()[..], b"foobar"[..]);
            assert_eq!(p.date, 1507458744);
            assert_eq!(p.common.content, Some(b"FOOBAR"[..].to_vec()));
        } else {
            unreachable!();
        }
    }

    {
        let data = bytes!("literal-mode-t-partial-body.gpg");
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Partial(4096));

        if let BodyLength::Partial(l) = header.length {
            let bio2 = BufferedReaderPartialBodyFilter::new(bio, l);

            let mut pp = literal_parser(bio2).unwrap();
            let p = pp.finish();
            if let &Packet::Literal(ref p) = p {
                assert_eq!(p.format, 't' as u8);
                assert_eq!(p.filename.as_ref().unwrap()[..],
                           b"manifesto.txt"[..]);
                assert_eq!(p.date, 1508000649);

                let expected = bytes!("a-cypherpunks-manifesto.txt");

                assert_eq!(p.common.content, Some(expected.to_vec()));
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
    }
}

// Parse the body of a compressed data packet.
fn compressed_data_parser<'a, R: BufferedReader + 'a>(mut bio: R)
        -> Result<PacketParser<'a>, std::io::Error> {
    let algo = bio.data_hard(1)?[0];

    //   0          - Uncompressed
    //   1          - ZIP [RFC1951]
    //   2          - ZLIB [RFC1950]
    //   3          - BZip2 [BZ2]
    //   100 to 110 - Private/Experimental algorithm
    let bio : Box<BufferedReader> = match algo {
        0 => {
            // Uncompressed.
            bio.consume(1);
            // Our ownership convention is that each container
            // pushes exactly one `BufferedReader` on the reader
            // stack.  In this case, we need a pass-through
            // filter.  We can emulate this using a Limitor.
            Box::new(BufferedReaderLimitor::new(bio, std::u64::MAX))
        },
        1 => {
            // Zip.
            bio.consume(1);
            Box::new(BufferedReaderDeflate::new(bio))
        },
        2 => {
            // Zlib
            bio.consume(1);
            Box::new(BufferedReaderZlib::new(bio))
        },
        3 => {
            // BZip2
            bio.consume(1);
            Box::new(BufferedReaderBzip::new(bio))
        },
        _ => {
            // Unknown algo.  Return an unknown packet.
            return Ok(PacketParser {
                packet: Packet::Unknown(Unknown {
                    common: PacketCommon {
                        children: None,
                        content: None,
                    },
                    tag: Tag::CompressedData,
                }),
                reader: Box::new(bio),
                content_was_read: false,
                recursion_depth: 0,
                max_recursion_depth: MAX_RECURSION_DEPTH,
            });
        }
    };

    return Ok(PacketParser {
        packet: Packet::CompressedData(CompressedData {
            common: PacketCommon {
                children: None,
                content: None,
            },
            algo: algo,
        }),
        reader: bio,
        content_was_read: false,
        recursion_depth: 0,
        max_recursion_depth: MAX_RECURSION_DEPTH,
    });
}

#[test]
fn compressed_data_parser_test () {
    let expected = bytes!("a-cypherpunks-manifesto.txt");

    for i in 1..4 {
        use std::fs::File;

        let path = path_to(&format!("compressed-data-algo-{}.gpg", i)[..]);
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::new(&mut f, None);

        let h = header(&mut bio).unwrap();
        assert_eq!(h.ctb.tag, Tag::CompressedData);
        assert_eq!(h.length, BodyLength::Indeterminate);

        // We expect a compress packet containing a literal data
        // packet, and that is it.
        let (compressed, ppo, relative_position)
            = compressed_data_parser(bio).unwrap().recurse().unwrap();

        if let Packet::CompressedData(compressed) = compressed {
            assert_eq!(compressed.algo, i);
        } else {
            unreachable!();
        }

        // ppo should be the literal data packet.
        assert!(ppo.is_some());

        // It is a child.
        assert_eq!(relative_position, 1);

        let (literal, ppo, _relative_position)
            = ppo.unwrap().recurse().unwrap();

        if let Packet::Literal(literal) = literal {
            assert_eq!(literal.filename, None);
            assert_eq!(literal.format, 'b' as u8);
            assert_eq!(literal.date, 1509219866);
            assert_eq!(literal.common.content, Some(expected.to_vec()));
        } else {
            unreachable!();
        }

        // And, we're done...
        assert!(ppo.is_none());

    }
}

struct PacketParserBuilderSettings {
    max_recursion_depth: u8,
}

pub struct PacketParserBuilder<R: BufferedReader> {
    bio: R,
    settings: PacketParserBuilderSettings,
}


const PACKET_PARSER_DEFAULTS : PacketParserBuilderSettings
    = PacketParserBuilderSettings {
        max_recursion_depth: MAX_RECURSION_DEPTH,
    };

impl<R: BufferedReader> PacketParserBuilder<R> {
    pub fn from_buffered_reader(bio: R)
            -> Result<PacketParserBuilder<R>, std::io::Error> {
        Ok(PacketParserBuilder {
            bio: bio,
            settings: PACKET_PARSER_DEFAULTS
        })
    }

    pub fn max_recursion_depth(mut self, value: u8)
            -> PacketParserBuilder<R> {
        self.settings.max_recursion_depth = value;
        self
    }

    pub fn finalize<'a>(self)
            -> Result<Option<PacketParser<'a>>, std::io::Error> where Self: 'a {
        // Parse the first packet.
        let pp = PacketParser::parse(self.bio)?;

        if let PacketParserOrBufferedReader::PacketParser(mut pp) = pp {
            // We successfully parsed the first packet's header.

            // Override the defaults.
            pp.max_recursion_depth = self.settings.max_recursion_depth;

            Ok(Some(pp))
        } else {
            // `bio` is empty.  We're done.
            Ok(None)
        }
    }

    pub fn deserialize(self)
            -> Result<Message, std::io::Error> {
        Message::assemble(self.finalize()?)
    }
}

impl <'a, R: io::Read + 'a> PacketParserBuilder<BufferedReaderGeneric<R>> {
    pub fn from_reader(reader: R)
            -> Result<PacketParserBuilder<BufferedReaderGeneric<R>>,
                      std::io::Error> {
        Ok(PacketParserBuilder {
            bio: BufferedReaderGeneric::new(reader, None),
            settings: PACKET_PARSER_DEFAULTS
        })
    }
}

impl PacketParserBuilder<BufferedReaderGeneric<File>> {
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserBuilder<BufferedReaderGeneric<File>>,
                      std::io::Error> {
        PacketParserBuilder::from_reader(File::open(path)?)
    }
}

impl <'a> PacketParserBuilder<BufferedReaderMemory<'a>> {
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserBuilder<BufferedReaderMemory<'a>>,
                      std::io::Error> {
        PacketParserBuilder::from_buffered_reader(
            BufferedReaderMemory::new(bytes))
    }
}

pub struct PacketParser<'a> {
    // The reader.
    //
    // We can't make `reader` generic, because the type of
    // `BufferedReader` that is returned is not a function of the
    // arguments, and Rust figures out a generic's type by looking at
    // the calling site, not the function's implementation.  Consider
    // what happens when we parse a compressed data packet: we return
    // a Decompressor (in fact, the actual type is only known at
    // run-time!).
    reader: Box<BufferedReader + 'a>,

    // Whether the caller read the packets content.  If so, then we
    // can't recurse, because we're missing some of the packet!
    content_was_read: bool,

    // This packets recursion depth.  A top-level packet has a
    // recursion depth of 0.
    pub recursion_depth: u8,

    // The maximum allowed recursion depth.
    //
    // There is absolutely no reason that this should be more than
    // 255.  Moreover, if it is too large, then a read from the
    // pipeline will blow the stack.
    pub max_recursion_depth: u8,

    // The packet that is being parsed.
    pub packet: Packet,
}

impl <'a> std::fmt::Debug for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketParser")
            .field("reader", &self.reader)
            .field("packet", &self.packet)
            .field("recursion_depth", &self.recursion_depth)
            .field("max_recursion_depth", &self.max_recursion_depth)
            .finish()
    }
}

enum PacketParserOrBufferedReader<'a> {
    PacketParser(PacketParser<'a>),
    BufferedReader(Box<BufferedReader + 'a>),
}

impl <'a> PacketParser<'a> {
    /// Start parsing an OpenPGP message.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.  (If the first packet is a container, this returns
    /// the container; it does not recurse.)
    ///
    /// `max_recursion_depth` is the maximum recursion depth.  A
    /// top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1.  Calling
    /// `recurse()` on a `PacketParser` with the maximum recursion
    /// depth cause `recurse()` to treat a container packet as if it
    /// were not a container, and store the data inline.  Thus, 0
    /// means recurse is equivalent to `next()`.  Pass `None` for the
    /// default recursion depth, which is almost always reasonable.
    /// To manage the amount of recursion manually, just pass
    /// std::usize::MAX.
    pub fn from_buffered_reader<R: BufferedReader + 'a>(bio: R)
            -> Result<Option<PacketParser<'a>>, std::io::Error> {
        PacketParserBuilder::from_buffered_reader(bio)?.finalize()
    }

    pub fn from_reader<R: io::Read + 'a>(reader: R)
            -> Result<Option<PacketParser<'a>>, std::io::Error> {
        PacketParserBuilder::from_reader(reader)?.finalize()
    }

    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<Option<PacketParser<'a>>, std::io::Error> {
        PacketParserBuilder::from_file(path)?.finalize()
    }

    pub fn from_bytes(bytes: &'a [u8])
            -> Result<Option<PacketParser<'a>>, std::io::Error> {
        PacketParserBuilder::from_bytes(bytes)?.finalize()
    }

    /// Return a packet parser for the next OpenPGP packet in the
    /// stream.  If there are no packets left, then this function
    /// returns `bio`.
    fn parse<R: BufferedReader + 'a>(mut bio: R)
            -> Result<PacketParserOrBufferedReader<'a>, std::io::Error> {
        // When header encounters an EOF, it returns an error.  But,
        // we want to return None.  Try a one byte read.
        if bio.data(1)?.len() == 0 {
            // XXX: We need to return the reader here so that the
            // caller can pop the current container!
            return Ok(
                PacketParserOrBufferedReader::BufferedReader(Box::new(bio)));
        }

        let header = header(&mut bio)?;

        let bio : Box<BufferedReader> = match header.length {
            BodyLength::Full(len) =>
                Box::new(BufferedReaderLimitor::new(bio, len as u64)),
            BodyLength::Partial(len) =>
                Box::new(BufferedReaderPartialBodyFilter::new(bio, len)),
            BodyLength::Indeterminate =>
                // Our ownership convention is that each container
                // pushes exactly one `BufferedReader` on the reader
                // stack.  In this case, we need a pass-through
                // filter.  We can emulate this using a Limitor.
                Box::new(BufferedReaderLimitor::new(bio, std::u64::MAX)),
        };

        let tag = header.ctb.tag;
        let result = match tag {
            Tag::Signature =>
                signature_parser(bio)?,
            Tag::PublicSubkey =>
                key_parser(bio, tag)?,
            Tag::PublicKey =>
                key_parser(bio, tag)?,
            Tag::SecretKey =>
                key_parser(bio, tag)?,
            Tag::SecretSubkey =>
                key_parser(bio, tag)?,
            Tag::UserID =>
                userid_parser(bio)?,
            Tag::Literal =>
                literal_parser(bio)?,
            Tag::CompressedData =>
                compressed_data_parser(bio)?,
            _ =>
                unknown_parser(bio, tag)?,
        };

        return Ok(PacketParserOrBufferedReader::PacketParser(result));
    }

    /// Finish parsing the current packet and return it and a packet
    /// parser for the next packet (if any).
    ///
    /// The last value in the returned tuple is the position of the
    /// packet that is being parsed relative to the old packet.  Thus,
    /// if the value is 0, they are siblings.  If the value is 1, the
    /// old packet is a container and the new packet is its first
    /// child.  If the value is -1, the new packet belongs is
    /// contained in the old packet's grandparent.  The idea is
    /// illustrated below:
    ///
    /// #        ...
    /// #         |
    /// #       grandparent
    /// #       |          \
    /// #     parent       -1
    /// #     |      \
    /// #  packet    0
    /// #     |
    /// #     1
    ///
    /// Note, this function does not automatically recurse into a
    /// container (for that functionality, use the recurse method).
    /// Thus, if the current packet is, say, a compression packet,
    /// then the next packet is NOT the first packet in the
    /// compression container, but the packet following the
    /// compression container.  If the current container is empty,
    /// this function DOES pop that container off the container stack
    /// and returns the following packet in the parent container.
    pub fn next(mut self)
            -> Result<(Packet, Option<PacketParser<'a>>, isize),
                      std::io::Error> {
        // Finish processng the current packet.
        self.finish();

        // Pop the packet's BufferedReader.
        let mut reader = self.reader.into_inner().unwrap();

        // Stash some fields that we'll put in the new packet.
        let max_recursion_depth = self.max_recursion_depth;
        let packet = self.packet;

        // Now read the next packet.
        let mut recursion_depth = self.recursion_depth;
        let mut relative_position = 0;
        loop {
            // Parse the next packet.
            let pp = PacketParser::parse(reader)?;
            match pp {
                PacketParserOrBufferedReader::BufferedReader(reader2) => {
                    // We got EOF on the current container.  Pop it
                    // and try again.
                    if recursion_depth == 0 {
                        return Ok((packet, None, relative_position));
                    } else {
                        reader = reader2.into_inner().unwrap();
                        relative_position -= 1;
                        assert!(recursion_depth > 0);
                        recursion_depth -= 1;
                    }
                },
                PacketParserOrBufferedReader::PacketParser(mut pp) => {
                    pp.recursion_depth = recursion_depth;
                    pp.max_recursion_depth = max_recursion_depth;
                    return Ok((packet, Some(pp), relative_position));
                }
            }
        };
    }

    /// Like `next`, but if the current packet is a container (and we
    /// haven't reached the maximum recursion depth, and the user
    /// hasn't read the content), recurse into the container, and
    /// return a `PacketParser` for its first child.  Otherwise,
    /// return the next packet in the packet stream.  If we recurse,
    /// then the relative position parameter is 1.
    pub fn recurse(self)
            -> Result<(Packet, Option<PacketParser<'a>>, isize),
                      std::io::Error> {
        match self.packet {
            // Packets that recurse.
            Packet::CompressedData(_) => {
                if self.recursion_depth >= self.max_recursion_depth
                    || self.content_was_read {
                    // Drop through.
                } else {
                    match PacketParser::parse(self.reader)? {
                        PacketParserOrBufferedReader::PacketParser(mut pp) => {
                            pp.recursion_depth = self.recursion_depth + 1;
                            pp.max_recursion_depth = self.max_recursion_depth;
                            return Ok((self.packet, Some(pp), 1));
                        },
                        PacketParserOrBufferedReader::BufferedReader(_) => {
                            // XXX: We immediately got an EOF!
                            unimplemented!();
                        },
                    }
                }
            },
            // Packets that don't recurse.
            Packet::Unknown(_) | Packet::Signature(_)
                | Packet::PublicKey(_) | Packet::PublicSubkey(_)
                | Packet::SecretKey(_) | Packet::SecretSubkey(_)
                | Packet::UserID(_) | Packet::Literal(_) => {
                // Drop through.
            },
        }

        // No recursion.
        self.next()
    }

    pub fn finish<'b>(&'b mut self) -> &'b Packet {
        let mut rest = self.reader.steal_eof().unwrap();
        if rest.len() > 0 {
            if let Some(mut content) = self.packet.content.take() {
                content.append(&mut rest);
                self.packet.content = Some(content);
            } else {
                self.packet.content = Some(rest);
            }
        }

        return &mut self.packet;
    }
}

impl<'a> io::Read for PacketParser<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.content_was_read = true;
        return buffered_reader_generic_read_impl(self, buf);
    }
}

impl<'a> BufferedReader for PacketParser<'a> {
    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        return self.reader.data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        return self.reader.data_hard(amount);
    }

    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        return self.reader.data_eof();
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        if amount > 0 {
            self.content_was_read = true;
        }
        return self.reader.consume(amount);
    }

    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], io::Error> {
        if amount > 0 {
            self.content_was_read = true;
        }
        return self.reader.data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        if amount > 0 {
            self.content_was_read = true;
        }
        return self.reader.data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> Result<u16, io::Error> {
        self.content_was_read = true;
        return self.reader.read_be_u16();
    }

    fn read_be_u32(&mut self) -> Result<u32, io::Error> {
        self.content_was_read = true;
        return self.reader.read_be_u32();
    }

    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, io::Error> {
        self.content_was_read = true;
        return self.reader.steal(amount);
    }

    fn steal_eof(&mut self) -> Result<Vec<u8>, io::Error> {
        self.content_was_read = true;
        return self.reader.steal_eof();
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>>
            where Self: 'b {
        None
    }
}

// Check that we can use the read interface to stream the contents of
// a packet.
#[test]
fn packet_parser_reader_interface() {
    // We need the Read trait.
    use std::io::Read;

    let expected = bytes!("a-cypherpunks-manifesto.txt");

    // A message containing a compressed packet that contains a
    // literal packet.
    let path = path_to("compressed-data-algo-1.gpg");
    let pp = PacketParser::from_file(path).unwrap().unwrap();

    // The message has the form:
    //   [ compressed data [ literal data ] ]
    let (packet, ppo, relative_position) = pp.recurse().unwrap();
    if let Packet::CompressedData(_) = packet {
    } else {
        panic!("Expected a compressed data packet.");
    }
    assert_eq!(relative_position, 1);

    let mut pp = ppo.unwrap();

    if let Packet::Literal(_) = pp.packet {
    } else {
        panic!("Expected a literal data packet.");
    }

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

    // Make sure we can still get the next packet (which in this case
    // is just EOF).
    let (packet, ppo, _) = pp.recurse().unwrap();
    assert!(ppo.is_none());
    // Since we read all of the data, we expect content to be None.
    assert!(packet.content.is_none());
}

impl Container {
    fn new() -> Container {
        Container { packets: Vec::with_capacity(8) }
    }
}

impl Message {
    fn assemble<'a>(ppo: Option<PacketParser<'a>>)
            -> Result<Message, std::io::Error> {
        // Create a top-level container.
        let mut top_level = Container::new();

        let mut depth : isize = 0;
        let mut relative_position = 0;

        if ppo.is_none() {
            // Empty message.
            return Ok(Message::from_packets(Vec::new()));
        }
        let mut pp = ppo.unwrap();

        'outer: loop {
            let (mut packet, mut ppo, mut relative_position2) = pp.recurse()?;

            assert!(-depth <= relative_position);
            assert!(relative_position <= 1);
            depth += relative_position;

            // Find the right container.
            let mut container = &mut top_level;
            // If relative_position is 1, then we are creating a new
            // container.
            let traversal_depth
                = depth - if relative_position > 0 { 1 } else { 0 };
            if traversal_depth > 0 {
                for _ in 1..traversal_depth + 1 {
                    // Do a little dance to prevent container from
                    // being reborrowed and preventing us from
                    // assign to it.
                    let tmp = container;
                    let i = tmp.packets.len() - 1;
                    assert!(tmp.packets[i].children.is_some());
                    container = tmp.packets[i].children.as_mut().unwrap();
                }
            }


            // If next packet will be inserted in the same container
            // or the current container's child, we don't need to walk
            // the tree from the root.
            loop {
                if relative_position == 1 {
                    // Create a new container.
                    let tmp = container;
                    let i = tmp.packets.len() - 1;
                    assert!(tmp.packets[i].children.is_none());
                    tmp.packets[i].children = Some(Container::new());
                    container = tmp.packets[i].children.as_mut().unwrap();
                }

                container.packets.push(packet);

                if ppo.is_none() {
                    break 'outer;
                }

                relative_position = relative_position2;
                pp = ppo.unwrap();

                if relative_position < 0 {
                    break;
                }

                let result = pp.recurse()?;
                packet = result.0;
                ppo = result.1;
                relative_position2 = result.2;
            }
        }

        return Ok(Message { top_level: top_level });
    }

    pub fn deserialize<R: BufferedReader>(bio: R)
            -> Result<Message, std::io::Error> {
        PacketParserBuilder::from_buffered_reader(bio)?.deserialize()
    }

    pub fn from_reader<R: io::Read>(reader: R)
             -> Result<Message, std::io::Error> {
        let bio = BufferedReaderGeneric::new(reader, None);
        Message::deserialize(bio)
    }

    pub fn from_file(mut file: File) -> Result<Message, std::io::Error> {
        let bio = BufferedReaderGeneric::new(&mut file, None);
        Message::deserialize(bio)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Message, std::io::Error> {
        let bio = BufferedReaderMemory::new(data);
        Message::deserialize(bio)
    }
}

#[cfg(test)]
mod message_test {
    use super::path_to;
    use super::{BufferedReaderGeneric, BufferedReaderMemory,
                Message, Packet, PacketParser, PacketParserBuilder};

    use std::io::Read;
    use std::fs::File;

    #[test]
    fn deserialize_test_1 () {
        // XXX: This test should be more thorough.  Right now, we mostly
        // just rely on the fact that an assertion is not thrown.

        // A flat message.
        let data = bytes!("public-key.gpg");
        let bio = BufferedReaderMemory::new(data);
        let message = Message::deserialize(bio).unwrap();
        eprintln!("Message has {} top-level packets.",
                  message.children().len());
        eprintln!("Message: {:?}", message);

        let mut count = 0;
        for (i, p) in message.descendants().enumerate() {
            eprintln!("{}: {:?}", i, p);
            count += 1;
        }

        assert_eq!(count, 61);
    }

    #[test]
    fn deserialize_test_2 () {
        // A message containing a compressed packet that contains a
        // literal packet.
        let path = path_to("compressed-data-algo-1.gpg");
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let bio = BufferedReaderGeneric::new(&mut f, None);
        let message = Message::deserialize(bio).unwrap();
        eprintln!("Message has {} top-level packets.",
                  message.children().len());
        eprintln!("Message: {:?}", message);

        let mut count = 0;
        for (i, p) in message.descendants().enumerate() {
            eprintln!("{}: {:?}", i, p);
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn deserialize_test_3 () {
        let path = path_to("signed.gpg");
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let bio = BufferedReaderGeneric::new(&mut f, None);
        let message = Message::deserialize(bio).unwrap();
        eprintln!("Message has {} top-level packets.",
                  message.children().len());
        eprintln!("Message: {:?}", message);

        let mut count = 0;
        for (i, p) in message.descendants().enumerate() {
            count += 1;
            eprintln!("{}: {:?}", i, p);
        }
        // We expect 6 packets.
        assert_eq!(count, 6);
    }

    #[test]
    fn compression_quine_test_1 () {
        // Use the Message::deserialize interface to parse an OpenPGP
        // quine.
        let path = path_to("compression-quine.gpg");
        let max_recursion_depth = 128;
        let message = PacketParserBuilder::from_file(path).unwrap()
            .max_recursion_depth(max_recursion_depth)
            .deserialize().unwrap();

        let mut count = 0;
        for (i, p) in message.descendants().enumerate() {
            count += 1;
            if false {
                eprintln!("{}: p: {:?}", i, p);
            }
        }

        assert_eq!(count, 1 + max_recursion_depth);
    }

    #[test]
    fn compression_quine_test_2 () {
        // Use the iterator interface to parse an OpenPGP quine.
        let path = path_to("compression-quine.gpg");
        let mut f = File::open(&path).expect(&path.to_string_lossy());

        let bio = BufferedReaderGeneric::new(&mut f, None);
        let max_recursion_depth = 255;
        let mut ppo : Option<PacketParser>
            = PacketParserBuilder::from_buffered_reader(bio).unwrap()
                .max_recursion_depth(max_recursion_depth)
                .finalize().unwrap();

        let mut count : usize = 0;
        loop {
            if let Some(pp2) = ppo {
                count += 1;

                let (_packet, pp2, _position) = pp2.recurse().unwrap();
                ppo = pp2;
            } else {
                break;
            }
        }
        assert_eq!(count, 1 + max_recursion_depth as usize);
    }

    #[test]
    fn consume_content_1 () {
        // A message containing a compressed packet that contains a
        // literal packet.  When we read some of the compressed
        // packet, we expect recurse() to not recurse.

        let ppo = PacketParser::from_file(
            path_to("compressed-data-algo-1.gpg")).unwrap();

        let mut pp = ppo.unwrap();
        if let Packet::CompressedData(_) = pp.packet {
        } else {
            panic!("Expected a compressed packet!");
        }

        // Read some of the body of the compressed packet.
        let mut data = [0u8; 1];
        let amount = pp.read(&mut data).unwrap();
        assert_eq!(amount, 1);

        // recurse should now not recurse.  Since there is nothing
        // following the compressed packet, ppo should be None.
        let (mut packet, ppo, _relative_position) = pp.next().unwrap();
        assert!(ppo.is_none());

        // Get the rest of the content and put the initial byte that
        // we stole back.
        let mut content = packet.content.take().unwrap();
        content.insert(0, data[0]);

        let content = &content.into_boxed_slice()[..];
        let ppo = PacketParser::from_bytes(content).unwrap();
        let pp = ppo.unwrap();
        if let Packet::Literal(_) = pp.packet {
        } else {
            panic!("Expected a literal packet!");
        }

        // And we're done...
        let (_packet, ppo, _relative_position) = pp.next().unwrap();
        assert!(ppo.is_none());
    }

}
