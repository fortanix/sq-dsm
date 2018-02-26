use std;
use std::io;
use std::cmp;
use std::str;
use std::path::Path;
use std::fs::File;

use ::buffered_reader::*;
use Error;

use super::*;

mod partial_body;
use self::partial_body::BufferedReaderPartialBodyFilter;

pub mod subpacket;
pub use self::subpacket::SubpacketArea;
pub mod key;

mod message_parser;
pub use self::message_parser::MessageParser;

// Whether to trace execution by default (on stderr).
const TRACE : bool = false;

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

/// Parses a CTB as described in [Section 4.2 of RFC 4880] and returns
/// a [`CTB`].  This function parses both new and old format ctbs.
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
///   [`CTB`]: ../enum.CTB
pub fn ctb(ptag: u8) -> Result<CTB> {
    // The top bit of the ptag must be set.
    if ptag & 0b1000_0000 == 0 {
        // XXX: Use a proper error.
        return Err(
            Error::MalformedPacket(
                format!("Malformed ctb: MSB of ptag ({:#010b}) not set.", ptag)
            ).into());
    }

    let new_format = ptag & 0b0100_0000 != 0;
    let ctb = if new_format {
        let tag = ptag & 0b0011_1111;
        CTB::New(CTBNew {
            common: CTBCommon {
                tag: Tag::from_numeric(tag).unwrap()
            }})
    } else {
        let tag = (ptag & 0b0011_1100) >> 2;
        let length_type = ptag & 0b0000_0011;

        CTB::Old(CTBOld {
            common: CTBCommon {
                tag: Tag::from_numeric(tag).unwrap()
            },
            length_type: PacketLengthType::from_numeric(length_type).unwrap(),
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

/// Decodes a new format body length as described in [Section 4.2.2 of RFC 4880].
///
///   [Section 4.2.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.2
pub fn body_length_new_format<T: BufferedReader<C>, C> (bio: &mut T)
        -> io::Result<BodyLength> {
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
            body_length_new_format(
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

/// Decodes an old format body length as described in [Section 4.2.1 of RFC 4880].
///
///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
pub fn body_length_old_format<T: BufferedReader<C>, C>
        (bio: &mut T, length_type: PacketLengthType)
        -> Result<BodyLength> {
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

/// Parses an OpenPGP packet's header as described in [Section 4.2 of RFC 4880].
///
///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
pub fn header<R: BufferedReader<C>, C> (bio: &mut R)
        -> Result<Header> {
    let ctb = ctb(bio.data_consume_hard(1)?[0])?;
    let length = match ctb {
        CTB::New(_) => body_length_new_format(bio)?,
        CTB::Old(ref ctb) => body_length_old_format(bio, ctb.length_type)?,
    };
    return Ok(Header { ctb: ctb, length: length });
}

impl S2K {
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (bio: &mut R) -> Result<S2K> {
        let s2k_type = bio.data_consume_hard(1)?[0];

        if s2k_type != 0 && s2k_type != 1 && s2k_type != 3 {
            // XXX: How do we best deal with unknown s2k schemes?
            unimplemented!();
        }

        let algo = bio.data_consume_hard(1)?[0];

        let mut salt = Some([0u8; 8]);
        if s2k_type == 1 || s2k_type == 3 {
            salt.as_mut().unwrap().copy_from_slice(
                &bio.data_consume_hard(8)?[..8]);
        } else {
            salt = None;
        }

        let coded_count = if s2k_type == 3 {
            Some(bio.data_consume_hard(1)?[0])
        } else {
            None
        };

        Ok(S2K {
            hash_algo: algo,
            salt: salt,
            coded_count: coded_count
        })
    }
}

impl Unknown {
    /// Parses the body of any packet and returns an Unknown.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (bio: R, recursion_depth: usize, tag: Tag)
            -> Result<PacketParser<'a>> {
        return Ok(PacketParser {
            packet: Packet::Unknown(Unknown {
                common: PacketCommon {
                    children: None,
                    body: None,
                },
                tag: tag,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

pub fn to_unknown_packet<R: io::Read>(reader: R)
        -> Result<Unknown> {
    let mut reader = BufferedReaderGeneric::with_cookie(
        reader, None, BufferedReaderState::default());
    let header = header(&mut reader)?;

    let reader : Box<BufferedReader<BufferedReaderState>>
        = match header.length {
            BodyLength::Full(len) =>
                Box::new(BufferedReaderLimitor::with_cookie(
                    reader, len as u64, BufferedReaderState::default())),
            BodyLength::Partial(len) =>
                Box::new(BufferedReaderPartialBodyFilter::with_cookie(
                    reader, len, BufferedReaderState::default())),
            _ => Box::new(reader),
    };

    let mut pp = Unknown::parse(reader, 0, header.ctb.tag)?;
    pp.buffer_unread_content()?;
    pp.finish();

    if let Packet::Unknown(packet) = pp.packet {
        Ok(packet)
    } else {
        panic!("Internal inconsistency.");
    }
}

impl Signature {
    /// Parses the body of a signature packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
        let version = bio.data_hard(1)?[0];
        if version != 4 {
            if TRACE {
                eprintln!("{}Signature::parse: Ignoring verion {} packet",
                          indent(recursion_depth as u8), version);
            }

            // Unknown algo.  Return an unknown packet.
            return Unknown::parse(bio, recursion_depth, Tag::Signature);
        }

        bio.consume(1);

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
                    body: None,
                },
                version: version,
                sigtype: sigtype,
                pk_algo: pk_algo,
                hash_algo: hash_algo,
                hashed_area: SubpacketArea::new(hashed_area),
                unhashed_area: SubpacketArea::new(unhashed_area),
                hash_prefix: [hash_prefix1, hash_prefix2],
                mpis: mpis,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

#[test]
fn signature_parser_test () {
    let data = bytes!("sig.gpg");

    {
        let mut bio = BufferedReaderMemory::with_cookie(
            data, BufferedReaderState::default());

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Signature);
        assert_eq!(header.length, BodyLength::Full(307));

        let mut pp = Signature::parse(bio, 0).unwrap();
        let p = pp.finish();
        // eprintln!("packet: {:?}", p);

        if let &Packet::Signature(ref p) = p {
            assert_eq!(p.version, 4);
            assert_eq!(p.sigtype, 0);
            assert_eq!(p.pk_algo, 1);
            assert_eq!(p.hash_algo, 10);
            assert_eq!(p.hashed_area.data.len(), 29);
            assert_eq!(p.unhashed_area.data.len(), 10);
            assert_eq!(p.hash_prefix, [0x65u8, 0x74]);
            assert_eq!(p.mpis.len(), 258);
        } else {
            unreachable!();
        }
    }
}

impl Key {
    /// Parses the body of a public key, public subkey, secret key or
    /// secret subkey packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize, tag: Tag)
            -> Result<PacketParser<'a>> {
        assert!(tag == Tag::PublicKey
                || tag == Tag::PublicSubkey
                || tag == Tag::SecretKey
                || tag == Tag::SecretSubkey);

        let version = bio.data_hard(1)?[0];
        if version != 4 {
            // We only support version 4 keys.
            return Unknown::parse(bio, recursion_depth, tag);
        }
        bio.consume(1);

        let creation_time = bio.read_be_u32()?;
        let pk_algo = bio.data_consume_hard(1)?[0];
        let mpis = bio.steal_eof()?;

        let key = Key {
            common: PacketCommon {
                children: None,
                body: None,
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
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

impl UserID {
    /// Parses the body of a user id packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
        return Ok(PacketParser {
            packet: Packet::UserID(UserID {
                common: PacketCommon {
                    children: None,
                    body: None,
                },
                value: bio.steal_eof()?,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

impl UserAttribute {
    /// Parses the body of a user attribute packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
        return Ok(PacketParser {
            packet: Packet::UserAttribute(UserAttribute {
                common: PacketCommon {
                    children: None,
                    body: None,
                },
                value: bio.steal_eof()?,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

impl Literal {
    /// Parses the body of a literal packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
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
                    body: None,
                },
                format: format,
                filename: filename,
                date: date,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

#[test]
fn literal_parser_test () {
    {
        let data = bytes!("literal-mode-b.gpg");
        let mut bio = BufferedReaderMemory::with_cookie(
            data, BufferedReaderState::default());

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Full(18));

        let mut pp = Literal::parse(bio, 0).unwrap();
        let content = pp.steal_eof().unwrap();
        let p = pp.finish();
        // eprintln!("{:?}", p);
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format, 'b' as u8);
            assert_eq!(p.filename.as_ref().unwrap()[..], b"foobar"[..]);
            assert_eq!(p.date, 1507458744);
            assert_eq!(content, b"FOOBAR");
        } else {
            unreachable!();
        }
    }

    {
        let data = bytes!("literal-mode-t-partial-body.gpg");
        let mut bio = BufferedReaderMemory::with_cookie(
            data, BufferedReaderState::default());

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Partial(4096));

        if let BodyLength::Partial(l) = header.length {
            let bio2 = BufferedReaderPartialBodyFilter::with_cookie(
                bio, l, BufferedReaderState::default());

            let mut pp = Literal::parse(bio2, 1).unwrap();
            let content = pp.steal_eof().unwrap();
            let p = pp.finish();
            if let &Packet::Literal(ref p) = p {
                assert_eq!(p.format, 't' as u8);
                assert_eq!(p.filename.as_ref().unwrap()[..],
                           b"manifesto.txt"[..]);
                assert_eq!(p.date, 1508000649);

                let expected = bytes!("a-cypherpunks-manifesto.txt");

                assert_eq!(&content[..], &expected[..]);
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
    }
}

impl CompressedData {
    /// Parses the body of a compressed data packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
        let algo = bio.data_hard(1)?[0];

        if TRACE {
            eprintln!("compressed_data_parser(): \
                       adding decompressor at recursion depth = {:?}",
                      recursion_depth);
        }

        //   0          - Uncompressed
        //   1          - ZIP [RFC1951]
        //   2          - ZLIB [RFC1950]
        //   3          - BZip2 [BZ2]
        //   100 to 110 - Private/Experimental algorithm
        let bio : Box<BufferedReader<BufferedReaderState>> = match algo {
            0 => {
                if TRACE {
                    eprintln!("compressed_data_parser(): Actually, no need \
                               for a compression filter: this is an \
                               \"uncompressed compression packet\"");
                }
                // Uncompressed.
                bio.consume(1);
                // XXX: If bio is already boxed (`buffered_reader`
                // provides an impl of `BufferedReader` for
                // `Box<BufferedReader>`, this is going to add another
                // level of indirection.  It would be nice to avoid this
                // level of indirection, but I have no idea how...
                Box::new(bio)
            },
            1 => {
                // Zip.
                bio.consume(1);
                Box::new(BufferedReaderDeflate::with_cookie(
                    bio, BufferedReaderState::new(recursion_depth)))
            },
            2 => {
                // Zlib
                bio.consume(1);
                Box::new(BufferedReaderZlib::with_cookie(
                    bio, BufferedReaderState::new(recursion_depth)))
            },
            3 => {
                // BZip2
                bio.consume(1);
                Box::new(BufferedReaderBzip::with_cookie(
                    bio, BufferedReaderState::new(recursion_depth)))
            },
            _ => {
                // Unknown algo.  Return an unknown packet.
                return Unknown::parse(
                    bio, recursion_depth, Tag::CompressedData);
            }
        };

        return Ok(PacketParser {
            packet: Packet::CompressedData(CompressedData {
                common: PacketCommon {
                    children: None,
                    body: None,
                },
                algo: algo,
            }),
            reader: bio,
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

#[test]
fn compressed_data_parser_test () {
    let expected = bytes!("a-cypherpunks-manifesto.txt");

    for i in 1..4 {
        use std::fs::File;

        let path = path_to(&format!("compressed-data-algo-{}.gpg", i)[..]);
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::with_cookie(
            &mut f, None, BufferedReaderState::default());

        let h = header(&mut bio).unwrap();
        assert_eq!(h.ctb.tag, Tag::CompressedData);
        assert_eq!(h.length, BodyLength::Indeterminate);

        // We expect a compressed packet containing a literal data
        // packet, and that is it.
        let (compressed, _, ppo, _)
            = CompressedData::parse(bio, 0).unwrap().recurse().unwrap();

        if let Packet::CompressedData(compressed) = compressed {
            assert_eq!(compressed.algo, i);
        } else {
            unreachable!();
        }

        // ppo should be the literal data packet.
        let mut pp = ppo.unwrap();

        // It is a child.
        assert_eq!(pp.recursion_depth, 1);

        let content = pp.steal_eof().unwrap();

        let (literal, _, ppo, _) = pp.recurse().unwrap();

        if let Packet::Literal(literal) = literal {
            assert_eq!(literal.filename, None);
            assert_eq!(literal.format, 'b' as u8);
            assert_eq!(literal.date, 1509219866);
            assert_eq!(content, expected.to_vec());
        } else {
            unreachable!();
        }

        // And, we're done...
        assert!(ppo.is_none());

    }
}

impl SKESK {
    /// Parses the body of an SKESK packet.
    pub fn parse<'a, R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, recursion_depth: usize)
            -> Result<PacketParser<'a>> {
        let version = bio.data_hard(1)?[0];
        if version != 4 {
            // We only support version 4 keys.
            return Unknown::parse(bio, recursion_depth, Tag::SKESK);
        }
        bio.consume(1);

        let symm_algo = bio.data_consume_hard(1)?[0];
        let s2k = S2K::parse(&mut bio)?;
        let esk = bio.steal_eof()?;

        return Ok(PacketParser {
            packet: Packet::SKESK(SKESK {
                common: PacketCommon {
                    children: None,
                    body: None,
                },
                version: version,
                symm_algo: symm_algo,
                s2k: s2k,
                esk: esk,
            }),
            reader: Box::new(bio),
            content_was_read: false,
            recursion_depth: recursion_depth as u8,
            settings: PacketParserSettings::default(),
        });
    }
}

#[test]
fn skesk_parser_test() {
    struct Test<'a> {
        filename: &'a str,
        s2k: S2K,
        cipher_algo: SymmetricAlgo,
        password: &'a [u8],
        key_hex: &'a str,
    };

    let tests = [
            Test {
                filename: "s2k/mode-3-encrypted-key-password-bgtyhn.gpg",
                cipher_algo: SymmetricAlgo::AES128,
                s2k: S2K {
                    hash_algo: 2,
                    salt: Some([0x82, 0x59, 0xa0, 0x6e, 0x98, 0xda, 0x94, 0x1c]),
                    coded_count: Some(238),
                },
                password: &b"bgtyhn"[..],
                key_hex: "474E5C373BA18AF0A499FCAFE6093F131DF636F6A3812B9A8AE707F1F0214AE9",
            },
    ];

    for test in tests.iter() {
        let path = path_to(test.filename);
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::with_cookie(
            &mut f, None, BufferedReaderState::default());

        let h = header(&mut bio).unwrap();
        assert_eq!(h.ctb.tag, Tag::SKESK);

        let (packet, _, _, _)
            = SKESK::parse(bio, 0).unwrap().next().unwrap();

        if let Packet::SKESK(skesk) = packet {
            eprintln!("{:?}", skesk);

            assert_eq!(skesk.symm_algo,
                       SymmetricAlgo::to_numeric(test.cipher_algo));
            assert_eq!(skesk.s2k, test.s2k);

            let key = skesk.decrypt(test.password);
            if let Ok((_symm_algo, key)) = key {
                let key = to_hex(&key[..], false);
                assert_eq!(&key[..], &test.key_hex[..]);
            } else {
                panic!("Session key: None!");
            }
        } else {
            unreachable!();
        }
    }
}


// A `PacketParser`'s settings.
#[derive(Debug)]
struct PacketParserSettings {
    // The maximum allowed recursion depth.
    //
    // There is absolutely no reason that this should be more than
    // 255.  (GnuPG defaults to 32.)  Moreover, if it is too large,
    // then a read from the reader pipeline could blow the stack.
    max_recursion_depth: u8,

    // Whether a packet's contents should be buffered or dropped when
    // the next packet is retrieved.
    buffer_unread_content: bool,

    // Whether to trace the execute of the PacketParser.  (The output
    // is sent to stderr.)
    trace: bool,
}

// The default `PacketParser` settings.
impl Default for PacketParserSettings {
    fn default() -> Self {
        PacketParserSettings {
            max_recursion_depth: MAX_RECURSION_DEPTH,
            buffer_unread_content: false,
            trace: TRACE,
        }
    }
}

/// A builder for configuring a `PacketParser`.
///
/// Since the default settings are usually appropriate, this mechanism
/// will only be needed in exceptional circumstances.  Instead use,
/// for instance, `PacketParser::from_file` or
/// `PacketParser::from_reader` to start parsing an OpenPGP message.
pub struct PacketParserBuilder<R: BufferedReader<BufferedReaderState>> {
    bio: R,
    settings: PacketParserSettings,
}

impl<R: BufferedReader<BufferedReaderState>> PacketParserBuilder<R> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `BufferedReader` object.
    pub fn from_buffered_reader(mut bio: R)
            -> Result<PacketParserBuilder<R>> {
        bio.cookie_set(BufferedReaderState::default());
        Ok(PacketParserBuilder {
            bio: bio,
            settings: PacketParserSettings::default(),
        })
    }

    /// Sets the maximum recursion depth.
    ///
    /// Setting this to 0 means that the `PacketParser` will never
    /// recurse; it will only parse the top-level packets.
    ///
    /// This is a u8, because recursing more than 255 times makes no
    /// sense.  The default is `MAX_RECURSION_DEPTH`.  (GnuPG defaults
    /// to a maximum recursion depth of 32.)
    pub fn max_recursion_depth(mut self, value: u8)
            -> PacketParserBuilder<R> {
        self.settings.max_recursion_depth = value;
        self
    }

    /// Causes `PacketParser::finish()` to buffer any unread content.
    ///
    /// The unread content is stored in the `Packet::content` Option.
    pub fn buffer_unread_content(mut self)
            -> PacketParserBuilder<R> {
        self.settings.buffer_unread_content = true;
        self
    }

    /// Causes `PacketParser::finish()` to drop any unread content.
    /// This is the default.
    pub fn drop_unread_content(mut self)
            -> PacketParserBuilder<R> {
        self.settings.buffer_unread_content = false;
        self
    }

    /// Causes the `PacketParser` functionality to print a trace of
    /// its execution on stderr.
    pub fn trace(mut self) -> PacketParserBuilder<R> {
        self.settings.trace = true;
        self
    }

    /// Finishes configuring the `PacketParser` and returns an
    /// `Option<PacketParser>`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use openpgp::Result;
    /// # use openpgp::parse::{PacketParser,PacketParserBuilder};
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8])
    /// #     -> Result<Option<PacketParser>> {
    /// let ppo = PacketParserBuilder::from_bytes(message_data)?.finalize()?;
    /// # return Ok(ppo);
    /// # }
    /// ```
    pub fn finalize<'a>(self)
            -> Result<Option<PacketParser<'a>>> where Self: 'a {
        // Parse the first packet.
        let pp = PacketParser::parse(self.bio, &self.settings, 0)?;

        if let PacketParserOrBufferedReader::PacketParser(mut pp) = pp {
            // We successfully parsed the first packet's header.

            // Override the defaults.
            pp.settings = self.settings;

            if pp.settings.trace {
                eprintln!("PacketParserBuilder::finalize: \
                           Parsed first packet ({:?}). depth = {}; level = {:?}",
                          pp.packet.tag(),
                          pp.recursion_depth, pp.reader.cookie_ref().level);
            }

            Ok(Some(pp))
        } else {
            // `bio` is empty.  We're done.
            Ok(None)
        }
    }

    /// Finishes configuring the `PacketParser` and returns a fully
    /// parsed message.
    ///
    /// Note: calling this function does not change the default
    /// settings `PacketParserSettings`.  Thus, by default, the
    /// content of packets will *not* be buffered.
    ///
    /// Note: to avoid denial of service attacks, the `PacketParser`
    /// interface should be preferred unless the size of the message
    /// is known to fit in memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use openpgp::Result;
    /// # use openpgp::Message;
    /// # use openpgp::parse::{PacketParser,PacketParserBuilder};
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8]) -> Result<Message> {
    /// let message = PacketParserBuilder::from_bytes(message_data)?
    ///     .buffer_unread_content()
    ///     .to_message()?;
    /// # return Ok(message);
    /// # }
    /// ```
    pub fn to_message(self) -> Result<Message> {
        Message::assemble(self.finalize()?)
    }
}

impl<'a, R: io::Read + 'a>
        PacketParserBuilder<BufferedReaderGeneric<R, BufferedReaderState>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    pub fn from_reader(reader: R)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<R, BufferedReaderState>>> {
        Ok(PacketParserBuilder {
            bio: BufferedReaderGeneric::with_cookie(
                reader, None, BufferedReaderState::default()),
            settings: PacketParserSettings::default(),
        })
    }
}

impl PacketParserBuilder<BufferedReaderGeneric<File, BufferedReaderState>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<File, BufferedReaderState>>> {
        PacketParserBuilder::from_reader(File::open(path)?)
    }
}

impl <'a> PacketParserBuilder<BufferedReaderMemory<'a, BufferedReaderState>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in specified buffer.
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserBuilder<
                          BufferedReaderMemory<'a, BufferedReaderState>>> {
        PacketParserBuilder::from_buffered_reader(
            BufferedReaderMemory::with_cookie(
                bytes, BufferedReaderState::default()))
    }
}

#[derive(Clone, Copy)]
pub struct BufferedReaderState {
    // The top-level buffered reader is 0.
    // The limitor for a top-level packet is 1.
    // The filter for a top-level container packet is 1.
    // The limitor for the child of a top-level packet is 2.
    // The filter for the child of a top-level packet is 2.
    //
    // Thus, the filters that control the input for a packet at
    // recursion depth n have level n + 1.
    level: usize,
}

impl fmt::Debug for BufferedReaderState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderState")
            .field("level", &self.level)
            .finish()
    }
}

impl Default for BufferedReaderState {
    fn default() -> Self {
        BufferedReaderState {
            level: 0,
        }
    }
}

impl BufferedReaderState {
    fn new(recursion_depth: usize) -> BufferedReaderState {
        BufferedReaderState {
            level: recursion_depth + 1
        }
    }
}

/// A low-level OpenPGP message parser.
///
/// A `PacketParser` provides a low-level, iterator-like interface to
/// parse OpenPGP messages.
///
/// For each iteration, the user is presented with a [`Packet`]
/// corresponding to the last packet, a `PacketParser` for the next
/// packet, and their positions within the message.
///
/// Using the `PacketParser`, the user is able to configure how the
/// new packet will be parsed.  For instance, it is possible to stream
/// the packet's contents (a `PacketParser` implements the
/// `std::io::Read` and the `BufferedReader` traits), buffer them
/// within the [`Packet`], or drop them.  The user can also decide to
/// recurse into the packet, if it is a container, instead of getting
/// the following packet.
///
/// See the `next()` and `recurse()` methods for more details.
///
///   [`next()`]: #method.next
///   [`recurse()`]: #method.recurse
///   [`Packet`]: ../struct.Packet.html
///
/// # Examples
///
/// Parse an OpenPGP message using a `PacketParser`:
///
/// ```rust
/// # use openpgp::Result;
/// # use openpgp::Packet;
/// # use openpgp::parse::PacketParser;
/// # let _ = f(include_bytes!("../../tests/data/messages/public-key.gpg"));
/// #
/// # fn f(message_data: &[u8]) -> Result<()> {
/// let mut ppo = PacketParser::from_bytes(message_data)?;
/// while let Some(mut pp) = ppo {
///     // Process the packet.
///
///     if let Packet::Literal(_) = pp.packet {
///         // Stream the content of any literal packets to stdout.
///         std::io::copy(&mut pp, &mut std::io::stdout());
///     }
///
///     // Get the next packet.
///     let (_packet, _packet_depth, tmp, _pp_depth) = pp.recurse()?;
///     ppo = tmp;
/// }
/// # return Ok(());
/// # }
pub struct PacketParser<'a> {
    /// The packet that is being parsed.
    pub packet: Packet,

    /// This packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    pub recursion_depth: u8,

    // The reader.
    //
    // We can't make `reader` generic, because the type of
    // `BufferedReader` that is returned is not a function of the
    // arguments, and Rust figures out a generic's type by looking at
    // the calling site, not the function's implementation.  Consider
    // what happens when we parse a compressed data packet: we return
    // a Decompressor (in fact, the actual type is only known at
    // run-time!).
    reader: Box<BufferedReader<BufferedReaderState> + 'a>,

    // Whether the caller read the packets content.  If so, then we
    // can't recurse, because we're missing some of the packet!
    content_was_read: bool,

    // The `PacketParser`'s settings
    settings: PacketParserSettings,
}

impl <'a> std::fmt::Debug for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketParser")
            .field("packet", &self.packet)
            .field("recursion_depth", &self.recursion_depth)
            .field("reader", &self.reader)
            .field("content_was_read", &self.content_was_read)
            .field("settings", &self.settings)
            .finish()
    }
}

// The return value of PacketParser::parse.
enum PacketParserOrBufferedReader<'a> {
    PacketParser(PacketParser<'a>),
    BufferedReader(Box<BufferedReader<BufferedReaderState> + 'a>),
}

// Converts an indentation level to whitespace.
fn indent(depth: u8) -> &'static str {
    let s = "                                                  ";
    return &s[0..cmp::min(depth, s.len() as u8) as usize];
}

impl <'a> PacketParser<'a> {
    /// Starts parsing an OpenPGP message stored in a `BufferedReader` object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_buffered_reader<R: BufferedReader<BufferedReaderState> + 'a>(bio: R)
            -> Result<Option<PacketParser<'a>>> {
        PacketParserBuilder::from_buffered_reader(bio)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a `std::io::Read` object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_reader<R: io::Read + 'a>(reader: R)
            -> Result<Option<PacketParser<'a>>> {
        PacketParserBuilder::from_reader(reader)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a file named `path`.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<Option<PacketParser<'a>>> {
        PacketParserBuilder::from_file(path)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a buffer.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<Option<PacketParser<'a>>> {
        PacketParserBuilder::from_bytes(bytes)?.finalize()
    }

    // Returns a packet parser for the next OpenPGP packet in the
    // stream.  If there are no packets left, this function returns
    // `bio`.
    fn parse<R: BufferedReader<BufferedReaderState> + 'a>
            (mut bio: R, settings: &PacketParserSettings,
             recursion_depth: usize)
            -> Result<PacketParserOrBufferedReader<'a>> {
        if settings.trace {
            eprintln!("{}PacketParser::parse(depth: {}): reading packet",
                      indent(recursion_depth as u8), recursion_depth);
        }

        // When header encounters an EOF, it returns an error.  But,
        // we want to return None.  Try a one byte read.
        if bio.data(1)?.len() == 0 {
            if settings.trace {
                eprintln!("{}PacketParser::parse() -> EOF",
                          indent(recursion_depth as u8));
            }
            return Ok(
                PacketParserOrBufferedReader::BufferedReader(Box::new(bio)));
        }

        let header = header(&mut bio)?;
        let bio : Box<BufferedReader<BufferedReaderState>>
            = match header.length {
                BodyLength::Full(len) => {
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): \
                                   Pushing a limitor ({} bytes)",
                                  indent(recursion_depth as u8), len);
                    }
                    Box::new(BufferedReaderLimitor::with_cookie(
                        bio, len as u64,
                        BufferedReaderState::new(recursion_depth)))
                },
                BodyLength::Partial(len) => {
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): \
                                   Pushing a partial body chunk decoder",
                                  indent(recursion_depth as u8));
                    }
                    Box::new(BufferedReaderPartialBodyFilter::with_cookie(
                        bio, len,
                        BufferedReaderState::new(recursion_depth)))
                },
                BodyLength::Indeterminate => {
                    // XXX: If bio is already boxed (`buffered_reader`
                    // provides an impl of `BufferedReader` for
                    // `Box<BufferedReader>`, this is going to add
                    // another level of indirection.  It would be nice
                    // to avoid this level of indirection, but I have
                    // no idea how...
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): Indeterminate \
                                   length packet, not adding a filter.",
                                  indent(recursion_depth as u8));
                    }
                    Box::new(bio)
                },
        };

        let tag = header.ctb.tag;
        let result = match tag {
            Tag::Signature =>
                Signature::parse(bio, recursion_depth)?,
            Tag::PublicSubkey =>
                Key::parse(bio, recursion_depth, tag)?,
            Tag::PublicKey =>
                Key::parse(bio, recursion_depth, tag)?,
            Tag::SecretKey =>
                Key::parse(bio, recursion_depth, tag)?,
            Tag::SecretSubkey =>
                Key::parse(bio, recursion_depth, tag)?,
            Tag::UserID =>
                UserID::parse(bio, recursion_depth)?,
            Tag::UserAttribute =>
                UserAttribute::parse(bio, recursion_depth)?,
            Tag::Literal =>
                Literal::parse(bio, recursion_depth)?,
            Tag::CompressedData =>
                CompressedData::parse(bio, recursion_depth)?,
            Tag::SKESK =>
                SKESK::parse(bio, recursion_depth)?,
            _ =>
                Unknown::parse(bio, recursion_depth, tag)?,
        };

        if settings.trace {
            eprintln!("{}PacketParser::parse() -> {:?}",
                      indent(recursion_depth as u8), result.packet.tag());
        }

        return Ok(PacketParserOrBufferedReader::PacketParser(result));
    }

    /// Finishes parsing the current packet and starts parsing the
    /// following one.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  (See
    /// [`PacketParsererBuilder`] for how to configure this.)  It then
    /// creates a new packet parser for the following packet.  If the
    /// current packet is a container, this function does *not*
    /// recurse into the container, but skips any packets it contains.
    /// To recurse into the container, use the [`recurse()`] method.
    ///
    ///   [`PacketParsererBuilder`]: parse/struct.PacketParserBuilder.html
    ///   [`recurse()`]: #method.recurse
    ///
    /// The return value is a tuple containing:
    ///
    ///   - A `Packet` holding the fully processed old packet;
    ///
    ///   - The old packet's recursion depth;
    ///
    ///   - A `PacketParser` holding the new packet;
    ///
    ///   - And, the recursion depth of the new packet.
    ///
    /// A recursion depth of 0 means that the packet is a top-level
    /// packet, a recursion depth of 1 means that the packet is an
    /// immediate child of a top-level-packet, etc.
    ///
    /// Since the packets are laid out in depth-first order and all
    /// interior nodes are visited, we know that if the recursion
    /// depth is the same, then the packets are siblings (they have a
    /// common parent) and not, e.g., cousins (they have a common
    /// grandparent).  This is because, if we move up the tree, the
    /// only way to move back down is to first visit a new container
    /// (e.g., an aunt).
    ///
    /// Using the two positions, we can compute the change in depth as
    /// new_depth - old_depth.  Thus, if the change in depth is 0, the
    /// two packets are siblings.  If the value is 1, the old packet
    /// is a container, and the new packet is its first child.  And,
    /// if the value is -1, the new packet is contained in the old
    /// packet's grandparent.  The idea is illustrated below:
    ///
    /// ```text
    ///             ancestor
    ///             |       \
    ///            ...      -n
    ///             |
    ///           grandparent
    ///           |          \
    ///         parent       -1
    ///         |      \
    ///      packet    0
    ///         |
    ///         1
    /// ```
    ///
    /// Note: since this function does not automatically recurse into
    /// a container, the change in depth will always be non-positive.
    /// If the current container is empty, this function DOES pop that
    /// container off the container stack, and returns the following
    /// packet in the parent container.
    pub fn next(mut self)
            -> Result<(Packet, isize, Option<PacketParser<'a>>, isize)> {
        if self.settings.trace {
            eprintln!("{}PacketParser::next: Finished processing {:?} packet \
                       (recursion depth: {}, reader level {}",
                      indent(self.recursion_depth),
                      self.packet.tag(), self.recursion_depth,
                      self.reader.cookie_ref().level);
        }

        // Finish processing the current packet.
        self.finish();

        // Remove any filters that apply to the current packet parser.
        // Normally, this is just a limitor of some sort.
        let mut reader = self.reader;
        assert!(reader.cookie_ref().level <= self.recursion_depth as usize + 1);
        while reader.cookie_ref().level > self.recursion_depth as usize {
            if self.settings.trace {
                eprintln!("{}PacketParser::next: popping level {} reader",
                          indent(self.recursion_depth),
                          reader.cookie_ref().level);
            }
            reader.drop_eof().unwrap();
            reader = reader.into_inner().unwrap();
        }
        if self.settings.trace {
           eprintln!("{}PacketParser::next: New top reader is at level {}",
                     indent(self.recursion_depth),
                     reader.cookie_ref().level);
        }

        // Stash some fields that we'll put in the new packet.
        let settings = self.settings;
        let packet = self.packet;

        // Now read the next packet.
        let old_recursion_depth = self.recursion_depth;
        let mut recursion_depth = self.recursion_depth;
        loop {
            // Parse the next packet.
            let pp = PacketParser::parse(reader, &settings,
                                         recursion_depth as usize)?;
            match pp {
                PacketParserOrBufferedReader::BufferedReader(reader2) => {
                    // We got EOF on the current container.  The
                    // container at recursion depth n is empty.  Pop
                    // it and any filters for it, i.e., those at level
                    // n (e.g., the limitor that caused us to hit
                    // EOF), and then try again.

                    if settings.trace {
                        eprintln!("{}PacketParser::next(): \
                                   got EOF reading next packet at depth {}, \
                                   popping container",
                                  indent(recursion_depth), recursion_depth);
                    }

                    if recursion_depth == 0 {
                        if settings.trace {
                            eprintln!("{}PacketParser::next(): \
                                       Popped top-level container, done \
                                       reading message",
                                      indent(recursion_depth));
                        }
                        return Ok((packet, old_recursion_depth as isize,
                                   None, 0));
                    } else {
                        assert!(recursion_depth > 0);
                        reader = reader2;
                        recursion_depth -= 1;

                        // The top filter can't have a level larger
                        // than n + 1 (but it is entirely possible
                        // that it has a smaller level if there were
                        // no constraints on it, e.g., the packet has
                        // an indeterminate length).
                        assert!(reader.cookie_ref().level
                                <= recursion_depth as usize + 1);
                        let mut pops = 0;
                        while reader.cookie_ref().level
                                == recursion_depth as usize + 1 {
                            reader.drop_eof().unwrap();
                            reader = reader.into_inner().unwrap();
                            pops += 1;
                        }

                        if settings.trace {
                            eprintln!("{}PacketParser::next: \
                                       Popped {} readers; \
                                       top reader's level: {}",
                                      indent(recursion_depth), pops,
                                      reader.cookie_ref().level);
                        }
                    }
                },
                PacketParserOrBufferedReader::PacketParser(mut pp) => {
                    if settings.trace {
                        eprintln!("{}PacketParser::next() -> \
                                   {:?} at depth {}, level {:?}",
                                  indent(recursion_depth),
                                  pp.packet.tag(),
                                  recursion_depth,
                                  pp.cookie_ref().level);
                    }

                    pp.settings = settings;

                    return Ok((packet, old_recursion_depth as isize,
                               Some(pp), recursion_depth as isize));
                }
            }
        };
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one, recursing if possible.
    ///
    /// This method is similar to the [`next()`] method (see that
    /// method for more details), but if the current packet is a
    /// container (and we haven't reached the maximum recursion depth,
    /// and the user hasn't started reading the packet's contents), we
    /// recurse into the container, and return a `PacketParser` for
    /// its first child.  Otherwise, we return the next packet in the
    /// packet stream.  If this function recurses, then the new
    /// packet's position will be old_position + 1; because we always
    /// visit interior nodes, we can't recurse more than one level at
    /// a time.
    ///
    ///   [`next()`]: #method.next
    pub fn recurse(self)
            -> Result<(Packet, isize, Option<PacketParser<'a>>, isize)> {
        if self.settings.trace {
            eprintln!("{}PacketParser::recurse({:?})",
                      indent(self.recursion_depth), self.packet.tag());
        }

        match self.packet {
            // Packets that recurse.
            Packet::CompressedData(_) => {
                if self.recursion_depth
                    >= self.settings.max_recursion_depth {
                    if self.settings.trace {
                        eprintln!("{}PacketParser::recurse(): not recursing, \
                                   into the {:?} packet, maximum recursion \
                                   depth reached ({})",
                                  indent(self.recursion_depth), self.packet.tag(),
                                  self.settings.max_recursion_depth);
                    }

                    // Drop through.
                } else if self.content_was_read {
                    if self.settings.trace {
                        eprintln!("{}PacketParser::recurse(): not recursing \
                                   into the {:?} packet, some data was \
                                   already read.",
                                  indent(self.recursion_depth), self.packet.tag());
                    }

                    // Drop through.
                } else {
                    match PacketParser::parse(self.reader, &self.settings,
                            self.recursion_depth as usize + 1)? {
                        PacketParserOrBufferedReader::PacketParser(mut pp) => {
                            pp.settings = self.settings;

                            if pp.settings.trace {
                                eprintln!("{}PacketParser::recurse(): \
                                           recursed into the {:?} packet, got a {:?}.",
                                          indent(self.recursion_depth),
                                          self.packet.tag(),
                                          pp.packet.tag());
                            }

                            return Ok((self.packet,
                                       self.recursion_depth as isize,
                                       Some(pp),
                                       self.recursion_depth as isize + 1));
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
                | Packet::UserID(_) | Packet::UserAttribute(_)
                | Packet::Literal(_) | Packet::SKESK(_) => {
                // Drop through.
                if self.settings.trace {
                    eprintln!("{}PacketParser::recurse(): A {:?} packet is \
                               not a container, not recursing",
                              indent(self.recursion_depth), self.packet.tag());
                }
            },
        }

        // No recursion.
        self.next()
    }

    /// Causes the PacketParser to buffer the packet's contents.
    ///
    /// The packet's contents are stored in `packet.content`.  In
    /// general, you should avoid buffering a packet's content and
    /// prefer streaming its content unless you are certain that the
    /// content is small.
    ///
    /// ```rust
    /// # use openpgp::Result;
    /// # use openpgp::Packet;
    /// # use openpgp::parse::PacketParser;
    /// # use std::string::String;
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8]) -> Result<()> {
    /// let mut ppo = PacketParser::from_bytes(message_data)?;
    /// while let Some(mut pp) = ppo {
    ///     // Process the packet.
    ///
    ///     if let Packet::Literal(_) = pp.packet {
    ///         pp.buffer_unread_content();
    ///         if let Some(ref body) = pp.packet.body {
    ///             println!("{}", String::from_utf8_lossy(body));
    ///         }
    ///     }
    ///
    ///     // Get the next packet.
    ///     let (_packet, _packet_depth, tmp, _pp_depth) = pp.recurse()?;
    ///     ppo = tmp;
    /// }
    /// # return Ok(());
    /// # }
    pub fn buffer_unread_content(&mut self) -> Result<&[u8]> {
        let mut rest = self.steal_eof()?;
        if rest.len() > 0 {
            if let Some(mut body) = self.packet.body.take() {
                body.append(&mut rest);
                self.packet.body = Some(body);
            } else {
                self.packet.body = Some(rest);
            }

            Ok(&self.packet.body.as_ref().unwrap()[..])
        } else {
            Ok(&b""[..])
        }
    }

    /// Finishes parsing the current packet.
    ///
    /// By default, this drops any unread content.  Use, for instance,
    /// `PacketParserBuild` to customize the default behavior.
    // Note: this function is public and may be called multiple times!
    pub fn finish<'b>(&'b mut self) -> &'b Packet {
        if self.settings.buffer_unread_content {
            if self.settings.trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           buffering unread content",
                          indent(self.recursion_depth), self.packet.tag(),
                          self.recursion_depth);
            }

            if let Err(_err) = self.buffer_unread_content() {
                // XXX: We should propagate the error.
                unimplemented!();
            }
        } else {
            if self.settings.trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           dropping unread content",
                          indent(self.recursion_depth), self.packet.tag(),
                          self.recursion_depth);
            }

            self.reader.drop_eof().unwrap();
        }

        return &mut self.packet;
    }
}

/// This interface allows a caller to read the content of a
/// `PacketParser` using the `Read` interface.  This is essential to
/// supporting streaming operation.
///
/// Note: it is safe to mix the use of the `std::io::Read` and
/// `BufferedReader` interfaces.
impl<'a> io::Read for PacketParser<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.content_was_read = true;
        return buffered_reader_generic_read_impl(self, buf);
    }
}

/// This interface allows a caller to read the content of a
/// `PacketParser` using the `BufferedReader` interface.  This is
/// essential to supporting streaming operation.
///
/// Note: it is safe to mix the use of the `std::io::Read` and
/// `BufferedReader` interfaces.
impl<'a> BufferedReader<BufferedReaderState> for PacketParser<'a> {
    fn buffer(&self) -> &[u8] {
        return self.reader.buffer();
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        return self.reader.data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        return self.reader.data_hard(amount);
    }

    fn data_eof(&mut self) -> io::Result<&[u8]> {
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

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        if amount > 0 {
            self.content_was_read = true;
        }
        return self.reader.data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        if amount > 0 {
            self.content_was_read = true;
        }
        return self.reader.data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> io::Result<u16> {
        self.content_was_read = true;
        return self.reader.read_be_u16();
    }

    fn read_be_u32(&mut self) -> io::Result<u32> {
        self.content_was_read = true;
        return self.reader.read_be_u32();
    }

    fn steal(&mut self, amount: usize) -> io::Result<Vec<u8>> {
        self.content_was_read = true;
        return self.reader.steal(amount);
    }

    fn steal_eof(&mut self) -> io::Result<Vec<u8>> {
        self.content_was_read = true;
        return self.reader.steal_eof();
    }

    fn drop_eof(&mut self) -> io::Result<()> {
        self.content_was_read = true;
        return self.reader.drop_eof();
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<BufferedReaderState>> {
        None
    }

    fn get_ref(&self) -> Option<&BufferedReader<BufferedReaderState>> {
        None
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<BufferedReaderState> + 'b>>
            where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: BufferedReaderState)
            -> BufferedReaderState {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &BufferedReaderState {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut BufferedReaderState {
        self.reader.cookie_mut()
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
    //
    //   [ compressed data [ literal data ] ]
    //
    // packet is the compressed data packet; ppo is the literal data
    // packet.
    let (packet, packet_depth, ppo, pp_depth) = pp.recurse().unwrap();
    if let Packet::CompressedData(_) = packet {
    } else {
        panic!("Expected a compressed data packet.");
    }

    let relative_position = pp_depth - packet_depth;
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
    let (packet, _, ppo, _) = pp.recurse().unwrap();
    assert!(ppo.is_none());
    // Since we read all of the data, we expect content to be None.
    assert!(packet.body.is_none());
}

impl Message {
    // Reads all of the packets from a `PacketParser`, and turns them
    // into a message.  Note: this assumes that `ppo` points to a
    // top-level packet.
    fn assemble<'a>(ppo: Option<PacketParser<'a>>) -> Result<Message> {
        // Things are not going to work out if we don't start with a
        // top-level packet.  We should only pop until
        // ppo.recursion_depth and leave the rest of the message, but
        // it is hard to imagine that that is what the caller wants.
        // Instead of hiding that error, fail fast.
        if let Some(ref pp) = ppo {
            assert_eq!(pp.recursion_depth, 0);
        }

        // Create a top-level container.
        let mut top_level = Container::new();

        let mut last_position = 0;

        if ppo.is_none() {
            // Empty message.
            return Ok(Message::from_packets(Vec::new()));
        }
        let mut pp = ppo.unwrap();

        'outer: loop {
            let (mut packet, mut position, mut ppo, _) = pp.recurse()?;

            let mut relative_position : isize = position - last_position;
            assert!(relative_position <= 1);

            // Find the right container for `packet`.
            let mut container = &mut top_level;
            // If we recurse, don't create the new container here.
            for _ in 0..(position - if relative_position > 0 { 1 } else { 0 }) {
                // Do a little dance to prevent container from
                // being reborrowed and preventing us from
                // assigning to it.
                let tmp = container;
                let packets_len = tmp.packets.len();
                let p = &mut tmp.packets[packets_len - 1];

                container = p.children.as_mut().unwrap();
            }

            if relative_position < 0 {
                relative_position = 0;
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

                pp = ppo.unwrap();

                last_position = position;
                position = pp.recursion_depth as isize;
                relative_position = position - last_position;
                if position < last_position {
                    // There was a pop, we need to restart from the
                    // root.
                    break;
                }

                let result = pp.recurse()?;
                packet = result.0;
                assert_eq!(position, result.1);
                ppo = result.2;
            }
        }

        return Ok(Message { top_level: top_level });
    }

    /// Deserializes the OpenPGP message stored in a `BufferedReader`
    /// object.
    ///
    /// Although this method is easier to use to parse an OpenPGP
    /// message than a [`PacketParser`] or a [`MessageParser`], this
    /// interface buffers the whole message in memory.  Thus, the
    /// caller must be certain that the *deserialized* message is not
    /// too large.
    ///
    /// Note: this interface *does* buffer the contents of packets.
    ///
    ///   [`PacketParser`]: parse/struct.PacketParser.html
    ///   [`MessageParser`]: parse/struct.MessageParser.html
    pub fn from_buffered_reader<R: BufferedReader<BufferedReaderState>>(bio: R)
            -> Result<Message> {
        PacketParserBuilder::from_buffered_reader(bio)?
            .buffer_unread_content()
            .to_message()
    }

    /// Deserializes the OpenPGP message stored in a `std::io::Read`
    /// object.
    ///
    /// See `from_buffered_reader` for more details and caveats.
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Message> {
        let bio = BufferedReaderGeneric::with_cookie(
            reader, None, BufferedReaderState::default());
        Message::from_buffered_reader(bio)
    }

    /// Deserializes the OpenPGP message stored in the file named by
    /// `path`.
    ///
    /// See `from_buffered_reader` for more details and caveats.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Message> {
        Message::from_reader(File::open(path)?)
    }

    /// Deserializes the OpenPGP message stored in the provided buffer.
    ///
    /// See `from_buffered_reader` for more details and caveats.
    pub fn from_bytes(data: &[u8]) -> Result<Message> {
        let bio = BufferedReaderMemory::with_cookie(
            data, BufferedReaderState::default());
        Message::from_buffered_reader(bio)
    }
}

#[cfg(test)]
mod message_test {
    use super::path_to;
    use super::{Message, Packet, PacketParser, PacketParserBuilder};

    use std::io::Read;

    #[test]
    fn deserialize_test_1 () {
        // XXX: This test should be more thorough.  Right now, we mostly
        // just rely on the fact that an assertion is not thrown.

        // A flat message.
        let message = Message::from_bytes(bytes!("public-key.gpg")).unwrap();
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
        let message = Message::from_file(&path).unwrap();
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
        let message = Message::from_file(&path).unwrap();
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

    // dkg's key contains packets from different OpenPGP
    // implementations.  And, it even includes some v3 signatures.
    //
    // lutz's key is a v3 key.
    #[test]
    fn torture() {
        let data = bytes!("../keys/dkg.gpg");
        let mut mp = PacketParserBuilder::from_bytes(data).unwrap()
            //.trace()
            .buffer_unread_content()
            .to_message_parser().unwrap();

        while mp.recurse() {
            //let pp = mp.ppo.as_mut().unwrap();
            //eprintln!("{:?}", pp);
        }
        let message = mp.finish();
        //message.pretty_print();
        assert_eq!(message.children().len(), 1450);

        let data = bytes!("../keys/lutz.gpg");
        let mut mp = PacketParserBuilder::from_bytes(data).unwrap()
            //.trace()
            .buffer_unread_content()
            .to_message_parser().unwrap();

        while mp.recurse() {
            let pp = mp.ppo.as_mut().unwrap();
            eprintln!("{:?}", pp);
        }
        let message = mp.finish();
        message.pretty_print();
        assert_eq!(message.children().len(), 77);
    }

    #[test]
    fn compression_quine_test_1 () {
        // Use the Message::from_file interface to parse an OpenPGP
        // quine.
        let path = path_to("compression-quine.gpg");
        let max_recursion_depth = 128;
        let message = PacketParserBuilder::from_file(path).unwrap()
            .max_recursion_depth(max_recursion_depth)
            .to_message().unwrap();

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
        let max_recursion_depth = 255;
        let mut ppo : Option<PacketParser>
            = PacketParserBuilder::from_file(path).unwrap()
                .max_recursion_depth(max_recursion_depth)
                .finalize().unwrap();

        let mut count : usize = 0;
        loop {
            if let Some(pp2) = ppo {
                count += 1;

                let (_packet, packet_depth, pp2, pp_depth)
                    = pp2.recurse().unwrap();
                eprintln!("{}, {}", packet_depth, pp_depth);
                assert_eq!(packet_depth as usize, count - 1);
                if pp2.is_some() {
                    assert_eq!(pp_depth as usize, count);
                }
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

        let ppo = PacketParserBuilder::from_file(
                path_to("compressed-data-algo-1.gpg")).unwrap()
            .buffer_unread_content()
            .finalize().unwrap();

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
        let (mut packet, _, ppo, _) = pp.next().unwrap();
        assert!(ppo.is_none());

        // Get the rest of the content and put the initial byte that
        // we stole back.
        let mut content = packet.body.take().unwrap();
        content.insert(0, data[0]);

        let content = &content.into_boxed_slice()[..];
        let ppo = PacketParser::from_bytes(content).unwrap();
        let pp = ppo.unwrap();
        if let Packet::Literal(_) = pp.packet {
        } else {
            panic!("Expected a literal packet!");
        }

        // And we're done...
        let (_packet, _, ppo, _) = pp.next().unwrap();
        assert!(ppo.is_none());
    }
}
