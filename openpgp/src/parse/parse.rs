use std;
use std::io;
use std::io::prelude::*;
use std::cmp;
use std::str;
use std::mem;
use std::path::Path;
use std::fs::File;

use ::buffered_reader::*;
use mpis::MPIs;
use Error;
use HashAlgo;
use symmetric::{SymmetricAlgo, Decryptor, BufferedReaderDecryptor};

use super::*;

mod partial_body;
use self::partial_body::BufferedReaderPartialBodyFilter;

pub mod subpacket;
pub use self::subpacket::SubpacketArea;
pub mod key;

mod message_parser;
pub use self::message_parser::MessageParser;

mod hashed_reader;
pub use self::hashed_reader::HashedReader;

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

// Converts an indentation level to whitespace.
fn indent(depth: u8) -> &'static str {
    let s = "                                                  ";
    return &s[0..cmp::min(depth, s.len() as u8) as usize];
}

/// The default amount of acceptable nesting.  Typically, we expect a
/// message to looking like:
///
///   [ encryption container: [ signature: [ compressioned data: [ literal data ]]]]
///
/// So, this should be more than enough.
const MAX_RECURSION_DEPTH : u8 = 16;

/// Binds a parser providing a local 'rtry!' macro.
macro_rules! bind_ptry {
    ($parser:expr) => {

        /// Handles errors like try!, returns Unknown packet on
        /// truncation.
        macro_rules! ptry {
            ($e:expr) => {
                match $e {
                    Ok(b) => {
                        Ok(b)
                    },
                    Err(e) =>
                        if let io::ErrorKind::UnexpectedEof = e.kind() {
                            return $parser.fail("truncated")
                        } else {
                            Err(e)
                        },
                }?
            };
        }
    };
}

// Packet headers.

impl CTB {
    /// Parses a CTB as described in [Section 4.2 of RFC 4880].  This
    /// function parses both new and old format ctbs.
    ///
    ///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
    pub fn from_ptag(ptag: u8) -> Result<CTB> {
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
                    tag: tag.into()
                }})
        } else {
            let tag = (ptag & 0b0011_1100) >> 2;
            let length_type = ptag & 0b0000_0011;

            CTB::Old(CTBOld {
                common: CTBCommon {
                    tag: tag.into(),
                },
                length_type: PacketLengthType::from_numeric(length_type).unwrap(),
            })
        };

        Ok(ctb)
    }
}

#[test]
fn ctb() {
    // 0x99 = public key packet
    if let CTB::Old(ctb) = CTB::from_ptag(0x99).unwrap() {
        assert_eq!(ctb.tag, Tag::PublicKey);
        assert_eq!(ctb.length_type, PacketLengthType::TwoOctets);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xa3 = old compressed packet
    if let CTB::Old(ctb) = CTB::from_ptag(0xa3).unwrap() {
        assert_eq!(ctb.tag, Tag::CompressedData);
        assert_eq!(ctb.length_type, PacketLengthType::Indeterminate);
    } else {
        panic!("Expected an old format packet.");
    }

    // 0xcb: new literal
    if let CTB::New(ctb) = CTB::from_ptag(0xcb).unwrap() {
        assert_eq!(ctb.tag, Tag::Literal);
    } else {
        panic!("Expected a new format packet.");
    }
}

impl BodyLength {
    /// Decodes a new format body length as described in [Section
    /// 4.2.2 of RFC 4880].
    ///
    ///   [Section 4.2.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.2
    pub fn parse_new_format<T: BufferedReader<C>, C> (bio: &mut T)
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

    /// Decodes an old format body length as described in [Section
    /// 4.2.1 of RFC 4880].
    ///
    ///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
    pub fn parse_old_format<T: BufferedReader<C>, C>
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
}

#[test]
fn body_length_new_format() {
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

impl Header {
    /// Parses an OpenPGP packet's header as described in [Section 4.2 of RFC 4880].
    ///
    ///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
    pub fn parse<R: BufferedReader<C>, C> (bio: &mut R)
                                           -> Result<Header> {
        let ctb = CTB::from_ptag(bio.data_consume_hard(1)?[0])?;
        let length = match ctb {
            CTB::New(_) => BodyLength::parse_new_format(bio)?,
            CTB::Old(ref ctb) => BodyLength::parse_old_format(bio, ctb.length_type)?,
        };
        return Ok(Header { ctb: ctb, length: length });
    }
}

impl S2K {
    pub fn parse_naked<R: io::Read>(r: R) -> io::Result<Self> {
        let bio = BufferedReaderGeneric::with_cookie(
            r, None, Cookie::default());
        let mut parser = PacketParser::new_naked(Box::new(bio));
        Self::parse(&mut parser)
    }

    /// Reads a S2K from `r`.
    pub(crate) fn parse<'a>(pp: &mut PacketParser<'a>) -> io::Result<Self> {
        let s2k = pp.parse_u8("s2k_type")?;
        let ret = match s2k {
            0 => S2K::Simple{
                hash: HashAlgo::from(pp.parse_u8("s2k_hash_algo")?),
            },
            1 => S2K::Salted{
                hash: HashAlgo::from(pp.parse_u8("s2k_hash_algo")?),
                salt: Self::read_salt(pp)?,
            },
            3 => S2K::Iterated{
                hash: HashAlgo::from(pp.parse_u8("s2k_hash_algo")?),
                salt: Self::read_salt(pp)?,
                iterations: S2K::decode_count(pp.parse_u8("s2k_count")?),
            },
            100...110 => S2K::Private(s2k),
            u => S2K::Unknown(u),
        };

        Ok(ret)
    }

    fn read_salt<'a,>(pp: &mut PacketParser<'a>) -> io::Result<[u8; 8]> {
        let mut b = [0u8; 8];
        b.copy_from_slice(&pp.parse_bytes("s2k_salt", 8)?);

        Ok(b)
    }
}

impl Unknown {
    /// Parses the body of any packet and returns an Unknown.
    fn parse<'a>(pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        let tag = pp.header.ctb.tag;
        pp.decrypted(false).ok(Packet::Unknown(Unknown {
            common: Default::default(),
            tag: tag,
        }))
    }
}

pub fn to_unknown_packet<R: Read>(reader: R)
        -> Result<Unknown> {
    let mut reader = BufferedReaderGeneric::with_cookie(
        reader, None, Cookie::default());
    let header = Header::parse(&mut reader)?;

    let reader : Box<BufferedReader<Cookie>>
        = match header.length {
            BodyLength::Full(len) =>
                Box::new(BufferedReaderLimitor::with_cookie(
                    Box::new(reader), len as u64, Cookie::default())),
            BodyLength::Partial(len) =>
                Box::new(BufferedReaderPartialBodyFilter::with_cookie(
                    reader, len, true, Cookie::default())),
            _ => Box::new(reader),
    };

    let parser = PacketParser::new(
        reader, Default::default(), 0, header);
    let mut pp = Unknown::parse(parser)?;
    pp.buffer_unread_content()?;
    pp.finish();

    if let Packet::Unknown(packet) = pp.packet {
        Ok(packet)
    } else {
        panic!("Internal inconsistency.");
    }
}

impl Signature {
    fn parse_naked(value: &[u8]) -> Result<Packet> {
        let bio = BufferedReaderMemory::with_cookie(
            value, Cookie::default());
        let parser = PacketParser::new_naked(Box::new(bio));

        let mut pp = Signature::parse(parser, None)?;
        pp.buffer_unread_content()?;
        pp.finish();

        match pp.packet {
            Packet::Signature(_) => Ok(pp.packet),
            Packet::Unknown(_) => Ok(pp.packet),
            _ => panic!("Internal inconsistency."),
        }
    }

    /// Parses the body of a signature packet.
    fn parse<'a>(mut pp: PacketParser<'a>,
                 computed_hash: Option<(HashAlgo, Box<Hash>)>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        let version = ptry!(pp.parse_u8("version"));

        if version != 4 {
            if TRACE {
                eprintln!("{}Signature::parse: Ignoring verion {} packet.",
                          indent(pp.recursion_depth as u8), version);
            }
            return pp.fail("unknown version");
        }

        let sigtype = ptry!(pp.parse_u8("sigtype"));
        let pk_algo = ptry!(pp.parse_u8("pk_algo"));
        let hash_algo = ptry!(pp.parse_u8("hash_algo"));
        let hashed_area_len = ptry!(pp.parse_be_u16("hashed_area_len"));
        let hashed_area = ptry!(pp.parse_bytes("hashed_area",
                                            hashed_area_len as usize));
        let unhashed_area_len = ptry!(pp.parse_be_u16("unhashed_area_len"));
        let unhashed_area = ptry!(pp.parse_bytes("unhashed_area",
                                              unhashed_area_len as usize));
        let hash_prefix1 = ptry!(pp.parse_u8("hash_prefix1"));
        let hash_prefix2 = ptry!(pp.parse_u8("hash_prefix2"));
        let mpis = ptry!(pp.parse_bytes_eof("mpis"));
        pp.commit()?;

        let mut sig = Signature {
            common: Default::default(),
            version: version,
            sigtype: sigtype,
            pk_algo: pk_algo,
            hash_algo: hash_algo.into(),
            hashed_area: SubpacketArea::new(hashed_area),
            unhashed_area: SubpacketArea::new(unhashed_area),
            hash_prefix: [hash_prefix1, hash_prefix2],
            mpis: MPIs::parse(mpis),
            computed_hash: None,
        };

        if let Some((algo, mut hash)) = computed_hash {
            sig.hash(&mut hash);

            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);

            sig.computed_hash = Some((algo, digest));
        }

        pp.ok(Packet::Signature(sig))
    }
}

#[test]
fn signature_parser_test () {
    let data = bytes!("sig.gpg");

    {
        let pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Full(307));
        if let Packet::Signature(ref p) = pp.packet {
            assert_eq!(p.version, 4);
            assert_eq!(p.sigtype, 0);
            assert_eq!(p.pk_algo, 1);
            assert_eq!(p.hash_algo, HashAlgo::SHA512);
            assert_eq!(p.hashed_area.data.len(), 29);
            assert_eq!(p.unhashed_area.data.len(), 10);
            assert_eq!(p.hash_prefix, [0x65u8, 0x74]);
            assert_eq!(p.mpis.raw.len(), 258);
        } else {
            panic!("Wrong packet!");
        }
    }
}

impl OnePassSig {
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        let version = ptry!(pp.parse_u8("version"));
        if version != 3 {
            if TRACE {
                eprintln!("{}OnePassSig::parse: Ignoring verion {} packet",
                          indent(pp.recursion_depth as u8), version);
            }

            // Unknown version.  Return an unknown packet.
            return pp.fail("unknown version");
        }

        let sigtype = ptry!(pp.parse_u8("sigtype"));
        let hash_algo = ptry!(pp.parse_u8("hash_algo"));
        let pk_algo = ptry!(pp.parse_u8("pk_algo"));
        let mut issuer = [0u8; 8];
        issuer.copy_from_slice(&ptry!(pp.parse_bytes("issuer", 8)));
        let last = ptry!(pp.parse_u8("last"));
        pp.commit()?;

        // We create an empty hashed reader even if we don't support
        // the hash algorithm so that we have something to match
        // against when we get to the Signature packet.
        let mut algos = Vec::new();
        let hash_algo = HashAlgo::from(hash_algo);

        if hash_algo.is_supported() {
            algos.push(hash_algo);
        }

        match pp.state {
            State::Body(reader) => {
                // We can't push the HashedReader on the BufferedReader stack:
                // when we finish processing this OnePassSig packet, it will
                // be popped.  Instead, we need to insert it at the next
                // higher level.  Unfortunately, this isn't possible.  But,
                // since we're done reading the current packet, we can pop the
                // readers associated with it, and then push the HashedReader.
                // This is a bit of a layering violation, but I (Neal) can't
                // think of a more elegant solution.

                let recursion_depth = pp.recursion_depth;
                assert!(reader.cookie_ref().level <= Some(recursion_depth as isize));
                let reader = buffered_reader_stack_pop(Box::new(reader),
                                                       recursion_depth as isize);

                let mut reader = HashedReader::new(
                    reader, HashesFor::Signature, algos);
                reader.cookie_mut().level = Some(recursion_depth as isize - 1);

                if TRACE {
                    eprintln!("{}OnePassSig::parse: Pushed a hashed reader, level {:?}",
                              indent(recursion_depth as u8),
                              reader.cookie_mut().level);
                }

                // We add an empty limitor on top of the hashed reader,
                // because when we are done processing a packet,
                // PacketParser::finish discards any unread data from the top
                // reader.  Since the top reader is the HashedReader, this
                // discards any following packets.  To prevent this, we push a
                // Limitor on the reader stack.
                let mut reader = BufferedReaderLimitor::with_cookie(
                    Box::new(reader), 0, Cookie::default());
                reader.cookie_mut().level = Some(recursion_depth as isize);

                pp.state = State::Body(Box::new(reader));
            },
            State::Header(_) =>
                unreachable!("committed above"),
        }

        pp.ok(Packet::OnePassSig(OnePassSig {
            common: Default::default(),
            version: version,
            sigtype: sigtype,
            hash_algo: hash_algo.into(),
            pk_algo: pk_algo,
            issuer: issuer,
            last: last,
        }))
    }
}

#[test]
fn one_pass_sig_parser_test () {
    // This test assumes that the first packet is a OnePassSig packet.
    let data = bytes!("signed-1.gpg");
    let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
    let p = pp.finish();
    // eprintln!("packet: {:?}", p);

    if let &Packet::OnePassSig(ref p) = p {
        assert_eq!(p.version, 3);
        assert_eq!(p.sigtype, 0);
        assert_eq!(p.hash_algo, HashAlgo::SHA512);
        assert_eq!(p.pk_algo, 1);
        assert_eq!(to_hex(&p.issuer[..], false), "7223B56678E02528");
        assert_eq!(p.last, 1);
    } else {
        panic!("Wrong packet!");
    }
}

#[test]
fn one_pass_sig_test () {
    struct Test<'a> {
        filename: &'a str,
        hash_prefix: Vec<[u8; 2]>,
    };

    let tests = [
            Test {
                filename: "signed-1.gpg",
                hash_prefix: vec![ [ 0x83, 0xF5 ] ],
            },
            Test {
                filename: "signed-2-partial-body.gpg",
                hash_prefix: vec![ [ 0x2F, 0xBE ] ],
            },
            Test {
                filename: "signed-3-partial-body-multiple-sigs.gpg",
                hash_prefix: vec![ [ 0x29, 0x64 ], [ 0xff, 0x7d ] ],
            },
    ];

    for test in tests.iter() {
        eprintln!("Trying {}...", test.filename);
        let mut pp = PacketParserBuilder::from_file(path_to(test.filename))
            .expect(&format!("Reading {}", test.filename)[..])
            .finalize().unwrap();

        let mut one_pass_sigs = 0;
        let mut sigs = 0;

        while let Some(tmp) = pp {
            if let Packet::OnePassSig(_) = tmp.packet {
                one_pass_sigs += 1;
            } else if let Packet::Signature(ref sig) = tmp.packet {
                eprintln!("  {}:\n  prefix: expected: {}, in sig: {}",
                          test.filename,
                          to_hex(&test.hash_prefix[sigs][..], false),
                          to_hex(&sig.hash_prefix[..], false));
                eprintln!("  computed hash: {}",
                          to_hex(&sig.computed_hash.as_ref().unwrap().1, false));

                assert_eq!(test.hash_prefix[sigs], sig.hash_prefix);
                assert_eq!(&test.hash_prefix[sigs][..],
                           &sig.computed_hash.as_ref().unwrap().1[..2]);

                sigs += 1;
            } else if one_pass_sigs > 0 {
                assert_eq!(one_pass_sigs, test.hash_prefix.len(),
                           "Number of OnePassSig packets does not match \
                            number of expected OnePassSig packets.");
            }

            let (_, _, tmp, _) = tmp.recurse().expect("Parsing message");
            pp = tmp;
        }
        assert_eq!(one_pass_sigs, sigs,
                   "Number of OnePassSig packets does not match \
                    number of signature packets.");

        eprintln!("done.");
    }
}

impl Key {
    /// Parses the body of a public key, public subkey, secret key or
    /// secret subkey packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);
        let tag = pp.header.ctb.tag;
        assert!(tag == Tag::PublicKey
                || tag == Tag::PublicSubkey
                || tag == Tag::SecretKey
                || tag == Tag::SecretSubkey);
        let version = ptry!(pp.parse_u8("version"));
        if version != 4 {
            // We only support version 4 keys.
            return pp.fail("unknown version");
        }

        let creation_time = ptry!(pp.parse_be_u32("creation_time"));
        let pk_algo = ptry!(pp.parse_u8("pk_algo"));
        let mpis = ptry!(pp.parse_bytes_eof("mpis"));

        let tag = pp.header.ctb.tag;
        let key = Key {
            common: Default::default(),
            version: version,
            creation_time: creation_time,
            pk_algo: pk_algo,
            mpis: MPIs::parse(mpis),
        };

        pp.ok(match tag {
            Tag::PublicKey => Packet::PublicKey(key),
            Tag::PublicSubkey => Packet::PublicSubkey(key),
            Tag::SecretKey => Packet::SecretKey(key),
            Tag::SecretSubkey => Packet::SecretSubkey(key),
            _ => unreachable!(),
        })
    }
}

impl UserID {
    /// Parses the body of a user id packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        let value = ptry!(pp.parse_bytes_eof("value"));

        pp.ok(Packet::UserID(UserID {
            common: Default::default(),
            value: value,
        }))
    }
}

impl UserAttribute {
    /// Parses the body of a user attribute packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        let value = ptry!(pp.parse_bytes_eof("value"));

        pp.ok(Packet::UserAttribute(UserAttribute {
            common: Default::default(),
            value: value,
        }))
    }
}

impl Literal {
    /// Parses the body of a literal packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        // Directly hashing a literal data packet is... strange.
        // Neither the packet's header, the packet's meta-data nor the
        // length encoding information is included in the hash.
        //
        // Condition: Hashing has been disabled by the callee.

        let format = ptry!(pp.parse_u8("format"));
        let filename_len = ptry!(pp.parse_u8("filename_len"));

        let filename = if filename_len > 0 {
            Some(ptry!(pp.parse_bytes("filename", filename_len as usize)))
        } else {
            None
        };

        let date = ptry!(pp.parse_be_u32("date"));

        // Consume the header is consumed while hashing is
        // disabled.
        let recursion_depth = pp.recursion_depth;
        pp.commit_then(|mut bio, total_out| {
            // We know the data has been read, so this cannot
            // fail.
            bio.data_consume_hard(total_out).unwrap();

            // Enable hashing of the body.
            Cookie::hashing(
                &mut bio, true, recursion_depth as isize - 1);
            Ok((bio, ()))
        })?;

        pp.ok(Packet::Literal(Literal {
            common: Default::default(),
            format: format,
            filename: filename,
            date: date,
        }))
    }
}

#[test]
fn literal_parser_test () {
    {
        let data = bytes!("literal-mode-b.gpg");
        let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Full(18));
        let content = pp.steal_eof().unwrap();
        let p = pp.finish();
        // eprintln!("{:?}", p);
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format, 'b' as u8);
            assert_eq!(p.filename.as_ref().unwrap()[..], b"foobar"[..]);
            assert_eq!(p.date, 1507458744);
            assert_eq!(content, b"FOOBAR");
        } else {
            panic!("Wrong packet!");
        }
    }

    {
        let data = bytes!("literal-mode-t-partial-body.gpg");
        let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Partial(4096));
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
            panic!("Wrong packet!");
        }
    }
}

impl CompressedData {
    /// Parses the body of a compressed data packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);
        let algo = ptry!(pp.parse_u8("algo"));

        if TRACE {
            eprintln!("CompressedData::parse(): \
                       Adding decompressor, recursion depth = {:?}.",
                      pp.recursion_depth);
        }

        //   0          - Uncompressed
        //   1          - ZIP [RFC1951]
        //   2          - ZLIB [RFC1950]
        //   3          - BZip2 [BZ2]
        //   100 to 110 - Private/Experimental algorithm
        if algo > 3 {
            return pp.fail("unknown compression algorithm");
        }

        let recursion_depth = pp.recursion_depth as usize;
        pp.commit_then(|mut bio, total_out| {
            // We know the data has been read, so this cannot
            // fail.
            bio.data_consume_hard(total_out).unwrap();

            let bio : Box<BufferedReader<Cookie>> = match algo {
                0 => {
                    if TRACE {
                        eprintln!("CompressedData::parse(): Actually, no need \
                                   for a compression filter: this is an \
                                   \"uncompressed compression packet\".");
                    }
                    // Uncompressed.
                    bio
                },
                1 => {
                    // Zip.
                    Box::new(BufferedReaderDeflate::with_cookie(
                        bio, Cookie::new(recursion_depth)))
                },
                2 => {
                    // Zlib
                    Box::new(BufferedReaderZlib::with_cookie(
                        bio, Cookie::new(recursion_depth)))
                },
                3 => {
                    // BZip2
                    Box::new(BufferedReaderBzip::with_cookie(
                        bio, Cookie::new(recursion_depth)))
                },
                _ => unreachable!(), // Validated above.
            };

            Ok((bio, ()))
        })?;

        pp.ok(Packet::CompressedData(CompressedData {
            common: Default::default(),
            algo: algo,
        }))
    }
}

#[test]
fn compressed_data_parser_test () {
    let expected = bytes!("a-cypherpunks-manifesto.txt");

    for i in 1..4 {
        let path = path_to(&format!("compressed-data-algo-{}.gpg", i)[..]);
        let mut pp = PacketParser::from_file(path).unwrap().unwrap();

        // We expect a compressed packet containing a literal data
        // packet, and that is it.
        if let Packet::CompressedData(ref compressed) = pp.packet {
            assert_eq!(compressed.algo, i);
        } else {
            panic!("Wrong packet!");
        }

        let (_packet, _packet_depth, ppo, _pp_depth) = pp.recurse().unwrap();

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
            panic!("Wrong packet!");
        }

        // And, we're done...
        assert!(ppo.is_none());
    }
}

impl SKESK {
    /// Parses the body of an SKESK packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);
        let version = ptry!(pp.parse_u8("version"));
        if version != 4 {
            // We only support version 4 keys.
            return pp.fail("unknown version");
        }

        let symm_algo = ptry!(pp.parse_u8("symm_algo"));
        let s2k = ptry!(S2K::parse(&mut pp));
        let esk = ptry!(pp.parse_bytes_eof("esk"));

        pp.ok(Packet::SKESK(SKESK {
            common: Default::default(),
            version: version,
            symm_algo: symm_algo.into(),
            s2k: s2k,
            esk: esk,
        }))
    }
}

impl SEIP {
    /// Parses the body of a SEIP packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);
        let version = ptry!(pp.parse_u8("version"));
        if version != 1 {
            return pp.fail("unknown version");
        }

        pp.decrypted(false).ok(Packet::SEIP(SEIP {
            common: Default::default(),
            version: version,
        }))
    }
}

impl MDC {
    /// Parses the body of an MDC packet.
    fn parse<'a>(mut pp: PacketParser<'a>)
                 -> Result<PacketParser<'a>> {
        bind_ptry!(pp);

        // Find the HashedReader pushed by the containing SEIP packet.
        // In a well-formed message, this will be the outer most
        // HashedReader on the BufferedReader stack: we pushed it
        // there when we started decrypting the SEIP packet, and an
        // MDC packet is the last packet in a SEIP container.
        // Nevertheless, we take some basic precautions to check
        // whether it is really the matching HashedReader.

        let mut computed_hash : [u8; 20] = Default::default();
        {
            let mut r : Option<&mut BufferedReader<Cookie>>
                = pp.get_mut();
            while let Some(bio) = r {
                {
                    let state = bio.cookie_mut();
                    if state.hashes_for == HashesFor::MDC {
                        if state.hashes.len() > 0 {
                            let (a, mut h) = state.hashes.pop().unwrap();
                            assert_eq!(a, HashAlgo::SHA1);
                            h.digest(&mut computed_hash);
                        }

                        // If the outer most HashedReader is not the
                        // matching HashedReader, then the message is
                        // malformed.
                        break;
                    }
                }

                r = bio.get_mut();
            }
        }

        let mut hash : [u8; 20] = Default::default();
        hash.copy_from_slice(&ptry!(pp.parse_bytes("hash", 20)));

        pp.ok(Packet::MDC(MDC {
            common: Default::default(),
            computed_hash: computed_hash,
            hash: hash,
        }))
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
                s2k: S2K::Iterated {
                    hash: HashAlgo::SHA1,
                    salt: [0x82, 0x59, 0xa0, 0x6e, 0x98, 0xda, 0x94, 0x1c],
                    iterations: S2K::decode_count(238),
                },
                password: &b"bgtyhn"[..],
                key_hex: "474E5C373BA18AF0A499FCAFE6093F131DF636F6A3812B9A8AE707F1F0214AE9",
            },
    ];

    for test in tests.iter() {
        let path = path_to(test.filename);
        let mut pp = PacketParser::from_file(path).unwrap().unwrap();
        if let Packet::SKESK(ref skesk) = pp.packet {
            eprintln!("{:?}", skesk);

            assert_eq!(skesk.symm_algo, test.cipher_algo);
            assert_eq!(skesk.s2k, test.s2k);

            match skesk.decrypt(test.password) {
                Ok((_symm_algo, key)) => {
                    let key = to_hex(&key[..], false);
                    assert_eq!(&key[..], &test.key_hex[..]);
                }
                Err(e) => {
                    panic!("No session key, got: {:?}", e);
                }
            }
        } else {
            panic!("Wrong packet!");
        }
    }
}


// A `PacketParser`'s settings.
#[derive(Clone, Debug)]
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
pub struct PacketParserBuilder<R: BufferedReader<Cookie>> {
    bio: R,
    settings: PacketParserSettings,
}

impl<R: BufferedReader<Cookie>> PacketParserBuilder<R> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `BufferedReader` object.
    ///
    /// Note: this clears the `level` field of the
    /// `Cookie` cookie.
    pub fn from_buffered_reader(mut bio: R)
            -> Result<PacketParserBuilder<R>> {
        bio.cookie_mut().level = None;
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
        let pp = PacketParser::parse(Box::new(self.bio), &self.settings, 0)?;

        if let ParserResult::Success(mut pp) = pp {
            // We successfully parsed the first packet's header.

            // Override the defaults.
            pp.settings = self.settings;

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
        PacketParserBuilder<BufferedReaderGeneric<R, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    pub fn from_reader(reader: R)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<R, Cookie>>> {
        Ok(PacketParserBuilder {
            bio: BufferedReaderGeneric::with_cookie(
                reader, None, Cookie::default()),
            settings: PacketParserSettings::default(),
        })
    }
}

impl PacketParserBuilder<BufferedReaderGeneric<File, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<File, Cookie>>> {
        PacketParserBuilder::from_reader(File::open(path)?)
    }
}

impl <'a> PacketParserBuilder<BufferedReaderMemory<'a, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in specified buffer.
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserBuilder<
                          BufferedReaderMemory<'a, Cookie>>> {
        PacketParserBuilder::from_buffered_reader(
            BufferedReaderMemory::with_cookie(
                bytes, Cookie::default()))
    }
}

use nettle::Hash;

/// What the hash in the Cookie is for.
#[derive(Clone, PartialEq, Debug)]
pub enum HashesFor {
    Nothing,
    MDC,
    Signature,
}

pub struct Cookie {
    // `BufferedReader`s managed by a `PacketParser` have
    // `Some(level)`; an external `BufferedReader` (i.e., the
    // underlying `BufferedReader`) has no level.
    //
    // Before parsing a top-level packet, we may push a
    // `BufferedReaderLimitor` in front of the external
    // `BufferedReader`.  Such `BufferedReader`s are assigned a level
    // of 0.
    //
    // When a top-level packet (i.e., a packet with a recursion depth
    // of 0) reads from the `BufferedReader` stack, the top
    // `BufferedReader` will have a level of at most 0.
    //
    // If the top-level packet is a container, say, a `CompressedData`
    // packet, then it pushes a decompression filter with a level of 0
    // onto the `BufferedReader` stack, and it recursively invokes the
    // parser.
    //
    // When the parser encounters the `CompressedData`'s first child,
    // say, a `Literal` packet, it pushes a `BufferedReaderLimitor` on
    // the `BufferedReader` stack with a level of 1.  Then, a
    // `PacketParser` for the `Literal` data packet is created with a
    // recursion depth of 1.
    //
    // There are several things to note:
    //
    //   - When a `PacketParser` with a recursion depth of N reads
    //     from the `BufferedReader` stack, the top `BufferedReader`'s
    //     level is (at most) N.
    //
    //     - Because we sometimes don't need to push a limitor
    //       (specifically, when the length is indeterminate), the
    //       `BufferedReader` at the top of the stack may have a level
    //       less than the current `PacketParser`'s recursion depth.
    //
    //   - When a packet at depth N is a container that filters the
    //     data, it pushes a `BufferedReader` at level N onto the
    //     `BufferedReader` stack.
    //
    //   - When we finish parsing a packet at depth N, we pop all
    //     `BufferedReader`s from the `BufferedReader` stack that are
    //     at level N.  The intuition is: the `BufferedReaders` at
    //     level N are associated with the packet at depth N.
    //
    //   - If a OnePassSig packet occurs at the top level, then we
    //     need to push a HashedReader above the current level.  The
    //     top level is level 0, thus we push the HashedReader at
    //     level -1.
    level: Option<isize>,

    hashes_for: HashesFor,
    hashing: bool,
    hashes: Vec<(HashAlgo, Box<Hash>)>,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let algos = self.hashes.iter()
            .map(|&(algo, _)| algo)
            .collect::<Vec<HashAlgo>>();

        f.debug_struct("Cookie")
            .field("level", &self.level)
            .field("hashes_for", &self.hashes_for)
            .field("hashes", &algos)
            .finish()
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie {
            level: None,
            hashing: true,
            hashes_for: HashesFor::Nothing,
            hashes: vec![],
        }
    }
}

impl Cookie {
    fn new(recursion_depth: usize) -> Cookie {
        Cookie {
            level: Some(recursion_depth as isize),
            hashing: true,
            hashes_for: HashesFor::Nothing,
            hashes: vec![],
        }
    }
}

impl Cookie {
    // Enables or disables signature hashers (HashesFor::Signature) at
    // level `level`.
    //
    // Thus to disable the hashing of a level 3 literal packet's
    // meta-data, we disable hashing at level 2.
    fn hashing(reader: &mut BufferedReader<Cookie>,
               enabled: bool, level: isize) {
        let mut reader : Option<&mut BufferedReader<Cookie>>
            = Some(reader);
        while let Some(r) = reader {
            {
                let cookie = r.cookie_mut();
                if let Some(br_level) = cookie.level {
                    if br_level < level {
                        break;
                    }
                    if br_level == level
                        && cookie.hashes_for == HashesFor::Signature {
                        cookie.hashing = enabled;
                    }
                } else {
                    break;
                }
            }
            reader = r.get_mut();
        }
    }
}

// Pops readers from a buffered reader stack at the specified level.
//
// If the reader stack is owned by a PacketParser, it is up to the
// caller to adjust PacketParser::recursion_depth, etc. appropriately!
fn buffered_reader_stack_pop<'a>(
    mut reader: Box<BufferedReader<Cookie> + 'a>, depth: isize)
    -> Box<BufferedReader<Cookie> + 'a>
{
    while let Some(level) = reader.cookie_ref().level {
        assert!(level <= depth);

        if level >= depth {
            if TRACE {
                eprintln!("{}buffered_reader_stack_pop: popping level {:?} reader: {:?}",
                          indent(depth as u8),
                          reader.cookie_ref().level,
                          reader);
            }

            reader.drop_eof().unwrap();
            reader = reader.into_inner().unwrap();
        } else {
            break;
        }
    }

    reader
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
    /// The current packet's header.
    pub header: Header,

    /// The packet that is being parsed.
    pub packet: Packet,

    /// This packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    pub recursion_depth: u8,

    // Either parsing or done.
    state: State<'a>,

    // Whether the caller read the packets content.  If so, then we
    // can't recurse, because we're missing some of the packet!
    content_was_read: bool,

    // Whether PacketParser::finish has been called.
    finished: bool,

    // Whether the content has been decrypted.
    decrypted: bool,

    // The `PacketParser`'s settings
    settings: PacketParserSettings,

    // The cookie.
    cookie: Cookie,
}

// PacketParser states.
//
// Parsing is divided in two phases.  First, we parse the framing and
// the header as we understand them.  Then, we surrender control to
// the callee to parse the packets body as she sees fit.
#[derive(Debug)]
enum State<'a> {
    // While we are parsing the framing and headers, we dup the inner
    // reader so that if the parsing fails, we return an unknown
    // packet with the body intact.
    Header(Box<BufferedReaderDup<'a, Cookie>>),

    // The inner reader.
    //
    // We can't make `reader` generic, because the type of
    // `BufferedReader` that is returned is not a function of the
    // arguments, and Rust figures out a generic's type by looking at
    // the calling site, not the function's implementation.  Consider
    // what happens when we parse a compressed data packet: we return
    // a Decompressor (in fact, the actual type is only known at
    // run-time!).
    Body(Box<'a + BufferedReader<Cookie>>),
}

impl <'a> std::fmt::Debug for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketParser")
            .field("header", &self.packet)
            .field("packet", &self.packet)
            .field("recursion_depth", &self.recursion_depth)
            .field("state", &self.state)
            .field("content_was_read", &self.content_was_read)
            .field("settings", &self.settings)
            .finish()
    }
}

// The return value of PacketParser::parse.
enum ParserResult<'a> {
    Success(PacketParser<'a>),
    EOF(Box<BufferedReader<Cookie> + 'a>),
}

impl <'a> PacketParser<'a> {
    /// Starts parsing an OpenPGP message stored in a `BufferedReader` object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_buffered_reader<R: BufferedReader<Cookie> + 'a>(bio: R)
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

    fn new(inner: Box<'a + BufferedReader<Cookie>>,
           settings: PacketParserSettings,
           recursion_depth: u8, header: Header) -> Self {
        PacketParser {
            packet: Packet::Unknown(Unknown {
                common: Default::default(),
                tag: Tag::Reserved,
            }),
            recursion_depth: recursion_depth,
            state: State::Header(Box::new(
                BufferedReaderDup::with_cookie(inner, Default::default()))),
            content_was_read: false,
            finished: false,
            decrypted: true,
            settings: settings,
            header: header,
            cookie: Default::default(),
        }
    }

    fn new_naked(inner: Box<'a + BufferedReader<Cookie>>)
                 -> Self {
        PacketParser::new(inner, Default::default(), 0, Header {
            ctb: CTB::new(Tag::Reserved),
            length: BodyLength::Full(0),
        })
    }

    fn decrypted(mut self, v: bool) -> Self {
        self.decrypted = v;
        self
    }

    fn commit_then<F, R>(&mut self, mut fun: F) -> Result<R>
        where F: FnMut(Box<'a + BufferedReader<Cookie>>, usize)
                    -> Result<(Box<'a + BufferedReader<Cookie>>, R)> {
        // Steal the reader.
        let state = ::std::mem::replace(
            &mut self.state,
            State::Body(Box::new(
                BufferedReaderEOF::with_cookie(Default::default()))));

        match state {
            State::Header(reader) => {
                let total_out = reader.total_out();

                // This is a BufferedReaderDup, so this cannot fail.
                let mut inner = reader.into_inner().unwrap();

                // Apply the given function.
                let (inner, result) = fun(inner, total_out)?;

                self.state = State::Body(inner);
                Ok(result)
            },
            State::Body(_) =>
                panic!("PacketParser already committed"),
        }
    }

    fn commit(&mut self) -> Result<()> {
        self.commit_then(|mut reader, total_out| {
            // We know the data has been read, so this cannot fail.
            reader.data_consume_hard(total_out).unwrap();
            Ok((reader, ()))
        })
    }

    fn ok(mut self, packet: Packet) -> Result<PacketParser<'a>> {
        if let State::Header(_) = self.state {
            self.commit()?;
        }
        self.packet = packet;
        Ok(self)
    }

    fn fail(self, _reason: &'static str) -> Result<PacketParser<'a>> {
        Unknown::parse(self)
    }

    fn field(&mut self, _name: &'static str, _size: usize) {
        // Nothing yet...
    }

    fn parse_u8(&mut self, name: &'static str) -> io::Result<u8> {
        self.field(name, 1);
        Ok(self.data_consume_hard(1)?[0])
    }

    fn parse_be_u16(&mut self, name: &'static str) -> io::Result<u16> {
        self.field(name, 2);
        self.read_be_u16()
    }

    fn parse_be_u32(&mut self, name: &'static str) -> io::Result<u32> {
        self.field(name, 4);
        self.read_be_u32()
    }

    fn parse_bytes(&mut self, name: &'static str, amount: usize)
             -> io::Result<Vec<u8>> {
        self.field(name,  amount);
        self.steal(amount)
    }

    fn parse_bytes_eof(&mut self, name: &'static str) -> io::Result<Vec<u8>> {
        let r = self.steal_eof()?;
        self.field(name, r.len());
        Ok(r)
    }

    // Returns a packet parser for the next OpenPGP packet in the
    // stream.  If there are no packets left, this function returns
    // `bio`.
    fn parse(mut bio: Box<BufferedReader<Cookie> + 'a>,
             settings: &PacketParserSettings,
             recursion_depth: usize)
            -> Result<ParserResult<'a>> {
        // When header encounters an EOF, it returns an error.  But,
        // we want to return None.  Try a one byte read.
        if bio.data(1)?.len() == 0 {
            if settings.trace {
                eprintln!("{}PacketParser::parse(depth: {}) -> EOF.",
                          indent(recursion_depth as u8),
                          recursion_depth);
            }
            return Ok(
                ParserResult::EOF(Box::new(bio)));
        }

        // When computing a hash for a signature, most of the
        // signature packet should not be included in the hash.  That
        // is:
        //
        //    [ one pass sig ] [ ... message ... ] [ sig ]
        //                     ^^^^^^^^^^^^^^^^^^^
        //                        hash only this
        //
        // (The special logic for the Signature packet is in
        // Signature::parse.)
        //
        // To avoid this, we use a Dup reader to figure out if the
        // next packet is a sig packet without consuming the headers,
        // which would cause the headers to be hashed.  If so, we
        // extract the hash context.
        let mut bio = BufferedReaderDup::with_cookie(
            bio, Cookie::default());

        let header = Header::parse(&mut bio)?;
        let tag = header.ctb.tag;

        let mut computed_hash = None;
        if tag == Tag::Signature {
            // Ok, the next packet is a Signature packet.  Get the
            // nearest, valid OneSigPass packet.
            if settings.trace {
                eprintln!("{}PacketParser::parse(): Got a Signature packet, \
                           looking for a matching OnePassSig packet",
                          indent(recursion_depth as u8));
            }

            // We know that the top reader is not a HashedReader (it's
            // a BufferedReaderDup).  So, start with it's child.
            let mut r = bio.get_mut();
            while let Some(tmp) = r {
                {
                    let cookie = tmp.cookie_mut();

                    assert!(cookie.level.unwrap_or(-1)
                            <= recursion_depth as isize);
                    // The HashedReader has to be at level
                    // 'recursion_depth - 1'.
                    if cookie.level.is_none()
                        || cookie.level.unwrap()
                           < recursion_depth as isize - 1 {
                        break
                    }

                    if cookie.hashes_for == HashesFor::Signature {
                        assert_eq!(cookie.hashes.len(), 1);

                        let (algo, hash) = cookie.hashes.pop().unwrap();
                        if settings.trace {
                            eprintln!("{}PacketParser::parse(): \
                                       popped a {:?} HashedReader",
                                      indent(recursion_depth as u8), algo);
                        }
                        cookie.hashes_for = HashesFor::Nothing;
                        computed_hash = Some((algo, hash));

                        break;
                    }
                }

                r = tmp.get_mut();
            }
        }

        // We've extracted the hash context (if required).  Now, we
        // rip off the BufferedReaderDup and actually consume the
        // header.
        let consumed = bio.total_out();
        let mut bio = Box::new(bio).into_inner().unwrap();

        // If we have multiple one pass signature packets in a row,
        // then we (XXX: incorrectly!, but gpg doesn't support this
        // case either) assume that only the last one pass signature
        // packet has the `last` bit set and therefore the one pass
        // signature packets should not be included in any preceeding
        // one pass signature packet's hashes.
        if tag == Tag::Literal || tag == Tag::OnePassSig
            || tag == Tag::Signature {
            Cookie::hashing(
                &mut bio, false, recursion_depth as isize - 1);
        }
        bio.consume(consumed);

        let bio : Box<BufferedReader<Cookie>>
            = match header.length {
                BodyLength::Full(len) => {
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): \
                                   Pushing a limitor ({} bytes), level: {}.",
                                  indent(recursion_depth as u8), len,
                                  recursion_depth);
                    }
                    Box::new(BufferedReaderLimitor::with_cookie(
                        bio, len as u64,
                        Cookie::new(recursion_depth)))
                },
                BodyLength::Partial(len) => {
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): Pushing a \
                                   partial body chunk decoder, level: {}.",
                                  indent(recursion_depth as u8),
                                  recursion_depth);
                    }
                    Box::new(BufferedReaderPartialBodyFilter::with_cookie(
                        bio, len,
                        // When hashing a literal data packet, we only
                        // hash the packet's contents; we don't hash
                        // the literal data packet's meta-data or the
                        // length information, which includes the
                        // partial body headers.
                        tag != Tag::Literal,
                        Cookie::new(recursion_depth)))
                },
                BodyLength::Indeterminate => {
                    if settings.trace {
                        eprintln!("{}PacketParser::parse(): Indeterminate \
                                   length packet, not adding a limitor.",
                                  indent(recursion_depth as u8));
                    }
                    bio
                },
        };

        let tag = header.ctb.tag;
        let parser = PacketParser::new(bio, (*settings).clone(), recursion_depth as u8,
                                       header);
        let mut result = match tag {
            Tag::Signature =>           Signature::parse(parser, computed_hash),
            Tag::OnePassSig =>          OnePassSig::parse(parser),
            Tag::PublicSubkey =>	Key::parse(parser),
            Tag::PublicKey =>		Key::parse(parser),
            Tag::SecretKey =>		Key::parse(parser),
            Tag::SecretSubkey =>	Key::parse(parser),
            Tag::UserID =>		UserID::parse(parser),
            Tag::UserAttribute =>	UserAttribute::parse(parser),
            Tag::Literal =>		Literal::parse(parser),
            Tag::CompressedData =>	CompressedData::parse(parser),
            Tag::SKESK =>		SKESK::parse(parser),
            Tag::SEIP =>		SEIP::parse(parser),
            Tag::MDC =>			MDC::parse(parser),
            _ =>			Unknown::parse(parser),
        }?;

        if tag == Tag::OnePassSig {
            Cookie::hashing(
                &mut result, true, recursion_depth as isize - 1);
        }

        if settings.trace {
            eprintln!("{}PacketParser::parse() -> {:?}, depth: {}, level: {:?}.",
                      indent(recursion_depth as u8), result.packet.tag(),
                      result.recursion_depth,
                      result.cookie_ref().level);
        }

        return Ok(ParserResult::Success(result));
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
    /// Since the packets are serialized in depth-first order and all
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
            eprintln!("{}PacketParser::next({:?}, depth: {}, level: {:?}).",
                      indent(self.recursion_depth),
                      self.packet.tag(), self.recursion_depth,
                      self.cookie_ref().level);
        }

        let orig_depth = self.recursion_depth as usize;

        self.finish();
        let mut reader = match self.state {
            State::Body(reader) =>
                buffered_reader_stack_pop(
                    reader, self.recursion_depth as isize),
            State::Header(_) =>
                panic!("Header not parsed")
        };


        // Now read the next packet.
        loop {
            // Parse the next packet.
            let pp = PacketParser::parse(reader, &self.settings,
                                         self.recursion_depth as usize)?;
            match pp {
                ParserResult::EOF(reader_) => {
                    // We got EOF on the current container.  The
                    // container at recursion depth n is empty.  Pop
                    // it and any filters for it, i.e., those at level
                    // n (e.g., the limitor that caused us to hit
                    // EOF), and then try again.

                    if self.settings.trace {
                        eprintln!("{}PacketParser::next(): \
                                   Got EOF trying to read the next packet, \
                                   popping container at depth {}.",
                                  indent(self.recursion_depth),
                                  self.recursion_depth);
                    }

                    if self.recursion_depth == 0 {
                        if self.settings.trace {
                            eprintln!("{}PacketParser::next(): \
                                       Popped top-level container, done \
                                       reading message.",
                                      indent(self.recursion_depth));
                        }
                        return Ok((self.packet, orig_depth as isize,
                                   None, 0));
                    } else {
                        self.state = State::Body(reader_);
                        self.recursion_depth -= 1;
                        self.finish();
                        // XXX self.content_was_read = false;
                        reader = match self.state {
                            State::Body(reader) =>
                                buffered_reader_stack_pop(
                                    reader, self.recursion_depth as isize),
                            State::Header(_) =>
                                panic!("Header not parsed")
                        };
                    }
                },
                ParserResult::Success(mut pp) => {
                    pp.settings = self.settings;
                    return Ok((self.packet, orig_depth as isize,
                               Some(pp), self.recursion_depth as isize));
                }
            }
        }
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
            eprintln!("{}PacketParser::recurse({:?}, depth: {}, level: {:?})",
                      indent(self.recursion_depth),
                      self.packet.tag(), self.recursion_depth,
                      self.cookie_ref().level);
        }

        match self.packet {
            // Packets that recurse.
            Packet::CompressedData(_) | Packet::SEIP(_) if self.decrypted => {
                if self.recursion_depth
                    >= self.settings.max_recursion_depth {
                    if self.settings.trace {
                        eprintln!("{}PacketParser::recurse(): Not recursing \
                                   into the {:?} packet, maximum recursion \
                                   depth ({}) reached.",
                                  indent(self.recursion_depth), self.packet.tag(),
                                  self.settings.max_recursion_depth);
                    }

                    // Drop through.
                } else if self.content_was_read {
                    if self.settings.trace {
                        eprintln!("{}PacketParser::recurse(): Not recursing \
                                   into the {:?} packet, some data was \
                                   already read.",
                                  indent(self.recursion_depth), self.packet.tag());
                    }

                    // Drop through.
                } else {
                        match self.state {
                            State::Body(reader) =>
                                match PacketParser::parse(reader, &self.settings,
                                                          self.recursion_depth as usize + 1)? {
                                    ParserResult::Success(mut pp) => {
                                        pp.settings = self.settings;

                                        if pp.settings.trace {
                                            eprintln!("{}PacketParser::recurse(): \
                                                       Recursed into the {:?} packet, \
                                                       got a {:?}.",
                                                      indent(self.recursion_depth + 1),
                                                      self.packet.tag(), pp.packet.tag());
                                        }

                                        return Ok((self.packet,
                                                   self.recursion_depth as isize,
                                                   Some(pp),
                                                   self.recursion_depth as isize + 1));
                                    },
                                    ParserResult::EOF(_) => {
                                        unimplemented!("We immediately got an EOF!");
                                    },
                                },
                            State::Header(_) =>
                                panic!("Header not parsed"),
                        };
                    }
            },
            // decrypted should always be true.
            Packet::CompressedData(_) => unreachable!(),
            // Packets that don't recurse.
            Packet::Unknown(_) | Packet::Signature(_) | Packet::OnePassSig(_)
                | Packet::PublicKey(_) | Packet::PublicSubkey(_)
                | Packet::SecretKey(_) | Packet::SecretSubkey(_)
                | Packet::UserID(_) | Packet::UserAttribute(_)
                | Packet::Literal(_) | Packet::SKESK(_)
                | Packet::SEIP(_) | Packet::MDC(_) => {
                // Drop through.
                if self.settings.trace {
                    eprintln!("{}PacketParser::recurse(): A {:?} packet is \
                               not a container, not recursing.",
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
        if self.finished {
            return &mut self.packet;
        }

        let recursion_depth = self.recursion_depth;

        if self.settings.buffer_unread_content {
            if self.settings.trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           buffering {} bytes of unread content",
                          indent(recursion_depth), self.packet.tag(),
                          recursion_depth,
                          self.data_eof().unwrap().len());
            }

            if let Err(_err) = self.buffer_unread_content() {
                // XXX: We should propagate the error.
                unimplemented!();
            }
        } else {
            if self.settings.trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           dropping {} bytes of unread content",
                          indent(recursion_depth), self.packet.tag(),
                          recursion_depth,
                          self.data_eof().unwrap().len());
            }

            self.drop_eof().unwrap();
        }

        self.finished = true;

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
impl<'a> BufferedReader<Cookie> for PacketParser<'a> {
    fn buffer(&self) -> &[u8] {
        match self.state {
            State::Header(ref reader) => reader.buffer(),
            State::Body(ref reader) => reader.buffer(),
        }
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        match self.state {
            State::Header(ref mut reader) => reader.data(amount),
            State::Body(ref mut reader) => reader.data(amount),
        }
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        match self.state {
            State::Header(ref mut reader) => reader.data_hard(amount),
            State::Body(ref mut reader) => reader.data_hard(amount),
        }
    }

    fn data_eof(&mut self) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        match self.state {
            State::Header(ref mut reader) => reader.data_eof(),
            State::Body(ref mut reader) => reader.data_eof(),
        }
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        match self.state {
            State::Header(ref mut reader) => reader.consume(amount),
            State::Body(ref mut reader) => {
                self.content_was_read |= amount > 0;
                reader.consume(amount)
            },
        }
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.state {
            State::Header(ref mut reader) => reader.data_consume(amount),
            State::Body(ref mut reader) => {
                self.content_was_read |= amount > 0;
                reader.data_consume(amount)
            },
        }
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.state {
            State::Header(ref mut reader) => reader.data_consume_hard(amount),
            State::Body(ref mut reader) => {
                self.content_was_read |= amount > 0;
                reader.data_consume_hard(amount)
            },
        }
    }

    fn read_be_u16(&mut self) -> io::Result<u16> {
        match self.state {
            State::Header(ref mut reader) => reader.read_be_u16(),
            State::Body(ref mut reader) => {
                self.content_was_read = true;
                reader.read_be_u16()
            },
        }
    }

    fn read_be_u32(&mut self) -> io::Result<u32> {
        match self.state {
            State::Header(ref mut reader) => reader.read_be_u32(),
            State::Body(ref mut reader) => {
                self.content_was_read = true;
                reader.read_be_u32()
            },
        }
    }

    fn steal(&mut self, amount: usize) -> io::Result<Vec<u8>> {
        match self.state {
            State::Header(ref mut reader) => reader.steal(amount),
            State::Body(ref mut reader) => {
                self.content_was_read |= amount > 0;
                reader.steal(amount)
            },
        }
    }

    fn steal_eof(&mut self) -> io::Result<Vec<u8>> {
        match self.state {
            State::Header(ref mut reader) => reader.steal_eof(),
            State::Body(ref mut reader) => {
                self.content_was_read = true;
                reader.steal_eof()
            },
        }
    }

    fn drop_eof(&mut self) -> io::Result<()> {
        match self.state {
            State::Header(ref mut reader) => reader.drop_eof(),
            State::Body(ref mut reader) => {
                self.content_was_read = true;
                reader.drop_eof()
            },
        }
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<Cookie>> {
        Some(match self.state {
            State::Header(ref mut reader) => reader.as_mut(),
            State::Body(ref mut reader) => reader,
        })
    }

    fn get_ref(&self) -> Option<&BufferedReader<Cookie>> {
        Some(match self.state {
            State::Header(ref reader) => reader.as_ref(),
            State::Body(ref reader) => reader,
        })
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<Cookie> + 'b>>
            where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: Cookie)
            -> Cookie {
        ::std::mem::replace(&mut self.cookie, cookie)
    }

    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }

    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
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

impl<'a> PacketParser<'a> {
    /// Tries to decrypt the current packet.
    ///
    /// On success, this function pushes one or more readers onto the
    /// `PacketParser`'s reader stack, and sets the packet's
    /// `decrypted` flag.
    ///
    /// If this function is called on a packet that does not contain
    /// encrypted data, or some of the data was already read, then it
    /// returns `Error::InvalidOperation`.
    pub fn decrypt(&mut self, algo: SymmetricAlgo, key: &[u8])
        -> Result<()>
    {
        if self.content_was_read {
            return Err(Error::InvalidOperation(
                format!("Packet's content has already been read.")).into());
        }
        if self.decrypted {
            return Err(Error::InvalidOperation(
                format!("Packet not encrypted.")).into());
        }

        if let Packet::SEIP(_) = self.packet {
            // Get the first blocksize plus two bytes and check
            // whether we can decrypt them using the provided key.
            // Don't actually comsume them in case we can't.
            let bl = algo.block_size()?;

            {
                let mut dec = Decryptor::new(
                    algo, key, &self.data_hard(bl + 2)?[..bl + 2])?;
                let mut header = vec![ 0u8; bl + 2 ];
                dec.read(&mut header)?;

                if !(header[bl - 2] == header[bl]
                     && header[bl - 1] == header[bl + 1]) {
                    return Err(Error::InvalidSessionKey(
                        format!("Last two 16-bit quantities don't match: {}",
                                ::to_hex(&header[..], false)))
                               .into());
                }
            }

            // Ok, we can decrypt the data.  Push a Decryptor and a
            // HashedReader on the `BufferedReader` stack.

            let reader =
            match self.state {
                State::Body(ref mut reader) =>
                    mem::replace(
                        reader,
                        Box::new(BufferedReaderEOF::with_cookie(Default::default()))),
                State::Header(_) =>
                    panic!("Header not parsed"),
            };

            // This can't fail, because we create a decryptor above
            // with the same parameters.
            let mut reader = BufferedReaderDecryptor::with_cookie(
                algo, key, reader, Cookie::default()).unwrap();
            reader.cookie_mut().level = Some(self.recursion_depth as isize);

            if self.settings.trace {
                eprintln!("{}PacketParser::decrypt: Pushing Decryptor, \
                           level {:?}.",
                          indent(self.recursion_depth),
                          reader.cookie_ref().level);
            }

            // And the hasher.
            let mut reader = HashedReader::new(
                reader, HashesFor::MDC, vec![HashAlgo::SHA1]);
            reader.cookie_mut().level = Some(self.recursion_depth as isize);

            if self.settings.trace {
                eprintln!("{}PacketParser::decrypt: Pushing HashedReader, \
                           level {:?}.",
                          indent(self.recursion_depth),
                          reader.cookie_ref().level);
            }

            // Consume the header.  This shouldn't fail, because it
            // worked when reading the header.
            reader.data_consume_hard(bl + 2).unwrap();

            self.state = State::Body(Box::new(reader));
            self.decrypted = true;

            Ok(())
        } else {
            Err(Error::InvalidOperation(
                format!("Can't decrypt {:?} packets.",
                        self.packet.tag())).into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::path::PathBuf;
    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
            .iter().collect()
    }

    #[test]
    fn decrypt_test_1() {
        struct Test<'a> {
            filename: &'a str,
            algo: SymmetricAlgo,
            key_hex: &'a str,
        }

        let expected = bytes!("a-cypherpunks-manifesto.txt");

        let tests = [
            Test {
                filename: "encrypted-aes256-password-123.gpg",
                algo: SymmetricAlgo::AES256,
                key_hex: "7EF4F08C44F780BEA866961423306166B8912C43352F3D9617F745E4E3939710",
            },
            Test {
                filename: "encrypted-aes192-password-123456.gpg",
                algo: SymmetricAlgo::AES192,
                key_hex: "B2F747F207EFF198A6C826F1D398DE037986218ED468DB61",
            },
            Test {
                filename: "encrypted-aes128-password-123456789.gpg",
                algo: SymmetricAlgo::AES128,
                key_hex: "AC0553096429260B4A90B1CEC842D6A0",
            },
            Test {
                filename: "encrypted-twofish-password-red-fish-blue-fish.gpg",
                algo: SymmetricAlgo::Twofish,
                key_hex: "96AFE1EDFA7C9CB7E8B23484C718015E5159CFA268594180D4DB68B2543393CB",
            },
        ];

        for test in tests.iter() {
            eprintln!("Decrypting {}", test.filename);

            let path = path_to(test.filename);
            let mut pp = PacketParserBuilder::from_file(&path).unwrap()
                .buffer_unread_content()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..])
                .expect("Empty message");

            loop {
                if let Packet::SEIP(_) = pp.packet {
                    let key = ::from_hex(test.key_hex, false).unwrap();

                    pp.decrypt(test.algo, &key[..]).unwrap();

                    // SEIP packet.
                    let (packet, _, pp, _) = pp.recurse().unwrap();
                    assert_eq!(packet.tag(), Tag::SEIP);
                    let pp = pp.expect(
                        "Expected an compressed or literal packet, got EOF");

                    // Literal packet, optionally compressed
                    let (mut packet, _, mut pp, _) = pp.recurse().unwrap();
                    if let Packet::CompressedData(_) = packet {
                        let pp_tmp = pp.expect(
                            "Expected a literal packet, got EOF");
                        let (packet_tmp, _, pp_tmp, _)
                            = pp_tmp.recurse().unwrap();
                        packet = packet_tmp;
                        pp = pp_tmp;
                    }
                    assert_eq!(packet.tag(), Tag::Literal);
                    assert_eq!(&packet.body.as_ref().unwrap()[..],
                               &expected[..]);
                    let pp = pp.expect("Expected an MDC packet, got EOF");

                    // MDC packet.
                    let (packet, _, pp, _) = pp.recurse().unwrap();
                    if let Packet::MDC(mdc) = packet {
                        assert_eq!(mdc.computed_hash, mdc.hash,
                                   "MDC doesn't match");
                    } else {
                        panic!("Expected an MDC packet!");
                    }

                    // EOF.
                    assert!(pp.is_none());

                    break;
                }

                // This will blow up if we reach the end of the message.
                // But, that is what we want: we stop when we get to a
                // SEIP packet.
                let (_, _, pp_tmp, _) = pp.recurse().unwrap();
                pp = pp_tmp.unwrap();
            }
        }
    }
}

/// An iterator over a packet stream.
///
/// This iterator recurses into any containers.
///
/// Because parsing packets may result in an error, users of this
/// iterator should call iter.error() when they receive None to
/// determine if the iterator stopped due to an error or because the
/// packet stream was really exhausted.
pub struct PacketParserIter<'a> {
    ppo: Option<PacketParser<'a>>,
    error: Option<failure::Error>,
}

impl<'a> Iterator for PacketParserIter<'a> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }

        let ppo = self.ppo.take();
        if let Some(pp) = ppo {
            match pp.recurse() {
                Ok((packet, _, ppo_tmp, _)) => {
                    self.ppo = ppo_tmp;
                    Some(packet)
                },
                Err(err) => {
                    self.error = Some(err);
                    None
                },
            }
        } else {
            None
        }
    }
}

impl<'a> IterError for PacketParserIter<'a> {
    /// Returns any pending error.
    fn error(&mut self) -> Option<failure::Error> {
        self.error.take()
    }
}

impl<'a> IntoIterator for PacketParser<'a> {
    type Item = Packet;
    type IntoIter = PacketParserIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PacketParserIter {
            ppo: Some(self),
            error: None,
        }
    }
}

#[test]
fn packet_parser_iter_test() {
    let pp = PacketParser::from_file(
        path_to("compressed-data-algo-1.gpg")).unwrap().unwrap();

    let tags : Vec<Tag> = pp.into_iter().map(|p| p.tag()).collect();
    assert_eq!(&[ Tag::CompressedData, Tag::Literal ][..],
               &tags[..]);
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
    pub fn from_buffered_reader<R: BufferedReader<Cookie>>(bio: R)
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
            reader, None, Cookie::default());
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
            data, Cookie::default());
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
