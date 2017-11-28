use std;
use std::fs::File;
use std::io::{Error,ErrorKind};

use num::FromPrimitive;

use super::*;

pub mod buffered_reader;
use self::buffered_reader::*;
pub use self::buffered_reader::BufferedReader;

mod buffered_reader_partial_body;
use self::buffered_reader_partial_body::*;

// Packet headers.

// Parse a CTB (as described in Section 4.2 of RFC4880) and return a
// 'struct CTB'.  This function parses both new and old format ctbs.
//
// Example:
//
//   let (input, ctb) = ctb(data).unwrap();
//   println!("header: {:?}", ctb);
//   assert_eq!(ctb.tag, 11);
named!(
    ctb<CTB>,
    bits!(
        do_parse!(
            tag_bits!(u8, 1, 1) >>
            r: switch!(take_bits!(u8, 1),
                       /* New format.  */
                       1 => do_parse!(tag: take_bits!(u8, 6) >>
                                      (CTB::New(CTBNew {
                                          common: CTBCommon {
                                              tag: FromPrimitive::from_u8(tag).unwrap()
                                          },
                                      }))) |
                       /* Old format packet.  */
                       0 => do_parse!(tag: take_bits!(u8, 4) >>
                                      length_type: take_bits!(u8, 2) >>
                                      (CTB::Old(CTBOld {
                                          common: CTBCommon {
                                              tag: FromPrimitive::from_u8(tag).unwrap()
                                          },
                                          length_type:
                                            FromPrimitive::from_u8(length_type).unwrap(),
                                      })))
            ) >>
            (r))));

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
pub fn header<T: BufferedReader> (bio: &mut T) -> Result<Header, std::io::Error> {
    use nom::IResult;

    let ctb = match ctb(bio.data_consume_hard(1)?) {
        IResult::Done(_, ctb) => ctb,
        // We know we have enough data.  Nothing can go wrong.
        _ => unreachable!(),
    };
    let length = match ctb {
        CTB::New(_) => body_length_new_format(bio)?,
        CTB::Old(ref ctb) => body_length_old_format(bio, ctb.length_type)?,
    };
    return Ok(Header { ctb: ctb, length: length });
}

// Packets.

/// Parse the body of a signature packet.
pub fn signature_body<T: BufferedReader>(bio: &mut T)
                                         -> Result<Signature, std::io::Error> {
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

    return Ok(Signature {
        common: PacketCommon {
            tag: Tag::Signature,
        },
        version: version,
        sigtype: sigtype,
        pk_algo: pk_algo,
        hash_algo: hash_algo,
        hashed_area: hashed_area,
        unhashed_area: unhashed_area,
        hash_prefix: [hash_prefix1, hash_prefix2],
        mpis: mpis,
    });
}

#[test]
fn signature_body_test () {
    let data = include_bytes!("sig.asc");

    {
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Signature);
        assert_eq!(header.length, BodyLength::Full(307));

        let p = signature_body(&mut bio).unwrap();
        // println!("packet: {:?}", p);

        assert_eq!(p.version, 4);
        assert_eq!(p.sigtype, 0);
        assert_eq!(p.pk_algo, 1);
        assert_eq!(p.hash_algo, 10);
        assert_eq!(p.hashed_area.len(), 29);
        assert_eq!(p.unhashed_area.len(), 10);
        assert_eq!(p.hash_prefix, [0x65u8, 0x74]);
        assert_eq!(p.mpis.len(), 258);
    }
}

// Parse the body of a public key, public subkey, secret key or secret
// subkey packet.
pub fn key_body<T: BufferedReader>(bio: &mut T, tag: Tag) -> Result<Key, std::io::Error> {
    assert!(tag == Tag::PublicKey
            || tag == Tag::PublicSubkey
            || tag == Tag::SecretKey
            || tag == Tag::SecretSubkey);

    let version = bio.data_consume_hard(1)?[0];
    let creation_time = bio.read_be_u32()?;
    let pk_algo = bio.data_consume_hard(1)?[0];
    let mpis = bio.steal_eof()?;

    return Ok(Key {
        common: PacketCommon {
            tag: tag,
        },
        version: version,
        creation_time: creation_time,
        pk_algo: pk_algo,
        mpis: mpis,
    });
}

// Parse the body of a user id packet.
pub fn userid_body<T: BufferedReader>(bio: &mut T) -> Result<UserID, std::io::Error> {
    return Ok(UserID {
        common: PacketCommon {
            tag: Tag::UserID,
        },
        value: bio.steal_eof()?,
    });
}

/// Parse the body of a literal packet.
pub fn literal_body<R: BufferedReader>(mut bio: &mut R)
        -> Result<Literal, std::io::Error> {
    // When using bio, we have to do some acrobatics, because
    // calling bio.data() creates a mutable borrow on bio.  Since
    // there can only be one such borrow at a time, we have to put it
    // in its own scope, and in that scope we can't call, for
    // instance, bio.consume().
    let format = bio.data_consume_hard(1)?[0];
    let filename_len = bio.data_consume_hard(1)?[0];

    let filename = if filename_len > 0 {
        Some(bio.data_consume_hard(filename_len as usize)?
               [0..filename_len as usize].to_vec())
    } else {
        None
    };

    let date = bio.read_be_u32()?;

    let result = Literal {
        common: PacketCommon {
            tag: Tag::Literal,
        },
        format: format,
        filename: filename,
        date: date,
        content: bio.steal_eof()?,
    };

    return Ok(result);
}

#[test]
fn literal_body_test () {
    {
        let data = include_bytes!("literal-mode-b.asc");
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Full(18));

        let p = literal_body(&mut bio).unwrap();
        assert_eq!(p.format, 'b' as u8);
        assert_eq!(p.filename.unwrap()[..], b"foobar"[..]);
        assert_eq!(p.date, 1507458744);
        assert_eq!(&p.content[..], &b"FOOBAR"[..]);
    }

    {
        let data = include_bytes!("literal-mode-t-partial-body.asc");
        let mut bio = BufferedReaderMemory::new(data);

        let header = header(&mut bio).unwrap();
        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Partial(4096));

        if let BodyLength::Partial(l) = header.length {
            let mut bio2 = BufferedReaderPartialBodyFilter::new(&mut bio, l);

            let p = literal_body(&mut bio2).unwrap();
            assert_eq!(p.format, 't' as u8);
            println!("filename: {:?}", p.filename);
            assert_eq!(p.filename.unwrap()[..], b"manifesto.txt"[..]);
            assert_eq!(p.date, 1508000649);

            let expected = include_bytes!("literal-mode-t-partial-body.txt");

            assert_eq!(&p.content[..], &expected[..]);
        } else {
            unreachable!();
        }
    }
}

// Parse the body of a user id packet.
pub fn compressed_data_body<T: BufferedReader>(bio: &mut T)
                                               -> Result<CompressedData,
                                                         std::io::Error> {
    use flate2::read::DeflateDecoder;
    use flate2::read::ZlibDecoder;
    use bzip2::read::BzDecoder;

    let algo = bio.data_consume_hard(1)?[0];

    //   0          - Uncompressed
    //   1          - ZIP [RFC1951]
    //   2          - ZLIB [RFC1950]
    //   3          - BZip2 [BZ2]
    //   100 to 110 - Private/Experimental algorithm
    let mut decompressor : Box<std::io::Read> = match algo {
        0 => // Uncompressed.
            Box::new(bio),
        1 => // Zip.
            Box::new(DeflateDecoder::new(bio)),
        2 => // Zlib
            Box::new(ZlibDecoder::new(bio)),
        3 => // BZip2
            Box::new(BzDecoder::new(bio)),
        _ =>
            // Unknown algo.  XXX: Return a better error code.
            return Err(Error::new(ErrorKind::UnexpectedEof,
                                  "Unsupported compression algo")),
    };

    let mut bio = BufferedReaderGeneric::new(&mut decompressor, None);
    return Ok(CompressedData {
        common: PacketCommon {
            tag: Tag::CompressedData,
        },
        algo: algo,
        content: Message::deserialize(&mut bio)?,
    });
}

#[test]
fn compressed_data_body_test () {
    let expected = include_bytes!("literal-mode-t-partial-body.txt");

    for i in 1..4 {
        use std::path::PathBuf;
        use std::fs::File;

        let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                              "src", "openpgp", "parse",
                              &format!("compressed-data-algo-{}.asc", i)[..]]
            .iter().collect();
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::new(&mut f, None);

        let h = header(&mut bio).unwrap();
        println!("{:?}", h);
        assert_eq!(h.ctb.tag, Tag::CompressedData);
        assert_eq!(h.length, BodyLength::Indeterminate);

        let p = compressed_data_body(&mut bio).unwrap();
        println!("{:?}", p);

        assert_eq!(p.content.packets.len(), 1);
        match p.content.packets[0] {
            Packet::Literal(ref l) => {
                assert_eq!(l.filename, None);
                assert_eq!(l.format, 'b' as u8);
                assert_eq!(l.date, 1509219866);
                assert_eq!(&expected[..], &l.content[..]);
            },
            _ => {
                unreachable!();
            },
        }

    }
}

/// Parse exactly one OpenPGP packet.  Any remaining data is returned.
pub fn parse_packet<T: BufferedReader>(bio: &mut T, header: Header)
                                       -> Result<Packet, std::io::Error> {
    // println!("Header: {:?}", header);
    // println!("Input ({} bytes): {:?}",
    //          input.len(),
    //          &input[0..(if input.len() > 20 { 20 } else { input.len() })]);

    let tag = header.ctb.tag;
    match tag {
        Tag::Signature =>
            return Ok(Packet::Signature(signature_body(bio)?)),
        Tag::PublicSubkey =>
            return Ok(Packet::PublicSubkey(key_body(bio, tag)?)),
        Tag::PublicKey =>
            return Ok(Packet::PublicKey(key_body(bio, tag)?)),
        Tag::SecretKey =>
            return Ok(Packet::SecretKey(key_body(bio, tag)?)),
        Tag::SecretSubkey =>
            return Ok(Packet::SecretSubkey(key_body(bio, tag)?)),
        Tag::UserID =>
            return Ok(Packet::UserID(userid_body(bio)?)),
        Tag::Literal =>
            return Ok(Packet::Literal(literal_body(bio)?)),
        Tag::CompressedData =>
            // XXX: We need to recurse on p.content.
            return Ok(Packet::CompressedData(compressed_data_body(bio)?)),
        _ => {
            println!("Unsupported packet type: {:?}", header);
            // XXX: Fix error code.
            return Err(Error::new(ErrorKind::UnexpectedEof, "EOF"));
        },
    }
}


impl Message {
    /// Deserializes an OpenPGP message,
    pub fn deserialize<T: BufferedReader>(bio: &mut T)
                                          -> Result<Message, std::io::Error> {
        let mut packets : Vec<Packet> = Vec::with_capacity(16);

        // XXX: Be smarter about how we detect the EOF.
        while bio.data(1)?.len() != 0 {
            let header = header(bio)?;
            let p = match header.length {
                BodyLength::Full(len) => {
                    let mut bio2 = BufferedReaderLimitor::new(bio, len as u64);
                    let p = parse_packet(&mut bio2, header)?;
                    let rest = bio2.steal_eof()?;
                    if rest.len() > 0 {
                        println!("Packet failed to process {} bytes of data",
                                 rest.len());
                    }
                    p
                },
                BodyLength::Partial(len) => {
                    let mut bio2 = BufferedReaderPartialBodyFilter::new(bio,
                                                                        len);
                    let p = parse_packet(&mut bio2, header)?;
                    let rest = bio2.steal_eof()?;
                    if rest.len() > 0 {
                        println!("Packet failed to process {} bytes of data",
                                 rest.len());
                    }
                    p
                },
                BodyLength::Indeterminate => {
                    let p = parse_packet(bio, header)?;
                    let rest = bio.steal_eof()?;
                    if rest.len() > 0 {
                        println!("Packet failed to process {} bytes of data",
                                 rest.len());
                    }
                    p
                },
            };

            // println!("packet: {:?}\n", _p);
            packets.push(p);
        }

        Ok(Message {
            input: None,
            packets: packets,
        })
    }

    pub fn from_file(mut file: File) -> Result<Message, std::io::Error> {
        let mut bio = BufferedReaderGeneric::new(&mut file, None);
        Message::deserialize(&mut bio)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Message, std::io::Error> {
        let mut bio = BufferedReaderMemory::new(data);
        Message::deserialize(&mut bio)
    }
}

#[test]
fn deserialize_test () {
    // XXX: This test should be more thorough.  Right now, we mostly
    // just rely on the fact that an assertion is not thrown.

    {
        // A flat message.
        let data = include_bytes!("public-key.asc");
        let mut bio = BufferedReaderMemory::new(data);
        let message = Message::deserialize(&mut bio).unwrap();
        println!("Message has {} top-level packets.", message.packets.len());
        println!("Message: {:?}", message);

        let mut count = 0;
        for (i, p) in message.iter().enumerate() {
            println!("{}: {:?}", i, p);
            count += 1;
        }
        assert_eq!(count, 61);
    }

    {
        // A message containing a compressed packet that contains a
        // literal packet.
        use std::path::PathBuf;

        let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                              "src", "openpgp", "parse",
                              "compressed-data-algo-1.asc"]
            .iter().collect();
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::new(&mut f, None);
        let message = Message::deserialize(&mut bio).unwrap();
        println!("Message has {} top-level packets.", message.packets.len());
        println!("Message: {:?}", message);

        let mut count = 0;
        for (i, p) in message.iter().enumerate() {
            println!("{}: {:?}", i, p);
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
