use std::io;
use std::cmp;
use std::str;

use super::*;

mod partial_body;
use self::partial_body::PartialBodyFilter;

// Whether to trace the modules execution (on stderr).
const TRACE : bool = false;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

fn write_byte<W: io::Write>(o: &mut W, b: u8) -> Result<(), io::Error> {
    let b : [u8; 1] = [b; 1];
    o.write_all(&b[..])
}

fn write_be_u16<W: io::Write>(o: &mut W, n: u16) -> Result<(), io::Error> {
    let b : [u8; 2] = [ ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
    o.write_all(&b[..])
}

fn write_be_u32<W: io::Write>(o: &mut W, n: u32) -> Result<(), io::Error> {
    let b : [u8; 4] = [ (n >> 24) as u8, ((n >> 16) & 0xFF) as u8,
                         ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
    o.write_all(&b[..])
}

/// Returns a new format body length header appropriate for the given
/// body length.
///
/// Note: the returned byte stream does not include a ctb header.
pub fn body_length_new_format(l: BodyLength) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(5);
    match l {
        BodyLength::Full(l) => {
            if l <= 191 {
                // Writing to a Vec can never fail.
                write_byte(&mut buffer, l as u8).unwrap();
            } else if l < 8383 {
                let v = l - 192;
                let v = v + (192 << 8);
                write_be_u16(&mut buffer, v as u16).unwrap();
            } else {
                write_be_u32(&mut buffer, l).unwrap();
            }
        },
        BodyLength::Partial(_) => {
            unimplemented!();
        },
        BodyLength::Indeterminate => {
            panic!("BodyLength::Indeterminate not supported by new format packets.");
        },
    }

    buffer
}

/// Returns an old format body length header appropriate for the given
/// body length.
///
/// Note: the returned byte stream does not include a ctb header.
pub fn body_length_old_format(l: BodyLength) -> Vec<u8> {
    // Assume an optimal encoding is desired.
    let mut buffer = Vec::with_capacity(4);
    match l {
        BodyLength::Full(l) => {
            match l {
                // One octet length.
                // write_byte can't fail for a Vec.
                0 ... 0xFF =>
                    write_byte(&mut buffer, l as u8).unwrap(),
                // Two octet length.
                0x1_00 ... 0xFF_FF =>
                    write_be_u16(&mut buffer, l as u16).unwrap(),
                // Four octet length,
                _ =>
                    write_be_u32(&mut buffer, l as u32).unwrap(),
            }
        },
        BodyLength::Indeterminate => {},
        BodyLength::Partial(_) =>
            panic!("old format CTB don't supported partial body length encoding."),
    }

    buffer
}

/// Returns a new format CTB.
pub fn ctb_new(tag: Tag) -> u8 {
    0b1100_0000u8 | Tag::to_numeric(tag)
}

/// Returns an old format CTB.
pub fn ctb_old(tag: Tag, l: BodyLength) -> u8 {
    let len_encoding : u8 = match l {
        // Assume an optimal encoding.
        BodyLength::Full(l) => {
            match l {
                // One octet length.
                0 ... 0xFF => 0,
                // Two octet length.
                0x1_00 ... 0xFF_FF => 1,
                // Four octet length,
                _ => 2,
            }
        },
        BodyLength::Partial(_) => {
            panic!("Partial body lengths are not support for old format packets.");
        },
        BodyLength::Indeterminate => 3,
    };
    assert!(len_encoding <= 3);

    let tag = Tag::to_numeric(tag);
    // Only tags 0-15 are supported.
    assert!(tag < 16);

    0b1000_0000u8 | (tag << 2) | len_encoding
}

/// Writes a serialized version of the `Literal` data packet to `o`.
pub fn literal_serialize<W: io::Write>(o: &mut W, l: &Literal)
        -> Result<(), io::Error> {
    let body = if let Some(ref body) = l.common.body {
        &body[..]
    } else {
        &b""[..]
    };

    if TRACE {
        let prefix = &body[..cmp::min(body.len(), 20)];
        eprintln!("literal_serialize({}{}, {} bytes)",
                  String::from_utf8_lossy(prefix),
                  if body.len() > 20 { "..." } else { "" },
                  body.len());
    }

    let filename = if let Some(ref filename) = l.filename {
        let len = cmp::min(filename.len(), 255) as u8;
        &filename[..len as usize]
    } else {
        &b""[..]
    };

    let len = 1 + (1 + filename.len()) + 4 + body.len();

    write_byte(o, ctb_old(Tag::Literal, BodyLength::Full(len as u32)))?;

    o.write_all(&body_length_old_format(BodyLength::Full(len as u32))[..])?;

    write_byte(o, l.format)?;
    write_byte(o, filename.len() as u8)?;
    o.write_all(filename)?;
    write_be_u32(o, l.date)?;
    o.write_all(body)?;

    Ok(())
}

/// Writes a serialized version of the specified `CompressedData`
/// packet to `o`.
///
/// This function works recursively: if the `CompressedData` packet
/// contains any packets, they are also serialized.
pub fn compressed_data_serialize<W: io::Write>(o: &mut W, cd: &CompressedData)
        -> Result<(), io::Error> {
    use flate2::Compression as FlateCompression;
    use flate2::write::{DeflateEncoder, ZlibEncoder};
    use bzip2::Compression as BzCompression;
    use bzip2::write::BzEncoder;

    if TRACE {
        eprintln!("compress_data_serialize(algo: {}, {:?} children, {:?} bytes)",
                  cd.algo,
                  cd.common.children.as_ref().map(|cont| cont.children().len()),
                  cd.common.body.as_ref().map(|body| body.len()));
    }

    // Packet header.
    write_byte(o, ctb_new(Tag::CompressedData))?;
    let mut o = PartialBodyFilter::new(o);

    // Compressed data header.
    write_byte(&mut o, cd.algo)?;

    // Create an appropriate filter.
    let mut o : Box<io::Write> = match cd.algo {
        0 => Box::new(o),
        1 => Box::new(DeflateEncoder::new(o, FlateCompression::default()))
                as Box<io::Write>,
        2 => Box::new(ZlibEncoder::new(o, FlateCompression::default()))
                as Box<io::Write>,
        3 => Box::new(BzEncoder::new(o, BzCompression::Default))
                as Box<io::Write>,
        _ => unimplemented!(),
    };

    // Serialize the packets.
    if let Some(ref children) = cd.common.children {
        for p in children.children() {
            packet_serialize(&mut o, p)?;
        }
    }

    // Append the data.
    if let Some(ref data) = cd.common.body {
        o.write_all(data)?;
    }

    Ok(())
}

/// Writes a serialized version of the specified `Packet` to `o`.
///
/// This function works recursively: if the packet contains any
/// packets, they are also serialized.
fn packet_serialize<W: io::Write>(o: &mut W, p: &Packet)
        -> Result<(), io::Error> {
    match p {
        &Packet::Literal(ref l) => literal_serialize(o, l),
        &Packet::CompressedData(ref cd) => compressed_data_serialize(o, cd),
        _ => unimplemented!(),
    }
}

impl Message {
    /// Writes a serialized version of the specified `Message` to `o`.
    pub fn serialize<W: io::Write>(self, o: &mut W) -> Result<(), io::Error> {
        for p in self.children() {
            packet_serialize(o, p)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod serialize_test {
    use std::fs::File;
    use std::io::Read;

    use super::*;
    use parse::to_unknown_packet;
    use parse::PacketParserBuilder;

    // A convenient function to dump binary data to stdout.
    fn binary_pp(data: &[u8]) -> String {
        let mut output = Vec::with_capacity(data.len() * 2 + 3 * data.len() / 4);

        for i in 0..data.len() {
            if i > 0 && i % (4 * 4 * 2) == 0 {
                output.push('\n' as u8);
            } else {
                if i > 0 && i % 2 == 0 {
                    output.push(' ' as u8);
                }
                if i > 0 && i % (4 * 2) == 0 {
                    output.push(' ' as u8);
                }
            }

            let top = data[i] >> 4;
            let bottom = data[i] & 0xFu8;

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

    // Does a bit-wise comparison of two packets ignoring the CTB
    // format, the body length encoding, and whether partial body
    // length encoding was used.
    fn packets_bitwise_compare(filename: &str, expected: &[u8], got: &[u8]) {
        let expected = to_unknown_packet(expected).unwrap();
        let got = to_unknown_packet(got).unwrap();

        let expected_body = if let Some(ref data) = expected.common.body {
            &data[..]
        } else {
            &b""[..]
        };
        let got_body = if let Some(ref data) = got.common.body {
            &data[..]
        } else {
            &b""[..]
        };

        let mut fail = false;
        if expected.tag != got.tag {
            eprintln!("Expected a {:?}, got a {:?}", expected.tag, got.tag);
            fail = true;
        }
        if expected_body != got_body {
            eprintln!("Packet contents don't match (for {}):",
                      filename);
            eprintln!("Expected ({} bytes):\n{}",
                      expected_body.len(), binary_pp(&expected_body));
            eprintln!("Got ({} bytes):\n{}",
                      got_body.len(), binary_pp(&got_body));
            fail = true;
        }
        if fail {
            panic!("Packets don't match (for {}).", filename);
        }
    }

    #[test]
    fn serialize_test_1() {
        let filenames = [
            "literal-mode-b.gpg",
            "literal-mode-t-partial-body.gpg",
        ];

        for filename in filenames.iter() {
            let path = path_to(filename);
            let mut data = Vec::new();
            File::open(&path).expect(&path.to_string_lossy())
                .read_to_end(&mut data).expect("Reading test data");
            let m = Message::from_bytes(&data[..]).unwrap();

            let po = m.descendants().next();
            if let Some(&Packet::Literal(ref l)) = po {
                let mut buffer = Vec::new();
                literal_serialize(&mut buffer, l).unwrap();

                packets_bitwise_compare(filename, &data[..], &buffer[..]);
            } else {
                panic!("Expected a literal data packet.");
            }
        }
    }

    #[test]
    fn serialize_test_2() {
        let filenames = [
            // XXX: We assume that compression is deterministic across
            // implementations and that the same parameters are used
            // by default.
            "compressed-data-algo-1.gpg",
            "compressed-data-algo-2.gpg",
            "compressed-data-algo-3.gpg",
            // This uses the "no compression" compression algorithm,
            // so this test should always be valid.
            "recursive-1.gpg",
        ];

        for filename in filenames.iter() {
            let path = path_to(filename);
            let mut data = Vec::new();
            File::open(&path).expect(&path.to_string_lossy())
                .read_to_end(&mut data).expect("Reading test data");
            let m = PacketParserBuilder::from_bytes(&data[..]).unwrap()
                .max_recursion_depth(0)
                .buffer_unread_content()
                //.trace()
                .to_message().unwrap();

            let po = m.descendants().next();
            if let Some(&Packet::CompressedData(ref cd)) = po {
                let mut buffer = Vec::new();
                compressed_data_serialize(&mut buffer, cd).unwrap();

                let m2 = PacketParserBuilder::from_bytes(&buffer[..]).unwrap()
                    .max_recursion_depth(0)
                    .buffer_unread_content()
                    //.trace()
                    .to_message().unwrap();

                if m != m2 {
                    eprintln!("Orig:");
                    let p = m.children().next().unwrap();
                    eprintln!("{:?}", p);
                    let body = &p.body.as_ref().unwrap()[..];
                    eprintln!("Body: {}", body.len());
                    eprintln!("{}", binary_pp(body));

                    eprintln!("Reparsed:");
                    let p = m2.children().next().unwrap();
                    eprintln!("{:?}", p);
                    let body = &p.body.as_ref().unwrap()[..];
                    eprintln!("Body: {}", body.len());
                    eprintln!("{}", binary_pp(body));

                    assert_eq!(m, m2);
                }
            } else {
                panic!("Expected a compressed data data packet.");
            }

            break;
        }
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn serialize_and_parse_1() {
        fn make_lit(body: &[u8]) -> Packet {
            Packet::Literal(Literal {
                common: PacketCommon {
                    body: Some(body.clone().to_vec()),
                    children: None,
                },
                format: 't' as u8,
                filename: None,
                date: 0
            })
        }

        fn make_cd(algo: u8, p: Packet, p2: Option<Packet>) -> Packet {
            let mut children = Vec::new();
            children.push(p);
            if let Some(p) = p2 {
                children.push(p);
            }
            Packet::CompressedData(CompressedData {
                common: PacketCommon {
                    body: None,
                    children: Some(Container { packets: children }),
                },
                algo: algo,
            })
        }

        let mut messages = Vec::new();

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            make_cd(0,
                    make_lit(&b"one"[..]),
                    Some(make_lit(&b"two"[..]))));
        top_level.push(make_lit(&b"three"[..]));
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "one (3 bytes)" })
        //   2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            make_cd(0,
                make_cd(0,
                    make_lit(&b"one"[..]),
                    Some(make_lit(&b"two"[..]))),
                Some(make_cd(0,
                    make_lit(&b"three"[..]),
                    Some(make_lit(&b"four"[..]))))));
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: CompressedData(CompressedData { algo: 0 })
        //    1: CompressedData(CompressedData { algo: 0 })
        //     1: Literal(Literal { body: "one (3 bytes)" })
        //     2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: CompressedData(CompressedData { algo: 0 })
        //    1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            make_cd(0,
                make_cd(0,
                    make_cd(0,
                        make_cd(0,
                            make_lit(&b"one"[..]),
                            Some(make_lit(&b"two"[..]))),
                        None),
                    None),
                Some(make_cd(0,
                    make_cd(0,
                        make_lit(&b"three"[..]),
                        None),
                    Some(make_lit(&b"four"[..]))))));
        messages.push(top_level);

        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        // 3: Literal(Literal { body: "four (4 bytes)" })
        // 4: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "five (4 bytes)" })
        //  2: Literal(Literal { body: "six (3 bytes)" })
        let mut top_level = Vec::new();
        top_level.push(
            make_cd(0,
                    make_lit(&b"one"[..]),
                    Some(make_lit(&b"two"[..]))));
        top_level.push(make_lit(&b"three"[..]));
        top_level.push(make_lit(&b"four"[..]));
        top_level.push(
            make_cd(0,
                    make_lit(&b"five"[..]),
                    Some(make_lit(&b"six"[..]))));
        messages.push(top_level);

        for m in messages.into_iter() {
            let m = Message::from_packets(m);

            m.pretty_print();

            // Serialize the message into a buffer.
            let mut buffer = Vec::new();
            m.clone().serialize(&mut buffer).unwrap();

            // use std::fs::File;
            // use std::io::prelude::*;
            // let mut file = File::create(format!("/tmp/foo.gpg", i)).unwrap();
            // file.write_all(&buffer[..]).unwrap();

            // Reparse it.
            let m2 = PacketParserBuilder::from_bytes(&buffer[..]).unwrap()
                //.trace()
                .buffer_unread_content()
                .to_message().unwrap();

            if m != m2 {
                eprintln!("ORIG...");
                m.pretty_print();
                eprintln!("REPARSED...");
                m2.pretty_print();
                panic!("Reparsed packet does not match original packet!");
            }
        }
    }
}

