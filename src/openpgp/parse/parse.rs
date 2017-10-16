// http://rust.unhandledexpression.com/nom/enum.IResult.html
// I = Input, O = Output, E = Error
//
// pub enum IResult<I, O, E = u32> {
//     // Correct parsing.  I = rest of unparsed data; O = the parser's result
//     Done(I, O),
//     // An error.
//     Error(Err<E>),
//     // 
//     Incomplete(Needed),
// }
//
// The named! macro is shorthand for creating an appropriate type
// signature for a nom combinator.  Normally, it is used like this:
//
//   named!(my_parser, parser_body)
//
// If the function name includes a generic type, then that can be used
// to override the type of the output in the IResult.  For instance:
//
//   named!(word<&str>, map_res!(take_while!(nom::is_alphabetic), str::from_utf8));
//
// preceded! takes two parsers.  The first is a prefix to match.  If
// the prefix matches, then it is discarded and the suffix is matched
// and returned.  This is useful when matching a signature or
// delimiter that isn't needed for further processing.
//
// preceded!(prefix, suffix) -> suffix

// delimited! is like preceded, but it takes three parsers and returns
// what the result of the middle parser if the first and last parser
// succeed.  It is useful for extracting name from: "[ name ]"

// take_while! is a simple parser that accumulates data from the input
// stream as long as the provided callback returns true.
//
//    fn is_digit(c: u8) -> bool { c >= '0' as u8 && c <= '9' as u8 }
//    named!(number, take_while!(is_digit));
//    let r = number(&b"1234after"[..]);
//    assert_eq!(r, IResult::Done(&b"after"[..], &b"1234"[..]));
//
// The map_res macro applies a function to the result portion of an
// IResult.  This is useful, for instance, to convert a byte array to
// a string:
//
//   named!(word<&str>, map_res!(take_while!(nom::is_alphabetic), str::from_utf8));
//   let r = word(&b"hello, world"[..]);
//   assert_eq!(r, IResult::Done(&b", world"[..], &"hello"[..]));

// use nom::HexDisplay;

use num;

use nom;
use nom::{IResult,be_u16,be_u32};

use super::*;

macro_rules! try_iresult (
  ($i:expr) => (
    match $i {
      nom::IResult::Done(i,o)     => (i,o),
      nom::IResult::Error(e)      => return nom::IResult::Error(e),
      nom::IResult::Incomplete(i) => return nom::IResult::Incomplete(i)
    }
  );
);

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
                                              tag: num::FromPrimitive::from_u8(tag).unwrap()
                                          },
                                      }))) |
                       /* Old format packet.  */
                       0 => do_parse!(tag: take_bits!(u8, 4) >>
                                      length_type: take_bits!(u8, 2) >>
                                      (CTB::Old(CTBOld {
                                          common: CTBCommon {
                                              tag: num::FromPrimitive::from_u8(tag).unwrap()
                                          },
                                          length_type:
                                            num::FromPrimitive::from_u8(length_type).unwrap(),
                                      })))
            ) >>
            (r))));

/// Decode a new format body length (as described in Section 4.2.2 of RFC4880).
///
/// Example:
///
///    assert_eq!(body_length_new_format(&[0x64][..]),
///               nom::IResult::Done(&b""[..], BodyLength::Full(100)));
pub fn body_length_new_format(input: &[u8]) -> IResult<&[u8], BodyLength> {
    fn to_u8 (x: &[u8]) -> u8 {
        assert_eq!(x.len(), 1);
        x[0]
    }

    match map!(input, take!(1), to_u8) {
        IResult::Done(input, octet1) if octet1 < 192 => {
            /* One octet.  */
            return IResult::Done(input, BodyLength::Full(octet1 as u32));
        },
        IResult::Done(input, octet1) if 192 <= octet1 && octet1 < 224 => {
            /* Two octets length.  */
            match map!(input, take!(1), to_u8) {
                IResult::Done(input, octet2) => {
                    return IResult::Done(
                        input,
                        BodyLength::Full(((octet1 as u32 - 192) << 8) + octet2 as u32 + 192));
                },
                IResult::Error(e) => {
                    return IResult::Error(e);
                },
                IResult::Incomplete(needed) => {
                    return IResult::Incomplete(needed);
                },
            }
        },
        IResult::Done(input, octet1) if 224 <= octet1 && octet1 < 255 => {
            /* Partial body length.  */
            return IResult::Done(input, BodyLength::Partial(1 << (octet1 & 0x1F)));
        },
        IResult::Done(input, octet1) if octet1 == 255 => {
            /* Four octets.  */
            return map!(input, nom::be_u32, |x| BodyLength::Full(x));
        },
        // The above is actually exhaustive---it covers all values
        // that a u8 could assume (or should), but rust doesn't figure
        // that out, so we add this arm.
        IResult::Done(_, _) => unreachable!(),
        IResult::Error(e) => {
            return IResult::Error(e);
        },
        IResult::Incomplete(needed) => {
            return IResult::Incomplete(needed);
        },
    }
}

#[test]
fn body_length_new_format_test() {
    /* Examples from Section 4.2.3 of RFC4880.  */

    // Example #1.
    assert_eq!(body_length_new_format(&[0x64][..]),
               IResult::Done(&b""[..], BodyLength::Full(100)));

    // Example #2.
    assert_eq!(body_length_new_format(&[0xC5, 0xFB][..]),
               IResult::Done(&b""[..], BodyLength::Full(1723)));

    // Example #3.
    assert_eq!(body_length_new_format(&[0xFF, 0x00, 0x01, 0x86, 0xA0][..]),
               IResult::Done(&b""[..], BodyLength::Full(100000)));

    // Example #4.
    assert_eq!(body_length_new_format(&[0xEF][..]),
               IResult::Done(&b""[..], BodyLength::Partial(32768)));
    assert_eq!(body_length_new_format(&[0xE1][..]),
               IResult::Done(&b""[..], BodyLength::Partial(2)));
    assert_eq!(body_length_new_format(&[0xF0][..]),
               IResult::Done(&b""[..], BodyLength::Partial(65536)));
    assert_eq!(body_length_new_format(&[0xC5, 0xDD][..]),
               IResult::Done(&b""[..], BodyLength::Full(1693)));
}

fn body_length_old_format<'a>(input: &'a [u8], length_type: PacketLengthType)
                          -> IResult<&'a [u8], BodyLength> {
    match length_type {
        PacketLengthType::OneOctet =>
            return map!(input, nom::be_u8, |x| BodyLength::Full(x as u32)),
        PacketLengthType::TwoOctets =>
            return map!(input, nom::be_u16, |x| BodyLength::Full(x as u32)),
        PacketLengthType::FourOctets =>
            return map!(input, nom::be_u32, |x| BodyLength::Full(x)),
        PacketLengthType::Indeterminate =>
            return IResult::Done(input, BodyLength::Indeterminate),
    }
}

#[test]
fn body_length_old_format_test() {
    assert_eq!(body_length_old_format(&[1], PacketLengthType::OneOctet),
               IResult::Done(&b""[..], BodyLength::Full(1)));
    assert_eq!(body_length_old_format(&[1, 2], PacketLengthType::TwoOctets),
               IResult::Done(&b""[..], BodyLength::Full((1 << 8) + 2)));
    assert_eq!(body_length_old_format(&[1, 2, 3, 4], PacketLengthType::FourOctets),
               IResult::Done(&b""[..],
                             BodyLength::Full((1 << 24) + (2 << 16) + (3 << 8) + 4)));
    assert_eq!(body_length_old_format(&[1, 2, 3, 4, 5, 6], PacketLengthType::FourOctets),
               IResult::Done(&[5, 6][..],
                             BodyLength::Full((1 << 24) + (2 << 16) + (3 << 8) + 4)));
    assert_eq!(body_length_old_format(&[1, 2, 3, 4], PacketLengthType::Indeterminate),
               IResult::Done(&[1, 2, 3, 4][..], BodyLength::Indeterminate));
}

/// INPUT is a byte array that presumably contains an OpenPGP packet.
/// This function parses the packet's header and returns a
/// deserialized version and the rest input.
pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, ctb) = try_iresult!(ctb(input));
    let (input, length) = match ctb {
        CTB::New(_) => try_iresult!(body_length_new_format(input)),
        CTB::Old(ref ctb) => try_iresult!(body_length_old_format(input, ctb.length_type)),
    };
    return IResult::Done(input, Header { ctb: ctb, length: length });
}

// Packets.

/// Parse the body of a signature packet.
pub fn signature_body(header: Header, input: &[u8]) -> IResult<&[u8], Signature> {
    let len = match header.length {
        BodyLength::Full(x) => x as usize,
        BodyLength::Partial(_) => unimplemented!(),
        BodyLength::Indeterminate => input.len(),
    };

    if len > input.len() {
        // XXX: Should we return len or len - input.len()?
        return IResult::Incomplete(nom::Needed::Size(len));
    }

    /* Make sure we don't read beyond the end of the packet.  */
    let rest = &input[len..];
    let input = &input[0..len];
    let r = do_parse!(
        input,
        version: take!(1) >>
        sigtype: take!(1) >>
        pk_algo: take!(1) >>
        hash_algo: take!(1) >>
        hashed_area_len: be_u16 >>
        hashed_area: take!(hashed_area_len) >>
        unhashed_area_len: be_u16 >>
        unhashed_area: take!(unhashed_area_len) >>
        hash_prefix: take!(2) >>
        (Signature {
            common: PacketCommon {
                tag: Tag::Signature,
            },
            version: version[0],
            sigtype: sigtype[0],
            pk_algo: pk_algo[0],
            hash_algo: hash_algo[0],
            hashed_area: hashed_area,
            unhashed_area: unhashed_area,
            hash_prefix: [hash_prefix[0], hash_prefix[1]],
            mpis: &b""[..],
        }));

    if let IResult::Done(content, signature) = r {
        return IResult::Done(rest, Signature { mpis: content, .. signature });
    }
    return r;
}

#[test]
fn signature_body_test () {
    let data = include_bytes!("sig.asc");
    let (data, header) = header(data).unwrap();

    assert_eq!(header.ctb.tag, Tag::Signature);
    assert_eq!(header.length, BodyLength::Full(307));

    let (_, p) = signature_body(header, data).unwrap();
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

// Parse the body of a public key, public subkey, secret key or secret
// subkey packet.
pub fn key_body(header: Header, input: &[u8]) -> IResult<&[u8], Key> {
    assert!(header.ctb.tag == Tag::PublicKey
            || header.ctb.tag == Tag::PublicSubkey
            || header.ctb.tag == Tag::SecretKey
            || header.ctb.tag == Tag::SecretSubkey);

    let len = match header.length {
        BodyLength::Full(x) => x as usize,
        BodyLength::Partial(_) => unimplemented!(),
        BodyLength::Indeterminate => input.len(),
    };

    if len > input.len() {
        // XXX: Should we return len or len - input.len()?
        return IResult::Incomplete(nom::Needed::Size(len));
    }

    /* Make sure we don't read beyond the end of the packet.  */
    let rest = &input[len..];
    let input = &input[0..len];
    let (mpis, key) = try_iresult!(do_parse!(
        input,
        version: take!(1) >>
        creation_time: be_u32 >>
        pk_algo: take!(1) >>
        (Key {
            common: PacketCommon {
                tag: header.ctb.tag,
            },
            version: version[0],
            creation_time: creation_time,
            pk_algo: pk_algo[0],
            mpis: &b""[..],
        })));

    return IResult::Done(rest, Key { mpis: mpis, .. key });
}

// Parse the body of a user id packet.
pub fn userid_body(header: Header, input: &[u8]) -> IResult<&[u8], UserID> {
    let len = match header.length {
        BodyLength::Full(x) => x as usize,
        BodyLength::Partial(_) => unimplemented!(),
        BodyLength::Indeterminate => input.len(),
    };

    if len > input.len() {
        // XXX: Should we return len or len - input.len()?
        println!("have: {}, need: {} bytes\n", input.len(), len);
        return IResult::Incomplete(nom::Needed::Size(len));
    }

    /* Make sure we don't read beyond the end of the packet.  */
    let rest = &input[len..];
    let input = &input[0..len];

    return IResult::Done(rest,
                         UserID {
                             common: PacketCommon {
                                 tag: Tag::UserID,
                             },
                             value: input,
                         });
}

/// Parse the body of a literal packet.
///
///
/// let data = include_bytes!("literal-mode-b.asc");
/// let (data, ctb) = ctb(data).unwrap();
/// assert_eq!(ctb.tag, Tag::Literal);
///
/// let (data, len) = body_length_new_format(data).unwrap();
/// println!("body len: {:?}", len);
///
/// let (data, p) = literal_body(Header { ctb: ctb, length: len }, data).unwrap();
/// println!("packet: {:?}", p);
pub fn literal_body(header: Header, input: &[u8]) -> IResult<&[u8], Literal> {
    let len = match header.length {
        BodyLength::Full(x) => x as usize,
        BodyLength::Partial(_) => unimplemented!(),
        BodyLength::Indeterminate => input.len(),
    };

    if len > input.len() {
        // XXX: Should we return len or len - input.len()?
        return IResult::Incomplete(nom::Needed::Size(len));
    }

    /* Make sure we don't read beyond the end of the packet.  */
    let rest = &input[len..];
    let input = &input[0..len];
    let r = do_parse!(
        input,
        format: take!(1) >>
        filename_len: take!(1) >>
        filename: take!(filename_len[0]) >>
        date: be_u32 >>
        (Literal {
            common: PacketCommon {
                tag: Tag::Literal,
            },
            format: format[0],
            filename: filename,
            date: date,
            content: &b""[..],
        }));

    if let IResult::Done(content, literal) = r {
        return IResult::Done(rest, Literal { content: content, .. literal });
    }
    return r;
}

#[test]
fn literal_body_test () {
    {
        let data = include_bytes!("literal-mode-b.asc");
        let (data, header) = header(data).unwrap();

        assert_eq!(header.ctb.tag, Tag::Literal);
        assert_eq!(header.length, BodyLength::Full(18));

        let (_, p) = literal_body(header, data).unwrap();
        // println!("packet: {:?}", p);

        assert_eq!(p.format, 'b' as u8);
        assert_eq!(p.filename, &b"foobar"[..]);
        assert_eq!(p.date, 1507458744);
        assert_eq!(p.content, &b"FOOBAR"[..]);
    }

    {
        let data = include_bytes!("literal-mode-t-partial-body.asc");
        let (data, header) = header(data).unwrap();

        assert_eq!(header.ctb.tag, Tag::Literal);
        println!("{:?}", header);
        assert_eq!(header.length, BodyLength::Partial(4096));

        let (_, p) = literal_body(header, data).unwrap();
        // println!("packet: {:?}", p);

        assert_eq!(p.format, 'b' as u8);
        assert_eq!(p.filename, &b"foobar"[..]);
        assert_eq!(p.date, 1507458744);
        assert_eq!(p.content, &b"FOOBAR"[..]);
    }
}

/// Parse exactly one OpenPGP packet.  Any remaining data is returned.
pub fn parse_packet(input: &[u8]) -> IResult<&[u8], Packet> {
    let (input, header) = try_iresult!(header(input));

    // println!("Header: {:?}", header);
    // println!("Input ({} bytes): {:?}",
    //          input.len(),
    //          &input[0..(if input.len() > 20 { 20 } else { input.len() })]);

    match header.ctb.tag {
        Tag::Signature => {
            let (input, signature) = try_iresult!(signature_body (header, input));
            return IResult::Done(input, Packet::Signature(signature));
        },
        Tag::PublicKey => {
            let (input, key) = try_iresult!(key_body (header, input));
            return IResult::Done(input, Packet::PublicKey(key));
        },
        Tag::PublicSubkey => {
            let (input, key) = try_iresult!(key_body (header, input));
            return IResult::Done(input, Packet::PublicSubkey(key));
        },
        Tag::SecretKey => {
            let (input, key) = try_iresult!(key_body (header, input));
            return IResult::Done(input, Packet::SecretKey(key));
        },
        Tag::SecretSubkey => {
            let (input, key) = try_iresult!(key_body (header, input));
            return IResult::Done(input, Packet::SecretSubkey(key));
        },
        Tag::UserID => {
            let (input, userid) = try_iresult!(userid_body (header, input));
            return IResult::Done(input, Packet::UserID(userid));
        },
        Tag::Literal => {
            let (input, literal) = try_iresult!(literal_body (header, input));
            return IResult::Done(input, Packet::Literal(literal));
        },
        _ => {
            println!("Unsupported packet type: {:?}", header);
            return IResult::Error(nom::ErrorKind::Custom(99987))
        },
    }
}

#[test]
fn parse_packet_test () {
    // XXX: This test should be more thorough.  Right now, we mostly
    // just rely on the fact that an assertion is not thrown.

    let mut data = &include_bytes!("public-key.asc")[..];
    while data.len() > 0 {
        let r = parse_packet(data);
        match r {
            IResult::Done(rest, _p) => {
                // println!("packet: {:?}\n", _p);
                data = rest;
                continue;
            },
            e => {
                /* We should consume all of the data.  */
                println!("{:?}", e);
                unreachable!()
            }
        }
    }
}

pub fn parse_message (input: &[u8]) -> IResult<&[u8], Vec<Packet>> {
    let mut input = input;
    let mut packets = Vec::with_capacity(16);

    while input.len() > 0 {
        let (rest, p) = try_iresult!(parse_packet(input));
        // println!("packet: {:?}\n", _p);
        input = rest;
        packets.push(p);
        continue;
    }

    return IResult::Done(&b""[..], packets);
}

#[test]
fn parse_message_test () {
    // XXX: This test should be more thorough.  Right now, we mostly
    // just rely on the fact that an assertion is not thrown.

    let data = include_bytes!("public-key.asc");
    let (rest, _packets) = parse_message (data).unwrap();
    assert_eq!(rest.len(), 0);
}
