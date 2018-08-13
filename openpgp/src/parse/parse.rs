use std;
use std::io;
use std::io::prelude::*;
use std::iter;
use std::cmp;
use std::str;
use std::mem;
use std::fmt;
use std::path::Path;
use time;
use failure;

use nettle::Hash;

use ::buffered_reader::*;

use {
    Result,
    CTB,
    BodyLength,
    s2k::S2K,
    Error,
    Tag,
    Header,
    Unknown,
    Signature,
    OnePassSig,
    Key,
    UserID,
    UserAttribute,
    Literal,
    CompressedData,
    SKESK,
    SEIP,
    MDC,
    Packet,
    KeyID,
    SecretKey,
    PKESK,
};
use constants::{
    CompressionAlgorithm,
    Curve,
    SignatureType,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};
use conversions::Time;
use mpis::{MPI, MPIs};
use symmetric::{Decryptor, BufferedReaderDecryptor};
use message;
use message::MessageValidator;

mod partial_body;
use self::partial_body::BufferedReaderPartialBodyFilter;

use subpacket::SubpacketArea;
pub mod key;

mod packet_pile_parser;
pub use self::packet_pile_parser::PacketPileParser;

mod hashed_reader;
pub(crate) use self::hashed_reader::HashedReader;

mod packet_parser_builder;
pub use self::packet_parser_builder::PacketParserBuilder;

pub mod mpis;

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

// Allows doing things like:
//
// ```rust,nocompile
// if ! destructures_to(Foo::Bar(_) = value) { ... }
// ```
macro_rules! destructures_to {
    ( $error: pat = $expr:expr ) => {
        {
            let x = $expr;
            if let $error = x {
                true
            } else {
                false
            }
        }
    };
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

// Used to parse an OpenPGP packet's header (note: in this case, the
// header means a Packet's fixed data, not the OpenPGP framing
// information, such as the CTB, and length information).
//
// This struct is not exposed to the user.  Instead, when a header has
// been successfully parsed, a `PacketParser` is returned.
pub(crate) struct PacketHeaderParser<'a> {
    // The reader stack wrapped in a BufferedReaderDup so that if
    // there is a parse error, we can abort and still return an
    // Unknown packet.
    reader: BufferedReaderDup<'a, Cookie>,

    // The current packet's header.
    header: Header,

    // This packet's recursion depth.
    //
    // A top-level packet has a recursion depth of 0.  Packets in a
    // top-level container have a recursion depth of 1, etc.
    recursion_depth: u8,

    // The `PacketParser`'s state.
    state: PacketParserState,

    /// A map of this packet.
    map: Option<Map>,
}

/// Creates a local marco called php_try! that returns an Unknown
/// packet instead of an Error like try! on parsing-related errors.
/// (Errors like read errors are still returned as usual.)
///
/// If you want to fail like this in a non-try! context, use
/// php.fail("reason").
macro_rules! make_php_try {
    ($parser:expr) => {
        macro_rules! php_try {
            ($e:expr) => {
                match $e {
                    Ok(b) => {
                        Ok(b)
                    },
                    Err(e) => {
                        // XXX: Ugh, this is getting unwieldy, and we
                        // are loosing information for no good reason.
                        // Why not simply pass the error to fail()?
                        // Otoh, currently the information isn't even
                        // stored.
                        let e = match e.downcast::<io::Error>() {
                            Ok(e) =>
                                if let io::ErrorKind::UnexpectedEof = e.kind() {
                                    return $parser.fail("truncated")
                                } else {
                                    e.into()
                                },
                            Err(e) => e,
                        };
                        let e = match e.downcast::<Error>() {
                            Ok(e) => match e {
                                Error::MalformedMPI(_) =>
                                    return $parser.fail("malformed MPI"),
                                _ =>
                                    e.into(),
                            },
                            Err(e) => e,
                        };

                        Err(e)
                    },
                }?
            };
        }
    };
}

impl<'a> std::fmt::Debug for PacketHeaderParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketHeaderParser")
            .field("header", &self.header)
            .field("recursion_depth", &self.recursion_depth)
            .field("reader", &self.reader)
            .field("state", &self.state)
            .field("map", &self.map)
            .finish()
    }
}

impl<'a> PacketHeaderParser<'a> {
    // Returns a `PacketHeaderParser` to parse an OpenPGP packet.
    // `inner` points to the start of the OpenPGP framing information,
    // i.e., the CTB.
    fn new(inner: Box<'a + BufferedReader<Cookie>>,
           state: PacketParserState,
           recursion_depth: u8, header: Header,
           header_bytes: Option<Vec<u8>>) -> Self
    {
        PacketHeaderParser {
            reader: BufferedReaderDup::with_cookie(inner, Default::default()),
            header: header,
            recursion_depth: recursion_depth,
            state: state,
            map: header_bytes.map(|h| Map::new(h)),
        }
    }

    // Returns a `PacketHeaderParser` that parses a bare packet.  That
    // is, `inner` points to the start of the packet; the OpenPGP
    // framing has already been processed, and `inner` already
    // includes any required filters (e.g., a
    // `BufferedReaderPartialBodyFilter`, etc.).
    fn new_naked(inner: Box<'a + BufferedReader<Cookie>>) -> Self {
        PacketHeaderParser::new(inner,
                                PacketParserState::new(Default::default()),
                                0,
                                Header {
                                    ctb: CTB::new(Tag::Reserved),
                                    length: BodyLength::Full(0),
                                },
                                None)
    }

    // Consumes the bytes belonging to the packet's header (i.e., the
    // number of bytes read) from the reader, and returns a
    // `PacketParser` that can be returned to the user.
    //
    // Only call this function if the packet's header has been
    // completely and correctly parsed.  If a failure occurs while
    // parsing the header, use `fail()` instead.
    fn ok(mut self, packet: Packet) -> Result<PacketParser<'a>> {
        let total_out = self.reader.total_out();

        let mut reader = if self.state.settings.map {
            // Read the body for the map.  Note that
            // `total_out` does not account for the body.
            //
            // XXX avoid the extra copy.
            let body = self.reader.steal_eof()?;
            if body.len() > 0 {
                self.field("body", body.len());
            }

            // This is a BufferedReaderDup, so this always has an
            // inner.
            let mut inner = Box::new(self.reader).into_inner().unwrap();

            // Combine the header with the body for the map.
            let mut data = Vec::with_capacity(total_out + body.len());
            // We know that the inner reader must have at least
            // `total_out` bytes buffered, otherwise we could never
            // have read that much from the `BufferedReaderDup`.
            data.extend_from_slice(&inner.buffer()[..total_out]);
            data.extend(body);
            self.map.as_mut().unwrap().finalize(data);

            inner
        } else {
            // This is a BufferedReaderDup, so this always has an
            // inner.
            Box::new(self.reader).into_inner().unwrap()
        };

        // We know the data has been read, so this cannot fail.
        reader.data_consume_hard(total_out).unwrap();

        Ok(PacketParser {
            header: self.header,
            packet: packet,
            recursion_depth: self.recursion_depth,
            reader: reader,
            content_was_read: false,
            decrypted: true,
            finished: false,
            map: self.map,
            state: self.state,
        })
    }

    // Something went wrong while parsing the packet's header.  Aborts
    // and returns an Unknown packet instead.
    fn fail(self, _reason: &'static str) -> Result<PacketParser<'a>> {
        Unknown::parse(self)
    }

    fn field(&mut self, name: &'static str, size: usize) {
        if let Some(ref mut map) = self.map {
            map.add(name, size)
        }
    }

    fn parse_u8(&mut self, name: &'static str) -> Result<u8> {
        self.field(name, 1);
        Ok(self.reader.data_consume_hard(1)?[0])
    }

    fn parse_be_u16(&mut self, name: &'static str) -> Result<u16> {
        self.field(name, 2);
        Ok(self.reader.read_be_u16()?)
    }

    fn parse_be_u32(&mut self, name: &'static str) -> Result<u32> {
        self.field(name, 4);
        Ok(self.reader.read_be_u32()?)
    }

    fn parse_bytes(&mut self, name: &'static str, amount: usize)
                   -> Result<Vec<u8>> {
        self.field(name, amount);
        Ok(self.reader.steal(amount)?)
    }

    fn parse_bytes_eof(&mut self, name: &'static str) -> Result<Vec<u8>> {
        let r = self.reader.steal_eof()?;
        self.field(name, r.len());
        Ok(r)
    }
}


/// What the hash in the Cookie is for.
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum HashesFor {
    Nothing,
    MDC,
    Signature,
}


pub(crate) struct Cookie {
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
    pub(crate) hashes: Vec<(HashAlgorithm, Box<Hash>)>,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let algos = self.hashes.iter()
            .map(|&(algo, _)| algo)
            .collect::<Vec<HashAlgorithm>>();

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
    -> Result<Box<BufferedReader<Cookie> + 'a>>
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

            reader.drop_eof()?;
            reader = reader.into_inner().unwrap();
        } else {
            break;
        }
    }

    Ok(reader)
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

    // Whether or not to create a map.
    map: bool,
}

// The default `PacketParser` settings.
impl Default for PacketParserSettings {
    fn default() -> Self {
        PacketParserSettings {
            max_recursion_depth: MAX_RECURSION_DEPTH,
            buffer_unread_content: false,
            trace: TRACE,
            map: false,
        }
    }
}

// Packet maps.

/// Map created during parsing.
///
/// If configured to do so, a `PacketParser` will create a map that
/// charts the byte-stream, describing where the information was
/// extracted from.
#[derive(Clone, Debug)]
pub struct Map {
    length: usize,
    entries: Vec<Entry>,
    header: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Entry {
    offset: usize,
    length: usize,
    field: &'static str,
}

impl Map {
    /// Creates a new map.
    fn new(header: Vec<u8>) -> Self {
        Map {
            length: 0,
            entries: Vec::new(),
            header: header,
            data: Vec::new(),
        }
    }

    /// Adds a field to the map.
    fn add(&mut self, field: &'static str, length: usize) {
        self.entries.push(Entry {
            offset: self.length, length: length, field: field
        });
        self.length += length;
    }

    /// Finalizes the map providing the actual data.
    fn finalize(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    /// Creates an iterator over the map.
    ///
    /// Items returned are a small string indicating what kind of
    /// information is extracted (e.g. "header", or "version"), and a
    /// slice containing the actual bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # use openpgp::Result;
    /// # use openpgp::parse::{PacketParser, PacketParserBuilder};
    /// # f();
    /// #
    /// # fn f() -> Result<()> {
    /// let msg = b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.";
    /// let ppo = PacketParserBuilder::from_bytes(msg)?
    ///     .map(true).finalize()?;
    /// let map = ppo.unwrap().map.unwrap();
    /// assert_eq!(map.iter().collect::<Vec<(&str, &[u8])>>(),
    ///            [("header", &b"\xcb\x12"[..]),
    ///             ("format", b"t"),
    ///             ("filename_len", b"\x00"),
    ///             ("date", b"\x00\x00\x00\x00"),
    ///             ("body", b"Hello world.")]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter<'a>(&'a self)
                    -> Box<'a + iter::Iterator<Item=(&'static str, &'a [u8])>> {
        let len = self.data.len();
        Box::new(
            iter::once(("header", self.header.as_slice()))
                .chain(self.entries.iter().map(move |e| {
                    let start = cmp::min(len, e.offset);
                    let end = cmp::min(len, e.offset + e.length);
                    (e.field, &self.data[start..end])
                })))
    }
}

// Note: this method is only used in a test in the s2k module.  This
// means that we get a warning about it being unused in !cfg(test).
// We can't add the #[cfg(test)] attribute to the method; we can only
// add it to the impl block.
#[cfg(test)]
impl S2K {
    // Reads an S2K from `r`.
    pub(crate) fn parse_naked<R: io::Read>(r: R) -> Result<Self> {
        let bio = BufferedReaderGeneric::with_cookie(
            r, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse(&mut parser)
    }
}

impl S2K {
    /// Reads an S2K from `php`.
    fn parse<'a>(php: &mut PacketHeaderParser<'a>) -> Result<Self>
    {
        let s2k = php.parse_u8("s2k_type")?;
        let ret = match s2k {
            0 => S2K::Simple {
                hash: HashAlgorithm::from(php.parse_u8("s2k_hash_algo")?),
            },
            1 => S2K::Salted {
                hash: HashAlgorithm::from(php.parse_u8("s2k_hash_algo")?),
                salt: Self::read_salt(php)?,
            },
            3 => S2K::Iterated {
                hash: HashAlgorithm::from(php.parse_u8("s2k_hash_algo")?),
                salt: Self::read_salt(php)?,
                iterations: S2K::decode_count(php.parse_u8("s2k_count")?),
            },
            100...110 => S2K::Private(s2k),
            u => S2K::Unknown(u),
        };

        Ok(ret)
    }

    fn read_salt<'a>(php: &mut PacketHeaderParser<'a>) -> Result<[u8; 8]> {
        let mut b = [0u8; 8];
        b.copy_from_slice(&php.parse_bytes("s2k_salt", 8)?);

        Ok(b)
    }
}

impl Unknown {
    /// Parses the body of any packet and returns an Unknown.
    fn parse<'a>(php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>>
    {
        let tag = php.header.ctb.tag;
        php.ok(Packet::Unknown(Unknown {
            common: Default::default(),
            tag: tag,
        })).map(|pp| pp.set_decrypted(false))
    }
}

// Read the next packet as an unknown packet.
//
// The `reader` must point to the packet's header, i.e., the CTB.
// This buffers the packet's contents.
//
// Note: we only need this function for testing purposes in a
// different module.
#[cfg(test)]
pub(crate) fn to_unknown_packet<R: Read>(reader: R) -> Result<Unknown>
{
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

    let parser = PacketHeaderParser::new(
        reader, PacketParserState::new(Default::default()), 0, header, None);
    let mut pp = Unknown::parse(parser)?;
    pp.buffer_unread_content()?;
    pp.finish()?;

    if let Packet::Unknown(packet) = pp.packet {
        Ok(packet)
    } else {
        panic!("Internal inconsistency.");
    }
}

impl Signature {
    // Parses a Signature packet without any OpenPGP framing.  That
    // is, the first byte of `value` is the Signature packet's version
    // field, not the ctb.  Also, any length encoding information has
    // been removed.
    pub(crate) fn parse_naked(value: &[u8]) -> Result<Packet> {
        let bio = BufferedReaderMemory::with_cookie(
            value, Cookie::default());
        let parser = PacketHeaderParser::new_naked(Box::new(bio));

        let mut pp = Signature::parse(parser, None)?;
        pp.buffer_unread_content()?;
        pp.finish()?;

        match pp.packet {
            Packet::Signature(_) => Ok(pp.packet),
            Packet::Unknown(_) => Ok(pp.packet),
            _ => panic!("Internal inconsistency."),
        }
    }

    // Parses a signature packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>,
                 computed_hash: Option<(HashAlgorithm, Box<Hash>)>)
        -> Result<PacketParser<'a>>
    {
        make_php_try!(php);

        let version = php_try!(php.parse_u8("version"));

        if version != 4 {
            if TRACE {
                eprintln!("{}Signature::parse: Ignoring verion {} packet.",
                          indent(php.recursion_depth as u8), version);
            }
            return php.fail("unknown version");
        }

        let sigtype = php_try!(php.parse_u8("sigtype"));
        let pk_algo: PublicKeyAlgorithm = php_try!(php.parse_u8("pk_algo")).into();
        let hash_algo = php_try!(php.parse_u8("hash_algo"));
        let hashed_area_len = php_try!(php.parse_be_u16("hashed_area_len"));
        let hashed_area
            = php_try!(php.parse_bytes("hashed_area",
                                   hashed_area_len as usize));
        let unhashed_area_len = php_try!(php.parse_be_u16("unhashed_area_len"));
        let unhashed_area
            = php_try!(php.parse_bytes("unhashed_area",
                                   unhashed_area_len as usize));
        let hash_prefix1 = php_try!(php.parse_u8("hash_prefix1"));
        let hash_prefix2 = php_try!(php.parse_u8("hash_prefix2"));
        let mpis = php_try!(MPIs::parse_signature(pk_algo, &mut php));

        let mut sig = Signature {
            common: Default::default(),
            version: version,
            sigtype: sigtype.into(),
            pk_algo: pk_algo.into(),
            hash_algo: hash_algo.into(),
            hashed_area: SubpacketArea::new(hashed_area),
            unhashed_area: SubpacketArea::new(unhashed_area),
            hash_prefix: [hash_prefix1, hash_prefix2],
            mpis: mpis,
            computed_hash: None,
        };

        if let Some((algo, mut hash)) = computed_hash {
            sig.hash(&mut hash);

            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);

            sig.computed_hash = Some((algo, digest));
        }

        php.ok(Packet::Signature(sig))
    }

    /// Returns whether the data appears to be a signature (no promises).
    fn plausible(bio: &mut BufferedReaderDup<Cookie>, header: &Header) -> Result<()> {
        // The absolute minimum size for the header is 11 bytes (this
        // doesn't include the signature MPIs).

        if let BodyLength::Full(len) = header.length {
            if len < 11 {
                // Much too short.
                return Err(
                    Error::MalformedPacket("Packet too short".into()).into());
            }
        } else {
            return Err(
                Error::MalformedPacket(
                    format!("Unexpected body length encoding: {:?}",
                            header.length)
                        .into()).into());
        }

        // Make sure we have a minimum header.
        let data = bio.data(11)?;
        if data.len() < 11 {
            return Err(
                Error::MalformedPacket("Short read".into()).into());
        }

        // Assume unknown == bad.
        let version = data[0];
        let sigtype : SignatureType = data[1].into();
        let pk_algo : PublicKeyAlgorithm = data[2].into();
        let hash_algo : HashAlgorithm = data[3].into();

        if version == 4
            && !destructures_to!(SignatureType::Unknown(_) = sigtype)
            && !destructures_to!(PublicKeyAlgorithm::Unknown(_) = pk_algo)
            && !destructures_to!(HashAlgorithm::Unknown(_) = hash_algo)
        {
            Ok(())
        } else {
            Err(Error::MalformedPacket("Invalid or unsupported data".into())
                .into())
        }
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
            assert_eq!(p.sigtype, SignatureType::Binary);
            assert_eq!(p.pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
            assert_eq!(p.hash_algo, HashAlgorithm::SHA512);
            assert_eq!(p.hashed_area.data.len(), 29);
            assert_eq!(p.unhashed_area.data.len(), 10);
            assert_eq!(p.hash_prefix, [0x65u8, 0x74]);
            assert_eq!(p.mpis.serialized_len(), 258);
        } else {
            panic!("Wrong packet!");
        }
    }
}

impl OnePassSig {
    fn parse<'a>(mut php: PacketHeaderParser<'a>)
        -> Result<PacketParser<'a>>
    {
        make_php_try!(php);

        let version = php_try!(php.parse_u8("version"));
        if version != 3 {
            if TRACE {
                eprintln!("{}OnePassSig::parse: Ignoring verion {} packet",
                          indent(php.recursion_depth as u8), version);
            }

            // Unknown version.  Return an unknown packet.
            return php.fail("unknown version");
        }

        let sigtype = php_try!(php.parse_u8("sigtype"));
        let hash_algo = php_try!(php.parse_u8("hash_algo"));
        let pk_algo = php_try!(php.parse_u8("pk_algo"));
        let mut issuer = [0u8; 8];
        issuer.copy_from_slice(&php_try!(php.parse_bytes("issuer", 8)));
        let last = php_try!(php.parse_u8("last"));

        let mut pp = php.ok(Packet::OnePassSig(OnePassSig {
            common: Default::default(),
            version: version,
            sigtype: sigtype.into(),
            hash_algo: hash_algo.into(),
            pk_algo: pk_algo.into(),
            issuer: KeyID::from_bytes(&issuer),
            last: last,
        }))?;

        // We create an empty hashed reader even if we don't support
        // the hash algorithm so that we have something to match
        // against when we get to the Signature packet.
        let mut algos = Vec::new();
        let hash_algo = HashAlgorithm::from(hash_algo);

        if hash_algo.is_supported() {
            algos.push(hash_algo);
        }

        // We can't push the HashedReader on the BufferedReader stack:
        // when we finish processing this OnePassSig packet, it will
        // be popped.  Instead, we need to insert it at the next
        // higher level.  Unfortunately, this isn't possible.  But,
        // since we're done reading the current packet, we can pop the
        // readers associated with it, and then push the HashedReader.
        // This is a bit of a layering violation, but I (Neal) can't
        // think of a more elegant solution.

        let recursion_depth = pp.recursion_depth;
        assert!(pp.reader.cookie_ref().level
                <= Some(recursion_depth as isize));
        let reader = buffered_reader_stack_pop(Box::new(pp.take_reader()),
                                               recursion_depth as isize)?;

        let mut reader = HashedReader::new(
            reader, HashesFor::Signature, algos);
        reader.cookie_mut().level = Some(recursion_depth as isize - 1);

        if TRACE {
            eprintln!("{}OnePassSig::parse: \
                       Pushed a hashed reader, level {:?}",
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

        pp.reader = Box::new(reader);

        Ok(pp)
    }
}

#[test]
fn one_pass_sig_parser_test () {
    use SignatureType;
    use PublicKeyAlgorithm;

    // This test assumes that the first packet is a OnePassSig packet.
    let data = bytes!("signed-1.gpg");
    let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
    let p = pp.finish().unwrap();
    // eprintln!("packet: {:?}", p);

    if let &Packet::OnePassSig(ref p) = p {
        assert_eq!(p.version, 3);
        assert_eq!(p.sigtype, SignatureType::Binary);
        assert_eq!(p.hash_algo, HashAlgorithm::SHA512);
        assert_eq!(p.pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(p.issuer.to_hex(), "7223B56678E02528");
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
        let mut ppr = PacketParserBuilder::from_file(path_to(test.filename))
            .expect(&format!("Reading {}", test.filename)[..])
            .finalize().unwrap();

        let mut one_pass_sigs = 0;
        let mut sigs = 0;

        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::OnePassSig(_) = pp.packet {
                one_pass_sigs += 1;
            } else if let Packet::Signature(ref sig) = pp.packet {
                eprintln!("  {}:\n  prefix: expected: {}, in sig: {}",
                          test.filename,
                          ::conversions::to_hex(&test.hash_prefix[sigs][..], false),
                          ::conversions::to_hex(&sig.hash_prefix[..], false));
                eprintln!("  computed hash: {}",
                          ::conversions::to_hex(&sig.computed_hash.as_ref().unwrap().1, false));

                assert_eq!(test.hash_prefix[sigs], sig.hash_prefix);
                assert_eq!(&test.hash_prefix[sigs][..],
                           &sig.computed_hash.as_ref().unwrap().1[..2]);

                sigs += 1;
            } else if one_pass_sigs > 0 {
                assert_eq!(one_pass_sigs, test.hash_prefix.len(),
                           "Number of OnePassSig packets does not match \
                            number of expected OnePassSig packets.");
            }

            let (_, _, tmp, _) = pp.recurse().expect("Parsing message");
            ppr = tmp;
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
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        use std::io::Cursor;
        use serialize::Serialize;

        make_php_try!(php);
        let tag = php.header.ctb.tag;
        assert!(tag == Tag::PublicKey
                || tag == Tag::PublicSubkey
                || tag == Tag::SecretKey
                || tag == Tag::SecretSubkey);
        let version = php_try!(php.parse_u8("version"));
        if version != 4 {
            // We only support version 4 keys.
            return php.fail("unknown version");
        }

        let creation_time = php_try!(php.parse_be_u32("creation_time"));
        let pk_algo: PublicKeyAlgorithm = php_try!(php.parse_u8("pk_algo")).into();
        let mpis = php_try!(MPIs::parse_public_key(pk_algo, &mut php));
        let secret = if tag == Tag::SecretKey || tag == Tag::SecretSubkey {
            let s2k_usage = php_try!(php.parse_u8("s2k_usage"));
            let sec = match s2k_usage {
                // Unencrypted
                0 => {
                    let sec = php_try!(MPIs::parse_secret_key(pk_algo, &mut php));
                    let their_chksum = php_try!(php.parse_be_u16("checksum"));
                    let mut cur = Cursor::new(Vec::default());

                    sec.serialize(&mut cur)?;
                    let our_chksum: usize = cur.into_inner()
                        .into_iter().map(|x| x as usize).sum();

                    if our_chksum as u16 & 0xffff != their_chksum {
                        return php.fail("wrong secret key checksum");
                    }

                    SecretKey::Unencrypted{ mpis: sec }
                }
                // Encrypted & MD5 for key derivation: unsupported
                1...253 => {
                    return php.fail("unsupported secret key encryption");
                }
                // Encrypted, S2K & SHA-1 checksum
                254 => {
                    let sk: SymmetricAlgorithm = php_try!(php.parse_u8("symm_algo")).into();
                    let s2k = php_try!(S2K::parse(&mut php));
                    let mut cipher = php_try!(php.parse_bytes_eof("encrypted_mpis"));

                    SecretKey::Encrypted{
                        s2k: s2k,
                        algorithm: sk,
                        ciphertext: cipher.into_boxed_slice(),
                    }
                }
                // Encrypted, S2K & mod 65536 checksum: unsupported
                255 => {
                    return php.fail("unsupported secret key encryption");
                }
                 _ => unreachable!()
            };

            Some(sec)
        } else if tag == Tag::PublicKey || tag == Tag::PublicSubkey {
            None
        } else {
            unimplemented!()
        };

        let key = Key {
            common: Default::default(),
            version: version,
            creation_time: time::Tm::from_pgp(creation_time),
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        };

        let tag = php.header.ctb.tag;
        php.ok(match tag {
            Tag::PublicKey => Packet::PublicKey(key),
            Tag::PublicSubkey => Packet::PublicSubkey(key),
            Tag::SecretKey => Packet::SecretKey(key),
            Tag::SecretSubkey => Packet::SecretSubkey(key),
            _ => unreachable!(),
        })
    }

    /// Returns whether the data appears to be a key (no promises).
    fn plausible(bio: &mut BufferedReaderDup<Cookie>, header: &Header) -> Result<()> {
        // The packet's header is 6 bytes.
        if let BodyLength::Full(len) = header.length {
            if len < 6 {
                // Much too short.
                return Err(Error::MalformedPacket(
                    format!("Packet too short ({} bytes)", len).into()).into());
            }
        } else {
            return Err(
                Error::MalformedPacket(
                    format!("Unexpected body length encoding: {:?}",
                            header.length)
                        .into()).into());
        }

        // Make sure we have a minimum header.
        let data = bio.data(6)?;
        if data.len() < 6 {
            return Err(
                Error::MalformedPacket("Short read".into()).into());
        }

        // Assume unknown == bad.
        let version = data[0];
        let pk_algo : PublicKeyAlgorithm = data[5].into();

        if version == 4
            && !destructures_to!(PublicKeyAlgorithm::Unknown(_) = pk_algo)
        {
            Ok(())
        } else {
            Err(Error::MalformedPacket("Invalid or unsupported data".into())
                .into())
        }
    }
}

impl UserID {
    /// Parses the body of a user id packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);

        let value = php_try!(php.parse_bytes_eof("value"));

        php.ok(Packet::UserID(UserID {
            common: Default::default(),
            value: value,
        }))
    }
}

impl UserAttribute {
    /// Parses the body of a user attribute packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);

        let value = php_try!(php.parse_bytes_eof("value"));

        php.ok(Packet::UserAttribute(UserAttribute {
            common: Default::default(),
            value: value,
        }))
    }
}

impl Literal {
    /// Parses the body of a literal packet.
    ///
    /// Condition: Hashing has been disabled by the callee.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>>
    {
        make_php_try!(php);

        // Directly hashing a literal data packet is... strange.
        // Neither the packet's header, the packet's meta-data nor the
        // length encoding information is included in the hash.

        let format = php_try!(php.parse_u8("format"));
        let filename_len = php_try!(php.parse_u8("filename_len"));

        let filename = if filename_len > 0 {
            Some(php_try!(php.parse_bytes("filename", filename_len as usize)))
        } else {
            None
        };

        let date = php_try!(php.parse_be_u32("date"));

        // The header is consumed while hashing is disabled.
        let recursion_depth = php.recursion_depth;
        let mut pp = php.ok(Packet::Literal(Literal {
            common: Default::default(),
            format: format.into(),
            filename: filename,
            date: time::Tm::from_pgp(date),
        }))?;

        // Enable hashing of the body.
        Cookie::hashing(pp.mut_reader(), true, recursion_depth as isize - 1);

        Ok(pp)
    }
}

#[test]
fn literal_parser_test () {
    use constants::DataFormat;
    {
        let data = bytes!("literal-mode-b.gpg");
        let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Full(18));
        let content = pp.steal_eof().unwrap();
        let p = pp.finish().unwrap();
        // eprintln!("{:?}", p);
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format, DataFormat::Binary);
            assert_eq!(p.filename.as_ref().unwrap()[..], b"foobar"[..]);
            assert_eq!(p.date, time::Tm::from_pgp(1507458744));
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
        let p = pp.finish().unwrap();
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format, DataFormat::Text);
            assert_eq!(p.filename.as_ref().unwrap()[..],
                       b"manifesto.txt"[..]);
            assert_eq!(p.date, time::Tm::from_pgp(1508000649));

            let expected = bytes!("a-cypherpunks-manifesto.txt");

            assert_eq!(&content[..], &expected[..]);
        } else {
            panic!("Wrong packet!");
        }
    }
}

impl CompressedData {
    /// Parses the body of a compressed data packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let algo: CompressionAlgorithm =
            php_try!(php.parse_u8("algo")).into();

        if TRACE {
            eprintln!("CompressedData::parse(): \
                       Adding decompressor, recursion depth = {:?}.",
                      php.recursion_depth);
        }

        #[allow(unreachable_patterns)]
        match algo {
            CompressionAlgorithm::Uncompressed => (),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip
                | CompressionAlgorithm::Zlib => (),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 => (),
            CompressionAlgorithm::Unknown(_)
            | CompressionAlgorithm::Private(_) =>
                return php.fail("unknown compression algorithm"),
            _ =>
                return php.fail("unsupported compression algorithm"),
        }

        let recursion_depth = php.recursion_depth as usize;
        let mut pp = php.ok(Packet::CompressedData(CompressedData {
            common: Default::default(),
            algo: algo,
        }))?;

        let reader = pp.take_reader();
        let reader = match algo {
            CompressionAlgorithm::Uncompressed => {
                if TRACE {
                    eprintln!("CompressedData::parse(): Actually, no need \
                               for a compression filter: this is an \
                               \"uncompressed compression packet\".");
                }
                let _ = recursion_depth;
                reader
            },
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip =>
                Box::new(BufferedReaderDeflate::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zlib =>
                Box::new(BufferedReaderZlib::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 =>
                Box::new(BufferedReaderBzip::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            _ => unreachable!(), // Validated above.
        };
        pp.set_reader(reader);

        Ok(pp)
    }
}

#[cfg(any(feature = "compression-deflate", feature = "compression-bzip2"))]
#[test]
fn compressed_data_parser_test () {
    use constants::DataFormat;

    let expected = bytes!("a-cypherpunks-manifesto.txt");

    for i in 1..4 {
        match CompressionAlgorithm::from(i) {
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip | CompressionAlgorithm::Zlib => (),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 => (),
            _ => continue,
        }
        let path = path_to(&format!("compressed-data-algo-{}.gpg", i)[..]);
        let mut pp = PacketParser::from_file(path).unwrap().unwrap();

        // We expect a compressed packet containing a literal data
        // packet, and that is it.
        if let Packet::CompressedData(ref compressed) = pp.packet {
            assert_eq!(compressed.algo, i.into());
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
            assert_eq!(literal.format, DataFormat::Binary);
            assert_eq!(literal.date, time::Tm::from_pgp(1509219866));
            assert_eq!(content, expected.to_vec());
        } else {
            panic!("Wrong packet!");
        }

        // And, we're done...
        assert!(ppo.is_none());
    }
}

impl SKESK {
    /// Parses the body of an SK-ESK packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        if version != 4 {
            // We only support version 4 keys.
            return php.fail("unknown version");
        }

        let symm_algo = php_try!(php.parse_u8("symm_algo"));
        let s2k = php_try!(S2K::parse(&mut php));
        let esk = php_try!(php.parse_bytes_eof("esk"));

        php.ok(Packet::SKESK(SKESK {
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
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        if version != 1 {
            return php.fail("unknown version");
        }

        php.ok(Packet::SEIP(SEIP {
            common: Default::default(),
            version: version,
        })).map(|pp| pp.set_decrypted(false))
    }
}

impl MDC {
    /// Parses the body of an MDC packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);

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
                = Some(&mut php.reader);
            while let Some(bio) = r {
                {
                    let state = bio.cookie_mut();
                    if state.hashes_for == HashesFor::MDC {
                        if state.hashes.len() > 0 {
                            let (a, mut h) = state.hashes.pop().unwrap();
                            assert_eq!(a, HashAlgorithm::SHA1);
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
        hash.copy_from_slice(&php_try!(php.parse_bytes("hash", 20)));

        php.ok(Packet::MDC(MDC {
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
        cipher_algo: SymmetricAlgorithm,
        password: &'a [u8],
        key_hex: &'a str,
    };

    let tests = [
            Test {
                filename: "s2k/mode-3-encrypted-key-password-bgtyhn.gpg",
                cipher_algo: SymmetricAlgorithm::AES128,
                s2k: S2K::Iterated {
                    hash: HashAlgorithm::SHA1,
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
                    let key = ::conversions::to_hex(&key[..], false);
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

impl MPI {
    // Reads an MPI from `r`.
    #[cfg(test)]
    pub(crate) fn parse_naked<R: io::Read>(r: R) -> Result<Self> {
        let bio = BufferedReaderGeneric::with_cookie(
            r, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse("(none)", &mut parser)
    }
}

impl MPI {
    /// Parses an OpenPGP MPI.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    fn parse<'a>(name: &'static str, php: &mut PacketHeaderParser<'a>) -> Result<Self> {
        let bits = php.parse_be_u16("mpi_len")? as usize;
        if bits == 0 {
            return Ok(MPI{ bits: 0, value: vec![].into_boxed_slice()});
        }

        let bytes = (bits + 7) / 8;
        let value = Vec::from(&php.parse_bytes(name, bytes)?[..bytes]);

        if TRACE {
            eprintln!("bits: {}, value: {}",
                      bits, ::conversions::to_hex(&value, true));
        }

        let unused_bits = bytes * 8 - bits;
        assert_eq!(bytes * 8 - unused_bits, bits);

        if TRACE {
            eprintln!("unused bits: {}", unused_bits);
        }

        // Make sure the unused bits are zeroed.
        if unused_bits > 0 {
            let mask = !((1 << (8 - unused_bits)) - 1);
            let unused_value = value[0] & mask;

            if TRACE {
                eprintln!("mask: {:08b} & first byte: {:08b} \
                               = unused value: {:08b}",
                               mask, value[0], unused_value);
            }

            if unused_value != 0 {
                return Err(Error::MalformedMPI(
                        format!("{} unused bits not zeroed: ({:x})",
                        unused_bits, unused_value)).into());
            }
        }

        let first_used_bit = 8 - unused_bits;
        if value[0] & (1 << (first_used_bit - 1)) == 0 {
            return Err(Error::MalformedMPI(
                    format!("leading bit is not set: \
                             expected bit {} to be set in {:8b} ({:x})",
                             first_used_bit, value[0], value[0])).into());
        }

        Ok(MPI{
            bits: bits,
            value: value.into_boxed_slice()
        })
    }

    /// Dissects this MPI describing a point into the individual
    /// coordinates.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedEllipticCurve` if the curve is not
    /// supported, `Error::InvalidArgument` if the point is
    /// formatted incorrectly.
    pub fn decode_point(&self, curve: &Curve) -> Result<(&[u8], &[u8])> {
        use nettle::{ed25519, curve25519};
        use self::Curve::*;
        match &curve {
            Ed25519 | Cv25519 => {
                assert_eq!(curve25519::CURVE25519_SIZE,
                           ed25519::ED25519_KEY_SIZE);
                // This curve uses a custom compression format which
                // only contains the X coordinate.
                if self.value.len() != 1 + curve25519::CURVE25519_SIZE {
                    return Err(Error::MalformedPacket(
                        format!("Bad size of Curve25519 key: {} expected: {}",
                                self.value.len(),
                                1 + curve25519::CURVE25519_SIZE)).into());
                }

                if self.value[0] != 0x40 {
                    return Err(Error::MalformedPacket(
                        "Bad encoding of Curve25519 key".into()).into());
                }

                Ok((&self.value[1..], &[]))
            },

            _ => {

                // Length of one coordinate in bytes, rounded up.
                let coordinate_length = (curve.len()? + 7) / 8;

                // Check length of Q.
                let expected_length =
                    1 // 0x04.
                    + (2 // (x, y)
                       * coordinate_length);

                if self.value.len() != expected_length {
                    return Err(Error::InvalidArgument(
                        format!("Invalid length of MPI: {} (expected {})",
                                self.value.len(), expected_length)).into());
                }

                if self.value[0] != 0x04 {
                    return Err(Error::InvalidArgument(
                        format!("Bad prefix: {:x} (expected 0x04)", self.value[0]))
                               .into());
                }

                Ok((&self.value[1..1 + coordinate_length],
                    &self.value[1 + coordinate_length..]))
            },
        }
    }
}

impl PKESK {
    /// Parses the body of an PK-ESK packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        if version != 3 {
            // We only support version 3 packets.
            return php.fail("unknown version");
        }

        let mut keyid = [0u8; 8];
        keyid.copy_from_slice(&php_try!(php.parse_bytes("keyid", 8)));
        let pk_algo: PublicKeyAlgorithm = php_try!(php.parse_u8("pk_algo")).into();
        let mpis = MPIs::parse_ciphertext(pk_algo, &mut php)?;

        php.ok(Packet::PKESK(PKESK {
            common: Default::default(),
            version: version,
            pk_algo: pk_algo,
            recipient: KeyID::from_bytes(&keyid),
            esk: mpis,
        }))
    }
}

// State that lives for the life of the packet parser, not the life of
// an individual packet.
#[derive(Debug)]
struct PacketParserState {
    // The `PacketParser`'s settings
    settings: PacketParserSettings,

    /// Whether the packet sequence is a valid OpenPGP Message.
    message_validator: MessageValidator,
}

impl PacketParserState {
    fn new(settings: PacketParserSettings) -> Self {
        PacketParserState {
            settings: settings,
            message_validator: Default::default(),
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
///   [`Packet`]: ../enum.Packet.html
///
/// # Examples
///
/// Parse an OpenPGP message using a `PacketParser`:
///
/// ```rust
/// # use openpgp::Result;
/// # use openpgp::Packet;
/// # use openpgp::parse::{PacketParserResult, PacketParser};
/// # let _ = f(include_bytes!("../../tests/data/messages/public-key.gpg"));
/// #
/// # fn f(message_data: &[u8]) -> Result<()> {
/// let mut ppr = PacketParser::from_bytes(message_data)?;
/// while let PacketParserResult::Some(mut pp) = ppr {
///     // Process the packet.
///
///     if let Packet::Literal(_) = pp.packet {
///         // Stream the content of any literal packets to stdout.
///         std::io::copy(&mut pp, &mut std::io::stdout());
///     }
///
///     // Get the next packet.
///     let (_packet, _packet_depth, tmp, _pp_depth) = pp.recurse()?;
///     ppr = tmp;
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

    reader: Box<BufferedReader<Cookie> + 'a>,

    // Whether the caller read the packet's content.  If so, then we
    // can't recurse, because we're missing some of the packet!
    content_was_read: bool,

    // Whether PacketParser::finish has been called.
    finished: bool,

    // Whether the content has been decrypted.
    decrypted: bool,

    /// A map of this packet.
    pub map: Option<Map>,

    state: PacketParserState,
}

impl <'a> std::fmt::Debug for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketParser")
            .field("header", &self.header)
            .field("packet", &self.packet)
            .field("recursion_depth", &self.recursion_depth)
            .field("decrypted", &self.decrypted)
            .field("content_was_read", &self.content_was_read)
            .field("settings", &self.state.settings)
            .field("map", &self.map)
            .finish()
    }
}

/// The return value of PacketParser::parse.
enum ParserResult<'a> {
    Success(PacketParser<'a>),
    EOF((Box<BufferedReader<Cookie> + 'a>, PacketParserState)),
}

/// Information about the stream of packets parsed by the
/// `PacketParser`.
#[derive(Debug)]
pub struct PacketParserEOF {
    state: PacketParserState,
}

impl PacketParserEOF {
    /// Copies the important information in `pp` into a new
    /// `PacketParserEOF` instance.
    fn new(mut state: PacketParserState) -> Self {
        state.message_validator.finish();

        PacketParserEOF {
            state: state,
        }
    }

    /// Whether the message is an OpenPGP Message.
    ///
    /// As opposed to a TPK or just a bunch of packets.
    pub fn is_message(&self) -> bool {
        self.state.message_validator.is_message()
    }
}

/// The return type of `PacketParser::next`() and
/// `PacketParser::recurse`().
///
/// We don't use an `Option`, because when we reach the end of the
/// packet sequence, some information about the message needs to
/// remain accessible.
#[derive(Debug)]
pub enum PacketParserResult<'a> {
    /// A `PacketParser` for the next packet.
    Some(PacketParser<'a>),
    /// Information about a fully parsed packet sequence.
    EOF(PacketParserEOF),
}

impl<'a> PacketParserResult<'a> {
    /// Like `Option::is_none`().
    pub fn is_none(&self) -> bool {
        if let PacketParserResult::EOF(_) = self {
            true
        } else {
            false
        }
    }

    /// An alias for `is_none`().
    pub fn is_eof(&self) -> bool {
        Self::is_none(self)
    }

    /// Like `Option::is_some`().
    pub fn is_some(&self) -> bool {
        ! Self::is_none(self)
    }

    /// Like `Option::expect`().
    pub fn expect(self, msg: &str) -> PacketParser<'a> {
        if let PacketParserResult::Some(pp) = self {
            return pp;
        } else {
            panic!("{}", msg);
        }
    }

    /// Like `Option::unwrap`().
    pub fn unwrap(self) -> PacketParser<'a> {
        self.expect("called `PacketParserResult::unwrap()` on a \
                     `PacketParserResult::PacketParserEOF` value")
    }

    /// Like `Option::as_ref`().
    pub fn as_ref(&self) -> Option<&PacketParser<'a>> {
        if let PacketParserResult::Some(ref pp) = self {
            Some(pp)
        } else {
            None
        }
    }

    /// Like `Option::as_mut`().
    pub fn as_mut(&mut self) -> Option<&mut PacketParser<'a>> {
        if let PacketParserResult::Some(ref mut pp) = self {
            Some(pp)
        } else {
            None
        }
    }

    /// Like `Option::take`().
    ///
    /// `self` is replaced with a `PacketParserEOF` with default
    /// values.
    pub fn take(&mut self) -> Self {
        mem::replace(
            self,
            PacketParserResult::EOF(
                PacketParserEOF::new(
                    PacketParserState::new(Default::default()))))
    }

    /// Like `Option::map`().
    pub fn map<U, F>(self, f: F) -> Option<U>
        where F: FnOnce(PacketParser<'a>) -> U
    {
        match self {
            PacketParserResult::Some(x) => Some(f(x)),
            PacketParserResult::EOF(_) => None,
        }
    }
}

impl <'a> PacketParser<'a> {
    /// Starts parsing an OpenPGP message stored in a `BufferedReader`
    /// object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub(crate) fn from_buffered_reader(bio: Box<BufferedReader<Cookie> + 'a>)
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_buffered_reader(bio)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a `std::io::Read` object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_reader<R: io::Read + 'a>(reader: R)
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_reader(reader)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a file named `path`.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_file(path)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a buffer.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_bytes(bytes)?.finalize()
    }

    /// Returns the reader stack, replacing it with a
    /// `BufferedReaderEOF` reader.
    ///
    /// This function may only be called when the `PacketParser` is in
    /// State::Body.
    fn take_reader(&mut self) -> Box<BufferedReader<Cookie> + 'a> {
        self.set_reader(
            Box::new(BufferedReaderEOF::with_cookie(Default::default())))
    }

    /// Replaces the reader stack.
    ///
    /// This function may only be called when the `PacketParser` is in
    /// State::Body.
    fn set_reader(&mut self, reader: Box<BufferedReader<Cookie> + 'a>)
        -> Box<BufferedReader<Cookie> + 'a>
    {
        mem::replace(&mut self.reader, reader)
    }

    /// Returns a mutable reference to the reader stack.
    fn mut_reader(&mut self) -> &mut BufferedReader<Cookie> {
        &mut self.reader
    }

    /// Marks the packet's contents (packet.common.body) as being
    /// decrypted (true) or encrypted (false).
    fn set_decrypted(mut self, v: bool) -> Self {
        self.decrypted = v;
        self
    }

    /// Returns whether the packet's contents (packet.common.body) are
    /// decrypted.
    pub fn decrypted(&self) -> bool {
        self.decrypted
    }

    /// Returns whether the message appears to be an OpenPGP Message.
    ///
    /// Only when the whole message has been processed is it possible
    /// to say whether the message is definitely an OpenPGP Message.
    /// Before that, it is only possible to say that the message is a
    /// valid prefix or definitely not an OpenPGP message.
    pub fn possible_message(&self) -> bool {
        self.state.message_validator.check().is_message_prefix()
    }

    /// Returns Ok if the data appears to be a legal packet.
    ///
    /// This is just a heuristic.  It can be used for recovering from
    /// garbage.
    ///
    /// Successfully reading the header only means that the top bit of
    /// the ptag is 1.  Assuming a uniform distribution, there's a 50%
    /// chance that that is the case.
    ///
    /// To improve our chances of a correct recovery, we make sure the
    /// tag is known (for new format CTBs, there are 64 possible tags,
    /// but only a third of them are reasonable; for old format
    /// packets, there are only 16 and nearly all are plausible), and
    /// we make sure the packet contents are reasonable.
    ///
    /// Currently, we only try to recover the most interesting
    /// packets.
    fn plausible(mut bio: &mut BufferedReaderDup<Cookie>, header: &Header) -> Result<()> {
        let bad = Err(
            Error::MalformedPacket("Can't make an educated case".into()).into());

        match header.ctb.tag {
            Tag::Reserved | Tag::Marker
            | Tag::Unknown(_) | Tag::Private(_) =>
                Err(Error::MalformedPacket("Looks like garbage".into()).into()),

            Tag::Signature => Signature::plausible(&mut bio, &header),

            Tag::SecretKey => Key::plausible(&mut bio, &header),
            Tag::PublicKey => Key::plausible(&mut bio, &header),
            Tag::SecretSubkey => Key::plausible(&mut bio, &header),
            Tag::PublicSubkey => Key::plausible(&mut bio, &header),

            Tag::UserID => bad,
            Tag::UserAttribute => bad,

            // It is reasonable to try and ignore garbage in TPKs,
            // because who knows what the keyservers return, etc.
            // But, if we have what appears to be an OpenPGP message,
            // then, ignore.
            Tag::PKESK => bad,
            Tag::SKESK => bad,
            Tag::OnePassSig => bad,
            Tag::CompressedData => bad,
            Tag::SED => bad,
            Tag::Literal => bad,
            Tag::Trust => bad,
            Tag::SEIP => bad,
            Tag::MDC => bad,
        }
    }

    /// Returns a `PacketParser` for the next OpenPGP packet in the
    /// stream.  If there are no packets left, this function returns
    /// `bio`.
    fn parse(mut bio: Box<BufferedReader<Cookie> + 'a>,
             state: PacketParserState,
             recursion_depth: usize)
            -> Result<ParserResult<'a>> {
        let trace = state.settings.trace;

        // When header encounters an EOF, it returns an error.  But,
        // we want to return None.  Try a one byte read.
        if bio.data(1)?.len() == 0 {
            if trace {
                eprintln!("{}PacketParser::parse(depth: {}) -> EOF.",
                          indent(recursion_depth as u8),
                          recursion_depth);
            }
            return Ok(ParserResult::EOF((bio, state)));
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

        let mut bio = BufferedReaderDup::with_cookie(bio, Cookie::default());
        let header;

        // Read the header.
        let mut skip = 0;
        let mut orig_error : Option<failure::Error> = None;
        loop {
            bio.rewind();
            bio.data_consume_hard(skip)?;

            match Header::parse(&mut bio) {
                Ok(header_) => {
                    if skip == 0 {
                        header = header_;
                        break;
                    }

                    match Self::plausible(&mut bio, &header_) {
                        Ok(()) => {
                            header = header_;
                            break;
                        }
                        Err(_err) => (),
                    }
                }
                Err(err) => {
                    if orig_error.is_none() {
                        orig_error = Some(err.into());
                    }

                    if skip > 32 * 1024 {
                        // Limit the search space.  This should be
                        // enough to find a reasonable recovery point
                        // in a TPK.
                        return Err(orig_error.unwrap());
                    }
                }
            }

            skip = skip + 1;
        }
        if skip > 0 {
            // XXX: We have no way to return this diagnosis.
            eprintln!("Skipped {} bytes of garbage.", skip);
        }
        let tag = header.ctb.tag;

        let mut computed_hash = None;
        if tag == Tag::Signature {
            // Ok, the next packet is a Signature packet.  Get the
            // nearest, valid OneSigPass packet.
            if trace {
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
                        if let Some((algo, hash)) = cookie.hashes.pop() {
                            if trace {
                                eprintln!("{}PacketParser::parse(): \
                                           popped a {:?} HashedReader",
                                          indent(recursion_depth as u8), algo);
                            }
                            cookie.hashes_for = HashesFor::Nothing;
                            computed_hash = Some((algo, hash));
                        }
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
        // A BufferedReaderDup always has an inner.
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

        // Save header for the map.
        let header_bytes = if state.settings.map {
            Some(Vec::from(&bio.data_consume_hard(consumed)?[..consumed]))
        } else {
            // Or not.
            bio.consume(consumed);
            None
        };

        let bio : Box<BufferedReader<Cookie>>
            = match header.length {
                BodyLength::Full(len) => {
                    if trace {
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
                    if trace {
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
                    if trace {
                        eprintln!("{}PacketParser::parse(): Indeterminate \
                                   length packet, not adding a limitor.",
                                  indent(recursion_depth as u8));
                    }
                    bio
                },
        };


        let tag = header.ctb.tag;
        let parser = PacketHeaderParser::new(bio, state,
                                             recursion_depth as u8,
                                             header, header_bytes);

        let mut result = match tag {
            Tag::Signature =>           Signature::parse(parser, computed_hash),
            Tag::OnePassSig =>          OnePassSig::parse(parser),
            Tag::PublicSubkey =>        Key::parse(parser),
            Tag::PublicKey =>           Key::parse(parser),
            Tag::SecretKey =>           Key::parse(parser),
            Tag::SecretSubkey =>        Key::parse(parser),
            Tag::UserID =>              UserID::parse(parser),
            Tag::UserAttribute =>       UserAttribute::parse(parser),
            Tag::Literal =>             Literal::parse(parser),
            Tag::CompressedData =>      CompressedData::parse(parser),
            Tag::SKESK =>               SKESK::parse(parser),
            Tag::SEIP =>                SEIP::parse(parser),
            Tag::MDC =>                 MDC::parse(parser),
            Tag::PKESK =>               PKESK::parse(parser),
            _ =>                        Unknown::parse(parser),
        }?;

        if tag == Tag::OnePassSig {
            Cookie::hashing(
                &mut result, true, recursion_depth as isize - 1);
        }

        if trace {
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
    ///   [`PacketParsererBuilder`]: struct.PacketParserBuilder.html
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
        -> Result<(Packet, isize, PacketParserResult<'a>, isize)>
    {
        let trace = self.state.settings.trace;

        if trace {
            eprintln!("{}PacketParser::next({:?}, depth: {}, level: {:?}).",
                      indent(self.recursion_depth),
                      self.packet.tag(), self.recursion_depth,
                      self.cookie_ref().level);
        }

        let orig_depth = self.recursion_depth as usize;

        self.finish()?;
        let mut reader = buffered_reader_stack_pop(
            mem::replace(&mut self.reader,
                         Box::new(BufferedReaderEOF::with_cookie(
                             Default::default()))),
            self.recursion_depth as isize)?;

        // Now read the next packet.
        loop {
            // Parse the next packet.
            let ppr = PacketParser::parse(reader, self.state,
                                          self.recursion_depth as usize)?;
            match ppr {
                ParserResult::EOF((reader_, state_)) => {
                    // We got EOF on the current container.  The
                    // container at recursion depth n is empty.  Pop
                    // it and any filters for it, i.e., those at level
                    // n (e.g., the limitor that caused us to hit
                    // EOF), and then try again.

                    if trace {
                        eprintln!("{}PacketParser::next(): \
                                   Got EOF trying to read the next packet, \
                                   popping container at depth {}.",
                                  indent(self.recursion_depth),
                                  self.recursion_depth);
                    }

                    if self.recursion_depth == 0 {
                        if trace {
                            eprintln!("{}PacketParser::next(): \
                                       Popped top-level container, done \
                                       reading message.",
                                      indent(self.recursion_depth));
                        }
                        let eof = PacketParserResult::EOF(
                            PacketParserEOF::new(state_));
                        return Ok((self.packet, orig_depth as isize, eof, 0));
                    } else {
                        self.recursion_depth -= 1;
                        self.state = state_;
                        self.finish()?;
                        // XXX self.content_was_read = false;
                        reader = buffered_reader_stack_pop(
                            reader_, self.recursion_depth as isize)?;
                    }
                },
                ParserResult::Success(mut pp) => {
                    pp.state.message_validator.push(
                        pp.packet.tag(), self.recursion_depth as usize);
                    return Ok((self.packet,
                               orig_depth as isize,
                               PacketParserResult::Some(pp),
                               self.recursion_depth as isize));
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
        -> Result<(Packet, isize, PacketParserResult<'a>, isize)>
    {
        let trace = self.state.settings.trace;

        if trace {
            eprintln!("{}PacketParser::recurse({:?}, depth: {}, level: {:?})",
                      indent(self.recursion_depth),
                      self.packet.tag(), self.recursion_depth,
                      self.cookie_ref().level);
        }

        match self.packet {
            // Packets that recurse.
            Packet::CompressedData(_) | Packet::SEIP(_) if self.decrypted => {
                if self.recursion_depth
                    >= self.state.settings.max_recursion_depth {
                    if trace {
                        eprintln!("{}PacketParser::recurse(): Not recursing \
                                   into the {:?} packet, maximum recursion \
                                   depth ({}) reached.",
                                  indent(self.recursion_depth), self.packet.tag(),
                                  self.state.settings.max_recursion_depth);
                    }

                    // Drop through.
                } else if self.content_was_read {
                    if trace {
                        eprintln!("{}PacketParser::recurse(): Not recursing \
                                   into the {:?} packet, some data was \
                                   already read.",
                                  indent(self.recursion_depth), self.packet.tag());
                    }

                    // Drop through.
                } else {
                    match PacketParser::parse(self.reader, self.state,
                                              self.recursion_depth
                                              as usize + 1)? {
                        ParserResult::Success(mut pp) => {
                            if trace {
                                eprintln!("{}PacketParser::recurse(): \
                                           Recursed into the {:?} \
                                           packet, got a {:?}.",
                                          indent(self.recursion_depth + 1),
                                          self.packet.tag(),
                                          pp.packet.tag());
                            }

                            pp.state.message_validator.push(
                                pp.packet.tag(),
                                self.recursion_depth as usize + 1);

                            return Ok((self.packet,
                                       self.recursion_depth as isize,
                                       PacketParserResult::Some(pp),
                                       self.recursion_depth as isize + 1));
                        },
                        ParserResult::EOF(_) => {
                            return Err(Error::MalformedPacket(
                                "Container is truncated".into()).into());
                        },
                    }
                }
            },
            // decrypted should always be true.
            Packet::CompressedData(_) => unreachable!(),
            // Packets that don't recurse.
            Packet::Unknown(_) | Packet::Signature(_) | Packet::OnePassSig(_)
                | Packet::PublicKey(_) | Packet::PublicSubkey(_)
                | Packet::SecretKey(_) | Packet::SecretSubkey(_)
                | Packet::UserID(_) | Packet::UserAttribute(_)
                | Packet::Literal(_) | Packet::PKESK(_) | Packet::SKESK(_)
                | Packet::SEIP(_) | Packet::MDC(_) => {
                // Drop through.
                if trace {
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
    /// # use openpgp::parse::{PacketParserResult, PacketParser};
    /// # use std::string::String;
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8]) -> Result<()> {
    /// let mut ppr = PacketParser::from_bytes(message_data)?;
    /// while let PacketParserResult::Some(mut pp) = ppr {
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
    ///     ppr = tmp;
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
    pub fn finish<'b>(&'b mut self) -> Result<&'b Packet> {
        let trace = self.state.settings.trace;

        if self.finished {
            return Ok(&mut self.packet);
        }

        let recursion_depth = self.recursion_depth;

        let unread_content = if self.state.settings.buffer_unread_content {
            if trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           buffering {} bytes of unread content",
                          indent(recursion_depth), self.packet.tag(),
                          recursion_depth,
                          self.data_eof().unwrap().len());
            }

            self.buffer_unread_content()?.len() > 0
        } else {
            if trace {
                eprintln!("{}PacketParser::finish({:?} at depth {}): \
                           dropping {} bytes of unread content",
                          indent(recursion_depth), self.packet.tag(),
                          recursion_depth,
                          self.data_eof().unwrap().len());
            }

            self.drop_eof()?
        };

        if unread_content {
            match self.packet.tag() {
                Tag::SEIP | Tag::SED | Tag::CompressedData => {
                    // We didn't (full) process a container's content.  Add
                    // this as opaque conent to the message validator.
                    self.state.message_validator.push_token(
                        message::Token::OpaqueContent,
                        recursion_depth as usize + 1);
                }
                _ => {},
            }
        }

        self.finished = true;

        Ok(&mut self.packet)
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
        self.reader.buffer()
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        self.reader.data(amount)
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        self.reader.data_hard(amount)
    }

    fn data_eof(&mut self) -> io::Result<&[u8]> {
        // There is no need to set `content_was_read`, because this
        // doesn't actually consume any data.
        self.reader.data_eof()
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        self.content_was_read |= amount > 0;
        self.reader.consume(amount)
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.content_was_read |= amount > 0;
        self.reader.data_consume(amount)
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.content_was_read |= amount > 0;
        self.reader.data_consume_hard(amount)
    }

    fn read_be_u16(&mut self) -> io::Result<u16> {
        self.content_was_read = true;
        self.reader.read_be_u16()
    }

    fn read_be_u32(&mut self) -> io::Result<u32> {
        self.content_was_read = true;
        self.reader.read_be_u32()
    }

    fn steal(&mut self, amount: usize) -> io::Result<Vec<u8>> {
        self.content_was_read |= amount > 0;
        self.reader.steal(amount)
    }

    fn steal_eof(&mut self) -> io::Result<Vec<u8>> {
        self.content_was_read = true;
        self.reader.steal_eof()
    }

    fn drop_eof(&mut self) -> io::Result<bool> {
        self.content_was_read = true;
        self.reader.drop_eof()
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<Cookie>> {
        None
    }

    fn get_ref(&self) -> Option<&BufferedReader<Cookie>> {
        None
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<Cookie> + 'b>>
            where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: Cookie)
            -> Cookie {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &Cookie {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut Cookie {
        self.reader.cookie_mut()
    }
}

// Check that we can use the read interface to stream the contents of
// a packet.
#[cfg(feature = "compression-deflate")]
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
    pub fn decrypt(&mut self, algo: SymmetricAlgorithm, key: &[u8])
        -> Result<()>
    {
        let trace = self.state.settings.trace;

        if self.content_was_read {
            return Err(Error::InvalidOperation(
                format!("Packet's content has already been read.")).into());
        }
        if self.decrypted {
            return Err(Error::InvalidOperation(
                format!("Packet not encrypted.")).into());
        }

        if algo.key_size()? != key.len () {
            return Err(Error::InvalidOperation(
                format!("Bad key size: {} expected: {}",
                        key.len(), algo.key_size()?)).into());
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
                                ::conversions::to_hex(&header[..], false)))
                               .into());
                }
            }

            // Ok, we can decrypt the data.  Push a Decryptor and a
            // HashedReader on the `BufferedReader` stack.

            // This can't fail, because we create a decryptor above
            // with the same parameters.
            let reader = self.take_reader();
            let mut reader = BufferedReaderDecryptor::with_cookie(
                algo, key, reader, Cookie::default()).unwrap();
            reader.cookie_mut().level = Some(self.recursion_depth as isize);

            if trace {
                eprintln!("{}PacketParser::decrypt: Pushing Decryptor, \
                           level {:?}.",
                          indent(self.recursion_depth),
                          reader.cookie_ref().level);
            }

            // And the hasher.
            let mut reader = HashedReader::new(
                reader, HashesFor::MDC, vec![HashAlgorithm::SHA1]);
            reader.cookie_mut().level = Some(self.recursion_depth as isize);

            if trace {
                eprintln!("{}PacketParser::decrypt: Pushing HashedReader, \
                           level {:?}.",
                          indent(self.recursion_depth),
                          reader.cookie_ref().level);
            }

            // Consume the header.  This shouldn't fail, because it
            // worked when reading the header.
            reader.data_consume_hard(bl + 2).unwrap();

            self.reader = Box::new(reader);
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

    const DECRYPT_PLAINTEXT: &[u8] = bytes!("a-cypherpunks-manifesto.txt");

    struct DecryptTest<'a> {
        filename: &'a str,
        algo: SymmetricAlgorithm,
        key_hex: &'a str,
    }
    const DECRYPT_TESTS: [DecryptTest; 4] = [
        DecryptTest {
            filename: "encrypted-aes256-password-123.gpg",
            algo: SymmetricAlgorithm::AES256,
            key_hex: "7EF4F08C44F780BEA866961423306166B8912C43352F3D9617F745E4E3939710",
        },
        DecryptTest {
            filename: "encrypted-aes192-password-123456.gpg",
            algo: SymmetricAlgorithm::AES192,
            key_hex: "B2F747F207EFF198A6C826F1D398DE037986218ED468DB61",
        },
        DecryptTest {
            filename: "encrypted-aes128-password-123456789.gpg",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "AC0553096429260B4A90B1CEC842D6A0",
        },
        DecryptTest {
            filename: "encrypted-twofish-password-red-fish-blue-fish.gpg",
            algo: SymmetricAlgorithm::Twofish,
            key_hex: "96AFE1EDFA7C9CB7E8B23484C718015E5159CFA268594180D4DB68B2543393CB",
        },
    ];

    #[test]
    fn decrypt_test_1() {
        for test in DECRYPT_TESTS.iter() {
            eprintln!("Decrypting {}", test.filename);

            let path = path_to(test.filename);
            let mut pp = PacketParserBuilder::from_file(&path).unwrap()
                .buffer_unread_content()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..])
                .expect("Empty message");

            loop {
                if let Packet::SEIP(_) = pp.packet {
                    let key = ::conversions::from_hex(test.key_hex, false)
                        .unwrap();

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
                               &DECRYPT_PLAINTEXT[..]);
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

    /// Like the above test, but streams the literal packet.
    #[test]
    fn decrypt_test_2() {
        for test in DECRYPT_TESTS.iter() {
            eprintln!("Decrypting {}", test.filename);

            let path = path_to(test.filename);
            let mut pp = PacketParserBuilder::from_file(&path).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..])
                .expect("Empty message");

            loop {
                if let Packet::SEIP(_) = pp.packet {
                    let key = ::conversions::from_hex(test.key_hex, false)
                        .unwrap();

                    pp.decrypt(test.algo, &key[..]).unwrap();

                    // SEIP packet.
                    let (packet, _, pp, _) = pp.recurse().unwrap();
                    assert_eq!(packet.tag(), Tag::SEIP);
                    let mut pp = pp.expect(
                        "Expected an compressed or literal packet, got EOF");

                    // Literal packet, optionally compressed
                    if let Packet::CompressedData(_) = pp.packet {
                        let (_, _, pp_tmp, _)
                            = pp.recurse().unwrap();
                        let pp_tmp = pp_tmp.expect(
                            "Expected a literal packet, got EOF");
                        pp = pp_tmp;
                    }

                    // Literal packet.
                    if let Packet::Literal(_) = pp.packet {
                        // Stream the content.
                        let mut body = Vec::new();
                        loop {
                            let mut b = [0];
                            if pp.read(&mut b).unwrap() == 0 {
                                break;
                            }
                            body.push(b[0]);
                        }
                        assert_eq!(&body[..], &DECRYPT_PLAINTEXT[..]);
                    } else {
                        panic!("Expected an Literal packet!");
                    }
                    let (_, _, pp_tmp, _)
                        = pp.recurse().unwrap();
                    let pp = pp_tmp.expect("Expected an MDC packet, got EOF");

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

    #[test]
    fn message_validator() {
        for test in DECRYPT_TESTS.iter() {
            let path = path_to(test.filename);
            let mut ppr = PacketParserBuilder::from_file(&path).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            // Make sure we actually decrypted...
            let mut saw_literal = false;
            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_message());

                match pp.packet {
                    Packet::SEIP(_) => {
                        let key = ::conversions::from_hex(test.key_hex, false)
                            .unwrap();
                        pp.decrypt(test.algo, &key[..]).unwrap();
                    },
                    Packet::Literal(_) => {
                        assert!(! saw_literal);
                        saw_literal = true;
                    },
                    _ => {},
                }

                let (_, _, ppr_tmp, _) = pp.recurse().unwrap();
                ppr = ppr_tmp;
            }
            assert!(saw_literal);
            if let PacketParserResult::EOF(eof) = ppr {
                assert!(eof.is_message());
            } else {
                unreachable!();
            }
        }
    }

    #[test]
    fn message_validator_opaque_content() {
        for test in DECRYPT_TESTS.iter() {
            let path = path_to(test.filename);
            let mut ppr = PacketParserBuilder::from_file(&path).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            // Make sure we actually decrypted...
            let mut saw_literal = false;
            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_message());

                match pp.packet {
                    Packet::Literal(_) => {
                        assert!(! saw_literal);
                        saw_literal = true;
                    },
                    _ => {},
                }

                let (_, _, ppr_tmp, _) = pp.recurse().unwrap();
                ppr = ppr_tmp;
            }
            assert!(! saw_literal);
            if let PacketParserResult::EOF(eof) = ppr {
                eprintln!("eof: {:?}", eof);
                assert!(eof.is_message());
            } else {
                unreachable!();
            }
        }
    }

    #[test]
    fn corrupted_tpk() {
        use armor::{Reader, Kind};

        // The following TPK is corrupted about a third the way
        // through.  Make sure we can recover.
        let mut ppr = PacketParser::from_reader(
            Reader::from_bytes(bytes!("../keys/corrupted.pgp"), Kind::PublicKey))
            .unwrap();

        let mut sigs = 0;
        let mut subkeys = 0;
        let mut userids = 0;
        let mut uas = 0;
        while let PacketParserResult::Some(pp) = ppr {
            match pp.packet.tag() {
                Tag::Signature => sigs = sigs + 1,
                Tag::PublicSubkey => subkeys = subkeys + 1,
                Tag::UserID => userids = userids + 1,
                Tag::UserAttribute => uas = uas + 1,
                _ => (),
            }

            let (_, _, ppr_, _) = pp.next().unwrap();
            ppr = ppr_;
        }

        assert_eq!(sigs, 53);
        assert_eq!(subkeys, 3);
        assert_eq!(userids, 5);
        assert_eq!(uas, 1);
    }
}
