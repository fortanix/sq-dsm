use std;
use std::io;
use std::io::prelude::*;
use std::cmp;
use std::collections::HashMap;
use std::str;
use std::mem;
use std::fmt;
use std::path::Path;
use time;
use failure;

use nettle;

use ::buffered_reader::*;

use {
    crypto::{aead, Hash},
    Result,
    CTB,
    BodyLength,
    crypto::s2k::S2K,
    Error,
    Header,
    packet::signature::Signature4,
    packet::prelude::*,
    Packet,
    KeyID,
    packet::key::SecretKey,
    crypto::SessionKey,
};
use constants::{
    AEADAlgorithm,
    CompressionAlgorithm,
    Curve,
    SignatureType,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};
use conversions::Time;
use crypto::{self, mpis::{PublicKey, MPI}};
use crypto::symmetric::{Decryptor, BufferedReaderDecryptor};
use message;
use message::MessageValidator;

mod partial_body;
use self::partial_body::BufferedReaderPartialBodyFilter;

use packet::signature::subpacket::SubpacketArea;

mod packet_pile_parser;
pub use self::packet_pile_parser::PacketPileParser;

mod hashed_reader;
pub(crate) use self::hashed_reader::HashedReader;

mod packet_parser_builder;
pub use self::packet_parser_builder::PacketParserBuilder;

pub mod map;
mod mpis;
pub mod stream;

// Whether to trace execution by default (on stderr).
const TRACE : bool = false;

/// Parsing of packets and related structures.
///
/// This is a uniform interface to parse packets, messages, keys, and
/// related data structures.
pub trait Parse<'a, T> {
    /// Reads from the given reader.
    fn from_reader<R: 'a + Read>(reader: R) -> Result<T>;

    /// Reads from the given file.
    ///
    /// The default implementation just uses [`from_reader(..)`], but
    /// implementations can provide their own specialized version.
    ///
    /// [`from_reader(..)`]: #tymethod.from_reader
    fn from_file<P: AsRef<Path>>(path: P) -> Result<T>
    {
        Self::from_reader(::std::fs::File::open(path)?)
    }

    /// Reads from the given slice.
    ///
    /// The default implementation just uses [`from_reader(..)`], but
    /// implementations can provide their own specialized version.
    ///
    /// [`from_reader(..)`]: #tymethod.from_reader
    fn from_bytes(data: &'a [u8]) -> Result<T>
    {
        Self::from_reader(io::Cursor::new(data))
    }
}

macro_rules! impl_parse_generic_packet {
    ($typ: ident) => {
        impl<'a> Parse<'a, $typ> for $typ {
            fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
                let bio = buffered_reader::Generic::with_cookie(
                    reader, None, Cookie::default());
                let parser = PacketHeaderParser::new_naked(Box::new(bio));

                let mut pp = Self::parse(parser)?;
                pp.buffer_unread_content()?;

                match pp.next()? {
                    (Packet::$typ(o), PacketParserResult::EOF(_))
                        => Ok(o),
                    (p, PacketParserResult::EOF(_)) =>
                        Err(Error::InvalidOperation(
                            format!("Not a {} packet: {:?}", stringify!($typ),
                                    p)).into()),
                    (_, PacketParserResult::Some(_)) =>
                        Err(Error::InvalidOperation(
                            "Excess data after packet".into()).into()),
                }
            }
        }
    };
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
    // The reader stack wrapped in a buffered_reader::Dup so that if
    // there is a parse error, we can abort and still return an
    // Unknown packet.
    reader: buffered_reader::Dup<'a, Cookie>,

    // The current packet's header.
    header: Header,
    header_bytes: Vec<u8>,

    // This packet's path.
    path: Vec<usize>,

    // The `PacketParser`'s state.
    state: PacketParserState,

    /// A map of this packet.
    map: Option<map::Map>,
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
                        let e = match e.downcast::<io::Error>() {
                            Ok(e) =>
                                if let io::ErrorKind::UnexpectedEof = e.kind() {
                                    return $parser.error(e.into());
                                } else {
                                    e.into()
                                },
                            Err(e) => e,
                        };
                        let e = match e.downcast::<Error>() {
                            Ok(e) => match e {
                                Error::MalformedMPI(_) =>
                                    return $parser.error(e.into()),
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
            .field("path", &self.path)
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
           path: Vec<usize>, header: Header,
           header_bytes: Vec<u8>) -> Self
    {
        assert!(path.len() > 0);

        let mut cookie = Cookie::default();
        cookie.level = inner.cookie_ref().level;
        let map = if state.settings.map {
            Some(map::Map::new(header_bytes.clone()))
        } else {
            None
        };
        PacketHeaderParser {
            reader: buffered_reader::Dup::with_cookie(inner, cookie),
            header: header,
            header_bytes: header_bytes.clone(),
            path: path,
            state: state,
            map: map,
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
                                vec![ 0 ],
                                Header {
                                    ctb: CTB::new(Tag::Reserved),
                                    length: BodyLength::Full(0),
                                },
                                Vec::new())
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

            // This is a buffered_reader::Dup, so this always has an
            // inner.
            let mut inner = Box::new(self.reader).into_inner().unwrap();

            // Combine the header with the body for the map.
            let mut data = Vec::with_capacity(total_out + body.len());
            // We know that the inner reader must have at least
            // `total_out` bytes buffered, otherwise we could never
            // have read that much from the `buffered_reader::Dup`.
            data.extend_from_slice(&inner.buffer()[..total_out]);
            data.extend(body);
            self.map.as_mut().unwrap().finalize(data);

            inner
        } else {
            // This is a buffered_reader::Dup, so this always has an
            // inner.
            Box::new(self.reader).into_inner().unwrap()
        };

        // We know the data has been read, so this cannot fail.
        reader.data_consume_hard(total_out).unwrap();

        Ok(PacketParser {
            header: self.header,
            packet: packet,
            path: self.path,
            last_path: vec![],
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
    fn fail(self, reason: &'static str) -> Result<PacketParser<'a>> {
        self.error(Error::MalformedPacket(reason.into()).into())
    }

    fn error(self, error: failure::Error) -> Result<PacketParser<'a>> {
        Unknown::parse(self, error)
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

    fn recursion_depth(&self) -> isize {
        self.path.len() as isize - 1
    }
}


/// What the hash in the Cookie is for.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum HashesFor {
    Nothing,
    MDC,
    Signature,
}

/// Controls whether or not a hashed reader hashes data.
#[derive(Copy, Clone, PartialEq, Debug)]
enum Hashing {
    /// Hashing is enabled.
    Enabled,
    /// Hashing is enabled for notarized signatures.
    Notarized,
    /// Hashing is disabled.
    Disabled,
}


#[derive(Debug)]
pub(crate) struct Cookie {
    // `BufferedReader`s managed by a `PacketParser` have
    // `Some(level)`; an external `BufferedReader` (i.e., the
    // underlying `BufferedReader`) has no level.
    //
    // Before parsing a top-level packet, we may push a
    // `buffered_reader::Limitor` in front of the external
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
    // say, a `Literal` packet, it pushes a `buffered_reader::Limitor` on
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
    hashing: Hashing,

    /// Keeps track of whether the last one pass signature packet had
    /// the last flag set.
    saw_last: bool,
    sig_groups: Vec<SignatureGroup>,
    /// Keep track of the maximal size of sig_groups to compute
    /// signature levels.
    sig_groups_max_len: usize,

    /// Stashed bytes that need to be hashed.
    ///
    /// When checking nested signatures, we need to hash the framing.
    /// However, at the time we know that we want to hash it, it has
    /// already been consumed.  Deferring the consumption of headers
    /// failed due to complications with the partial body decoder
    /// eagerly consuming data.  I (Justus) decided that doing the
    /// right thing is not worth the trouble, at least for now.  Also,
    /// hash stash sounds funny.
    hash_stash: Option<Vec<u8>>,

    /// Whether this `BufferedReader` is actually an interior EOF in a
    /// container.
    ///
    /// This is used by the SEIP parser to prevent a child packet from
    /// accidentally swallowing the trailing MDC packet.  This can
    /// happen when there is a compressed data packet with an
    /// indeterminate body length encoding.  In this case, due to
    /// buffering, the decompressor consumes data beyond the end of
    /// the compressed data.
    ///
    /// When set, buffered_reader_pop_stack will return early when it
    /// encounters a fake EOF at the level it is popping to.
    fake_eof: bool,
}

/// Contains hashes for consecutive one pass signature packets ending
/// in one with the last flag set.
pub(crate) struct SignatureGroup {
    /// Counts the number of one pass signature packets this group is
    /// for.  Once this drops to zero, we pop the group from the
    /// stack.
    ops_count: usize,

    /// Maps hash algorithms to hash contexts.
    pub(crate) hashes: HashMap<HashAlgorithm, Box<nettle::Hash>>,
}

impl fmt::Debug for SignatureGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let algos = self.hashes.keys()
            .collect::<Vec<&HashAlgorithm>>();

        f.debug_struct("Cookie")
            .field("ops_count", &self.ops_count)
            .field("hashes", &algos)
            .finish()
    }
}

impl Default for SignatureGroup {
    fn default() -> Self {
        SignatureGroup {
            ops_count: 0,
            hashes: HashMap::new(),
        }
    }
}

impl SignatureGroup {
    /// Clears the signature group.
    fn clear(&mut self) {
        self.ops_count = 0;
        self.hashes.clear();
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie {
            level: None,
            hashing: Hashing::Enabled,
            hashes_for: HashesFor::Nothing,
            saw_last: false,
            sig_groups: vec![Default::default()],
            sig_groups_max_len: 1,
            hash_stash: None,
            fake_eof: false,
        }
    }
}

impl Cookie {
    fn new(level: isize) -> Cookie {
        Cookie {
            level: Some(level),
            hashing: Hashing::Enabled,
            hashes_for: HashesFor::Nothing,
            saw_last: false,
            sig_groups: vec![Default::default()],
            sig_groups_max_len: 1,
            hash_stash: None,
            fake_eof: false,
        }
    }

    /// Returns a reference to the topmost signature group.
    pub(crate) fn sig_group(&self) -> &SignatureGroup {
        assert!(self.sig_groups.len() > 0);
        &self.sig_groups[self.sig_groups.len() - 1]
    }

    /// Returns a mutable reference to the topmost signature group.
    pub(crate) fn sig_group_mut(&mut self) -> &mut SignatureGroup {
        assert!(self.sig_groups.len() > 0);
        let len = self.sig_groups.len();
        &mut self.sig_groups[len - 1]
    }

    /// Returns the level of the currently parsed signature.
    fn signature_level(&self) -> usize {
        // The signature with the deepest "nesting" is closest to the
        // data, and hence level 0.
        self.sig_groups_max_len - self.sig_groups.len()
    }

    /// Tests whether the topmost signature group is no longer used.
    fn sig_group_unused(&self) -> bool {
        assert!(self.sig_groups.len() > 0);
        self.sig_groups[self.sig_groups.len() - 1].ops_count == 0
    }

    /// Pushes a new signature group to the stack.
    fn sig_group_push(&mut self) {
        self.sig_groups.push(Default::default());
        self.sig_groups_max_len += 1;
    }

    /// Pops a signature group from the stack.
    fn sig_group_pop(&mut self) {
        if self.sig_groups.len() == 1 {
            // Don't pop the last one, just clear it.
            self.sig_groups[0].clear();
            self.hashes_for = HashesFor::Nothing;
        } else {
            self.sig_groups.pop();
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
               how: Hashing, level: isize) {
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
                        cookie.hashing = how;
                    }
                } else {
                    break;
                }
            }
            reader = r.get_mut();
        }
    }

    // A helpful debugging aid to pretty print a Buffered Reader
    // stack.
    #[allow(dead_code)]
    fn dump(reader: &BufferedReader<Cookie>) {
        let mut i = 1;
        let mut reader : Option<&BufferedReader<Cookie>> = Some(reader);
        while let Some(r) = reader {
            {
                let cookie = r.cookie_ref();

                eprint!("  {}. {}, level: {:?}",
                        i, r, cookie.level);
                if cookie.hashes_for != HashesFor::Nothing {
                    eprint!(", hashes for: {:?}", cookie.hashes_for);
                }
                eprint!("\n");
            }
            reader = r.get_ref();
            i = i + 1;
        }
    }
}

// Pops readers from a buffered reader stack at the specified level.
fn buffered_reader_stack_pop<'a>(
    mut reader: Box<BufferedReader<Cookie> + 'a>, depth: isize)
    -> Result<(bool, Box<BufferedReader<Cookie> + 'a>)>
{
    tracer!(TRACE, "buffered_reader_stack_pop", depth);
    t!("(reader level: {:?}, pop through: {})",
       reader.cookie_ref().level, depth);

    let mut last_level = None;
    while let Some(level) = reader.cookie_ref().level {
        assert!(level <= depth);

        if level >= depth {
            let fake_eof = reader.cookie_ref().fake_eof;

            t!("top reader at level {:?} (fake eof: {}), pop through: {}",
               reader.cookie_ref().level, fake_eof, depth);

            let (dropping_content, dropped_content)
                = if Some(level) != last_level {
                    // Only drop the content of the top BufferedReader at
                    // a given level.
                    (true, reader.drop_eof()?)
                } else {
                    assert_eq!(reader.buffer().len(), 0);
                    (false, false)
                };

            t!("popping level {:?} reader, {}dropping content ({}), \
                reader: {:?}",
               reader.cookie_ref().level,
               if dropping_content { "" } else { "not " },
               if dropped_content { "something dropped" }
               else { "nothing to drop" },
               reader);

            if reader.eof() && ! reader.consummated() {
                return Err(Error::MalformedPacket("Truncated packet".into())
                           .into());
            }
            reader = reader.into_inner().unwrap();

            if level == depth && fake_eof {
                t!("Popped a fake EOF reader at level {}, stopping.", depth);
                return Ok((true, reader));
            }
        } else {
            break;
        }

        last_level = Some(level);
    }

    Ok((false, reader))
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

    // Whether or not to create a map.
    map: bool,
}

// The default `PacketParser` settings.
impl Default for PacketParserSettings {
    fn default() -> Self {
        PacketParserSettings {
            max_recursion_depth: MAX_RECURSION_DEPTH,
            buffer_unread_content: false,
            map: false,
        }
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
                hash_bytes: S2K::decode_count(php.parse_u8("s2k_count")?),
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

impl<'a> Parse<'a, S2K> for S2K {
    /// Reads an S2K from `reader`.
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse(&mut parser)
    }
}

impl Header {
    pub(crate) fn parse<R: BufferedReader<C>, C> (bio: &mut R)
        -> Result<Header>
    {
        let ctb = CTB::from_ptag(bio.data_consume_hard(1)?[0])?;
        let length = match ctb {
            CTB::New(_) => BodyLength::parse_new_format(bio)?,
            CTB::Old(ref ctb) =>
                BodyLength::parse_old_format(bio, ctb.length_type)?,
        };
        return Ok(Header { ctb: ctb, length: length });
    }
}

impl<'a> Parse<'a, Header> for Header {
    /// Parses an OpenPGP packet's header as described in [Section 4.2
    /// of RFC 4880].
    ///
    ///   [Section 4.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self>
    {
        let mut reader = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        Header::parse(&mut reader)
    }
}

impl Unknown {
    /// Parses the body of any packet and returns an Unknown.
    fn parse<'a>(php: PacketHeaderParser<'a>, error: failure::Error)
                 -> Result<PacketParser<'a>>
    {
        let tag = php.header.ctb.tag;
        php.ok(Packet::Unknown(Unknown::new(tag, error)))
            .map(|pp| pp.set_decrypted(false))
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
    let mut reader = buffered_reader::Generic::with_cookie(
        reader, None, Cookie::default());
    let header = Header::parse(&mut reader)?;

    let reader : Box<BufferedReader<Cookie>>
        = match header.length {
            BodyLength::Full(len) =>
                Box::new(buffered_reader::Limitor::with_cookie(
                    Box::new(reader), len as u64, Cookie::default())),
            BodyLength::Partial(len) =>
                Box::new(BufferedReaderPartialBodyFilter::with_cookie(
                    reader, len, true, Cookie::default())),
            _ => Box::new(reader),
    };

    let parser = PacketHeaderParser::new(
        reader, PacketParserState::new(Default::default()), vec![ 0 ], header, Vec::new());
    let mut pp =
        Unknown::parse(parser,
                       failure::err_msg("explicit conversion to unknown"))?;
    pp.buffer_unread_content()?;
    pp.finish()?;

    if let Packet::Unknown(packet) = pp.packet {
        Ok(packet)
    } else {
        panic!("Internal inconsistency.");
    }
}

impl Signature {
    // Parses a signature packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>)
        -> Result<PacketParser<'a>>
    {
        let indent = php.recursion_depth();
        tracer!(TRACE, "Signature::parse", indent);

        make_php_try!(php);

        let version = php_try!(php.parse_u8("version"));

        match version {
            4 => Signature4::parse(php),
            _ => {
                t!("Ignoring version {} packet.", version);
                php.fail("unknown version")
            },
        }
    }

    /// Returns whether the data appears to be a signature (no promises).
    fn plausible(bio: &mut buffered_reader::Dup<Cookie>, header: &Header)
                 -> Result<()> {
        Signature4::plausible(bio, header)
    }
}

impl Signature4 {
    // Parses a signature packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>)
        -> Result<PacketParser<'a>>
    {
        let indent = php.recursion_depth();
        tracer!(TRACE, "Signature4::parse", indent);

        make_php_try!(php);

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
        if ! pk_algo.can_sign() {
            return php.fail("not a signature algorithm");
        }
        let mpis = php_try!(
            crypto::mpis::Signature::_parse(pk_algo, &mut php));

        let hash_algo = hash_algo.into();
        let mut pp = php.ok(Packet::Signature(Signature4::new(
            sigtype.into(), pk_algo.into(), hash_algo,
            SubpacketArea::new(hashed_area),
            SubpacketArea::new(unhashed_area),
            [hash_prefix1, hash_prefix2],
            mpis).into()))?;

        // Locate the corresponding HashedReader and extract the
        // computed hash.
        let mut computed_hash = None;
        {
            let recursion_depth = pp.recursion_depth();

            // We know that the top reader is not a HashedReader (it's
            // a buffered_reader::Dup).  So, start with it's child.
            let mut r = (&mut pp.reader).get_mut();
            while let Some(tmp) = r {
                {
                    let cookie = tmp.cookie_mut();

                    assert!(cookie.level.unwrap_or(-1)
                            <= recursion_depth);
                    // The HashedReader has to be at level
                    // 'recursion_depth - 1'.
                    if cookie.level.is_none()
                        || cookie.level.unwrap() < recursion_depth - 1 {
                            break
                        }

                    if cookie.hashes_for == HashesFor::Signature {
                        cookie.sig_group_mut().ops_count -= 1;
                        if let Some(hash) =
                            cookie.sig_group().hashes.get(&hash_algo)
                        {
                            t!("popped a {:?} HashedReader", hash_algo);
                            computed_hash = Some((cookie.signature_level(),
                                                  hash_algo, hash.clone()));
                        }

                        if cookie.sig_group_unused() {
                            cookie.sig_group_pop();
                        }
                        break;
                    }
                }

                r = tmp.get_mut();
            }
        }

        if let Some((level, algo, mut hash)) = computed_hash {
            if let Packet::Signature(ref mut sig) = pp.packet {
                sig.hash(&mut hash);

                let mut digest = vec![0u8; hash.digest_size()];
                hash.digest(&mut digest);

                sig.set_computed_hash(Some((algo, digest)));
                sig.set_level(level);
            } else {
                unreachable!()
            }
        }

        Ok(pp)
    }

    /// Returns whether the data appears to be a signature (no promises).
    fn plausible(bio: &mut buffered_reader::Dup<Cookie>, header: &Header) -> Result<()> {
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

impl_parse_generic_packet!(Signature);

#[test]
fn signature_parser_test () {
    let data = ::tests::message("sig.gpg");

    {
        let pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Full(307));
        if let Packet::Signature(ref p) = pp.packet {
            assert_eq!(p.version(), 4);
            assert_eq!(p.sigtype(), SignatureType::Binary);
            assert_eq!(p.pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
            assert_eq!(p.hash_algo(), HashAlgorithm::SHA512);
            assert_eq!(p.hashed_area().data.len(), 29);
            assert_eq!(p.unhashed_area().data.len(), 10);
            assert_eq!(p.hash_prefix(), &[0x65u8, 0x74]);
            assert_eq!(p.mpis().serialized_len(), 258);
        } else {
            panic!("Wrong packet!");
        }
    }
}

impl OnePassSig {
    fn parse<'a>(php: PacketHeaderParser<'a>)
        -> Result<PacketParser<'a>>
    {
        OnePassSig3::parse(php)
    }
}

impl_parse_generic_packet!(OnePassSig);

impl OnePassSig3 {
    fn parse<'a>(mut php: PacketHeaderParser<'a>)
        -> Result<PacketParser<'a>>
    {
        let indent = php.recursion_depth();
        tracer!(TRACE, "OnePassSig", indent);

        make_php_try!(php);

        let version = php_try!(php.parse_u8("version"));
        if version != 3 {
            t!("Ignoring version {} packet", version);

            // Unknown version.  Return an unknown packet.
            return php.fail("unknown version");
        }

        let sigtype = php_try!(php.parse_u8("sigtype"));
        let hash_algo = php_try!(php.parse_u8("hash_algo"));
        let pk_algo = php_try!(php.parse_u8("pk_algo"));
        let mut issuer = [0u8; 8];
        issuer.copy_from_slice(&php_try!(php.parse_bytes("issuer", 8)));
        let last = php_try!(php.parse_u8("last"));

        let hash_algo = hash_algo.into();
        let mut sig = OnePassSig3::new(sigtype.into());
        sig.set_hash_algo(hash_algo);
        sig.set_pk_algo(pk_algo.into());
        sig.set_issuer(KeyID::from_bytes(&issuer));
        sig.set_last_raw(last);

        let recursion_depth = php.recursion_depth();

        // Walk up the reader chain to see if there is already a
        // hashed reader on level recursion_depth - 1.
        let done = {
            let mut done = false;
            let mut reader : Option<&mut BufferedReader<Cookie>>
                = Some(&mut php.reader);
            while let Some(r) = reader {
                {
                    let cookie = r.cookie_mut();
                    if let Some(br_level) = cookie.level {
                        if br_level < recursion_depth - 1 {
                            break;
                        }
                        if br_level == recursion_depth - 1
                            && cookie.hashes_for == HashesFor::Signature {
                                // We found a suitable hashed reader.
                                if cookie.saw_last {
                                    cookie.sig_group_push();
                                    cookie.saw_last = false;
                                    cookie.hash_stash =
                                        Some(php.header_bytes.clone());
                                }

                                // Make sure that it uses the required
                                // hash algorithm.
                                if ! cookie.sig_group()
                                    .hashes.contains_key(&hash_algo)
                                {
                                    if let Ok(ctx) = hash_algo.context() {
                                        cookie.sig_group_mut()
                                            .hashes.insert(hash_algo, ctx);
                                    }
                                }

                                // Account for this OPS packet.
                                cookie.sig_group_mut().ops_count += 1;

                                // Keep track of the last flag.
                                cookie.saw_last = last > 0;

                                // We're done.
                                done = true;
                                break;
                            }
                    } else {
                        break;
                    }
                }
                reader = r.get_mut();
            }
            done
        };
        // Commit here after potentially pushing a signature group.
        let mut pp = php.ok(Packet::OnePassSig(sig.into()))?;
        if done {
            return Ok(pp);
        }

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

        assert!(pp.reader.cookie_ref().level <= Some(recursion_depth));
        let (fake_eof, reader)
            = buffered_reader_stack_pop(Box::new(pp.take_reader()),
                                        recursion_depth)?;
        // We only pop the buffered readers for the OPS, and we
        // (currently) never use a fake eof for OPS packets.
        assert!(! fake_eof);

        let mut reader = HashedReader::new(
            reader, HashesFor::Signature, algos);
        reader.cookie_mut().level = Some(recursion_depth - 1);
        // Account for this OPS packet.
        reader.cookie_mut().sig_group_mut().ops_count += 1;
        // Keep track of the last flag.
        reader.cookie_mut().saw_last = last > 0;

        t!("Pushed a hashed reader, level {:?}", reader.cookie_mut().level);

        // We add an empty limitor on top of the hashed reader,
        // because when we are done processing a packet,
        // PacketParser::finish discards any unread data from the top
        // reader.  Since the top reader is the HashedReader, this
        // discards any following packets.  To prevent this, we push a
        // Limitor on the reader stack.
        let mut reader = buffered_reader::Limitor::with_cookie(
            Box::new(reader), 0, Cookie::default());
        reader.cookie_mut().level = Some(recursion_depth);

        pp.reader = Box::new(reader);

        Ok(pp)
    }
}

#[test]
fn one_pass_sig_parser_test () {
    use SignatureType;
    use PublicKeyAlgorithm;

    // This test assumes that the first packet is a OnePassSig packet.
    let data = ::tests::message("signed-1.gpg");
    let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
    let p = pp.finish().unwrap();
    // eprintln!("packet: {:?}", p);

    if let &Packet::OnePassSig(ref p) = p {
        assert_eq!(p.version(), 3);
        assert_eq!(p.sigtype(), SignatureType::Binary);
        assert_eq!(p.hash_algo(), HashAlgorithm::SHA512);
        assert_eq!(p.pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(p.issuer().to_hex(), "7223B56678E02528");
        assert_eq!(p.last_raw(), 1);
    } else {
        panic!("Wrong packet!");
    }
}

impl<'a> Parse<'a, OnePassSig3> for OnePassSig3 {
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
        OnePassSig::from_reader(reader).and_then(|p| match p {
            OnePassSig::V3(p) => Ok(p),
            // XXX: Once we have a second variant.
            //
            // p => Err(Error::InvalidOperation(
            //     format!("Not a OnePassSig::V3 packet: {:?}", p)).into()),
        })
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
        let mut ppr = PacketParserBuilder::from_bytes(
            ::tests::message(test.filename))
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
                          ::conversions::to_hex(sig.hash_prefix(), false));
                eprintln!("  computed hash: {}",
                          ::conversions::to_hex(&sig.computed_hash().unwrap().1,
                                                false));

                assert_eq!(&test.hash_prefix[sigs], sig.hash_prefix());
                assert_eq!(&test.hash_prefix[sigs][..],
                           &sig.computed_hash().unwrap().1[..2]);

                sigs += 1;
            } else if one_pass_sigs > 0 {
                assert_eq!(one_pass_sigs, test.hash_prefix.len(),
                           "Number of OnePassSig packets does not match \
                            number of expected OnePassSig packets.");
            }

            ppr = pp.recurse().expect("Parsing message").1;
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
        make_php_try!(php);
        let tag = php.header.ctb.tag;
        assert!(tag == Tag::PublicKey
                || tag == Tag::PublicSubkey
                || tag == Tag::SecretKey
                || tag == Tag::SecretSubkey);
        let version = php_try!(php.parse_u8("version"));

        match version {
            4 => Key4::parse(php),
            _ => php.fail("unknown version"),
        }
    }

    /// Returns whether the data appears to be a key (no promises).
    fn plausible(bio: &mut buffered_reader::Dup<Cookie>, header: &Header)
                 -> Result<()> {
        Key4::plausible(bio, header)
    }
}

impl Key4 {
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

        let creation_time = php_try!(php.parse_be_u32("creation_time"));
        let pk_algo: PublicKeyAlgorithm = php_try!(php.parse_u8("pk_algo")).into();
        let mpis = php_try!(PublicKey::_parse(pk_algo, &mut php));
        let secret = if tag == Tag::SecretKey || tag == Tag::SecretSubkey {
            let s2k_usage = php_try!(php.parse_u8("s2k_usage"));
            let sec = match s2k_usage {
                // Unencrypted
                0 => {
                    let sec = php_try!(
                        crypto::mpis::SecretKey::_parse(pk_algo, &mut php));
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
                    let sk: SymmetricAlgorithm = php_try!(php.parse_u8("sym_algo")).into();
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
            unreachable!("tag is one of {Public, Secret} x {Key, Subkey}")
        };

        let key = php_try!(Key4::new(time::Tm::from_pgp(creation_time),
                                     pk_algo, mpis, secret));

        let tag = php.header.ctb.tag;
        php.ok(match tag {
            Tag::PublicKey => Packet::PublicKey(key.into()),
            Tag::PublicSubkey => Packet::PublicSubkey(key.into()),
            Tag::SecretKey => Packet::SecretKey(key.into()),
            Tag::SecretSubkey => Packet::SecretSubkey(key.into()),
            _ => unreachable!(),
        })
    }

    /// Returns whether the data appears to be a key (no promises).
    fn plausible(bio: &mut buffered_reader::Dup<Cookie>, header: &Header) -> Result<()> {
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

impl<'a> Parse<'a, Key> for Key {
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let parser = PacketHeaderParser::new_naked(Box::new(bio));

        let mut pp = Self::parse(parser)?;
        pp.buffer_unread_content()?;

        match pp.next()? {
            (Packet::PublicKey(o), PacketParserResult::EOF(_))
            | (Packet::PublicSubkey(o), PacketParserResult::EOF(_))
            | (Packet::SecretKey(o), PacketParserResult::EOF(_))
            | (Packet::SecretSubkey(o), PacketParserResult::EOF(_)) =>
                Ok(o),
            (p, PacketParserResult::EOF(_)) =>
                Err(Error::InvalidOperation(
                    format!("Not a Key packet: {:?}", p)).into()),
            (_, PacketParserResult::Some(_)) =>
                Err(Error::InvalidOperation(
                    "Excess data after packet".into()).into()),
        }
    }
}

impl Trust {
    /// Parses the body of a trust packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let value = php_try!(php.parse_bytes_eof("value"));
        php.ok(Packet::Trust(Trust::from(value)))
    }
}

impl_parse_generic_packet!(Trust);

impl UserID {
    /// Parses the body of a user id packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);

        let value = php_try!(php.parse_bytes_eof("value"));

        php.ok(Packet::UserID(UserID::from(value)))
    }
}

impl_parse_generic_packet!(UserID);

impl UserAttribute {
    /// Parses the body of a user attribute packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);

        let value = php_try!(php.parse_bytes_eof("value"));

        php.ok(Packet::UserAttribute(UserAttribute::from(value)))
    }
}

impl_parse_generic_packet!(UserAttribute);

impl Marker {
    /// Parses the body of a marker packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>>
    {
        make_php_try!(php);
        let marker = php_try!(php.parse_bytes("marker", Marker::BODY.len()));
        if &marker[..] == Marker::BODY {
            php.ok(Marker::default().into())
        } else {
            php.fail("invalid marker")
        }
    }
}

impl_parse_generic_packet!(Marker);

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
        let recursion_depth = php.recursion_depth();

        let mut literal = Literal::new(format.into());
        if let Some(filename) = filename {
            literal.set_filename_from_bytes(&filename)
                .expect("length checked above");
        }
        literal.set_date(Some(time::Tm::from_pgp(date)));
        let mut pp = php.ok(Packet::Literal(literal))?;

        // Enable hashing of the body.
        Cookie::hashing(pp.mut_reader(), Hashing::Enabled,
                        recursion_depth - 1);

        Ok(pp)
    }
}

impl_parse_generic_packet!(Literal);

#[test]
fn literal_parser_test () {
    use constants::DataFormat;
    {
        let data = ::tests::message("literal-mode-b.gpg");
        let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Full(18));
        let content = pp.steal_eof().unwrap();
        let p = pp.finish().unwrap();
        // eprintln!("{:?}", p);
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format(), DataFormat::Binary);
            assert_eq!(p.filename().unwrap()[..], b"foobar"[..]);
            assert_eq!(p.date(), Some(&time::Tm::from_pgp(1507458744)));
            assert_eq!(content, b"FOOBAR");
        } else {
            panic!("Wrong packet!");
        }
    }

    {
        let data = ::tests::message("literal-mode-t-partial-body.gpg");
        let mut pp = PacketParser::from_bytes(data).unwrap().unwrap();
        assert_eq!(pp.header.length, BodyLength::Partial(4096));
        let content = pp.steal_eof().unwrap();
        let p = pp.finish().unwrap();
        if let &Packet::Literal(ref p) = p {
            assert_eq!(p.format(), DataFormat::Text);
            assert_eq!(p.filename().unwrap()[..],
                       b"manifesto.txt"[..]);
            assert_eq!(p.date(), Some(&time::Tm::from_pgp(1508000649)));

            let expected = ::tests::manifesto();

            assert_eq!(&content[..], &expected[..]);
        } else {
            panic!("Wrong packet!");
        }
    }
}

impl CompressedData {
    /// Parses the body of a compressed data packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        let recursion_depth = php.recursion_depth();
        tracer!(TRACE, "CompressedData::parse", recursion_depth);

        make_php_try!(php);
        let algo: CompressionAlgorithm =
            php_try!(php.parse_u8("algo")).into();

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

        let recursion_depth = php.recursion_depth();
        let mut pp = php.ok(Packet::CompressedData(CompressedData::new(algo)))?;

        t!("Pushing a decompressor for {}, recursion depth = {:?}.",
           algo, recursion_depth);

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
                Box::new(buffered_reader::Deflate::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zlib =>
                Box::new(buffered_reader::Zlib::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 =>
                Box::new(buffered_reader::Bzip::with_cookie(
                    reader, Cookie::new(recursion_depth))),
            _ => unreachable!(), // Validated above.
        };
        pp.set_reader(reader);

        Ok(pp)
    }
}

impl_parse_generic_packet!(CompressedData);

#[cfg(any(feature = "compression-deflate", feature = "compression-bzip2"))]
#[test]
fn compressed_data_parser_test () {
    use constants::DataFormat;

    let expected = ::tests::manifesto();

    for i in 1..4 {
        match CompressionAlgorithm::from(i) {
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip | CompressionAlgorithm::Zlib => (),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 => (),
            _ => continue,
        }
        let mut pp = PacketParser::from_bytes(::tests::message(
            &format!("compressed-data-algo-{}.gpg", i))).unwrap().unwrap();

        // We expect a compressed packet containing a literal data
        // packet, and that is it.
        if let Packet::CompressedData(ref compressed) = pp.packet {
            assert_eq!(compressed.algorithm(), i.into());
        } else {
            panic!("Wrong packet!");
        }

        let ppr = pp.recurse().unwrap().1;

        // ppr should be the literal data packet.
        let mut pp = ppr.unwrap();

        // It is a child.
        assert_eq!(pp.recursion_depth(), 1);

        let content = pp.steal_eof().unwrap();

        let (literal, ppr) = pp.recurse().unwrap();

        if let Packet::Literal(literal) = literal {
            assert_eq!(literal.filename(), None);
            assert_eq!(literal.format(), DataFormat::Binary);
            assert_eq!(literal.date(), Some(&time::Tm::from_pgp(1509219866)));
            assert_eq!(content, expected.to_vec());
        } else {
            panic!("Wrong packet!");
        }

        // And, we're done...
        assert!(ppr.is_none());
    }
}

impl SKESK {
    /// Parses the body of an SK-ESK packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        let skesk = match version {
            4 => {
                let sym_algo = php_try!(php.parse_u8("sym_algo"));
                let s2k = php_try!(S2K::parse(&mut php));
                let esk = php_try!(php.parse_bytes_eof("esk"));

                SKESK::V4(php_try!(SKESK4::new(
                    sym_algo.into(),
                    s2k,
                    if esk.len() > 0 { Some(esk) } else { None },
                )))
            },

            5 => {
                let sym_algo: SymmetricAlgorithm =
                    php_try!(php.parse_u8("sym_algo")).into();
                let aead_algo: AEADAlgorithm =
                    php_try!(php.parse_u8("aead_algo")).into();
                let s2k = php_try!(S2K::parse(&mut php));
                let iv_size = php_try!(aead_algo.iv_size());
                let digest_size = php_try!(aead_algo.digest_size());
                let aead_iv = php_try!(php.parse_bytes("aead_iv", iv_size));

                // The rest of the packet is the ESK, and the AEAD
                // digest.  We don't know the size of the former, but
                // we know the size of the latter.
                let mut esk = php_try!(php.reader.steal_eof()
                                       .map_err(|e| failure::Error::from(e)));
                let l = esk.len();
                let aead_digest = esk.split_off(l - digest_size);
                // Now fix the map.
                php.field("esk", esk.len());
                php.field("aead_digest", aead_digest.len());

                SKESK::V5(php_try!(SKESK5::new(
                    sym_algo,
                    aead_algo,
                    s2k,
                    aead_iv.into_boxed_slice(),
                    esk,
                    aead_digest.into_boxed_slice(),
                )))
            },

            _ => {
                // We only support version 4 and 5 SKESK packets.
                return php.fail("unknown version");
            }
        };

        php.ok(Packet::SKESK(skesk))
    }
}

impl_parse_generic_packet!(SKESK);

#[test]
fn skesk_parser_test() {
    use crypto::Password;
    struct Test<'a> {
        filename: &'a str,
        s2k: S2K,
        cipher_algo: SymmetricAlgorithm,
        password: Password,
        key_hex: &'a str,
    };

    let tests = [
        Test {
            filename: "s2k/mode-3-encrypted-key-password-bgtyhn.gpg",
            cipher_algo: SymmetricAlgorithm::AES128,
            s2k: S2K::Iterated {
                hash: HashAlgorithm::SHA1,
                salt: [0x82, 0x59, 0xa0, 0x6e, 0x98, 0xda, 0x94, 0x1c],
                hash_bytes: S2K::decode_count(238),
            },
            password: "bgtyhn".into(),
            key_hex: "474E5C373BA18AF0A499FCAFE6093F131DF636F6A3812B9A8AE707F1F0214AE9",
        },
    ];

    for test in tests.iter() {
        let mut pp = PacketParser::from_bytes(
            ::tests::message(test.filename)).unwrap().unwrap();
        if let Packet::SKESK(SKESK::V4(ref skesk)) = pp.packet {
            eprintln!("{:?}", skesk);

            assert_eq!(skesk.symmetric_algo(), test.cipher_algo);
            assert_eq!(skesk.s2k(), &test.s2k);

            match skesk.decrypt(&test.password) {
                Ok((_sym_algo, key)) => {
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

impl SEIP {
    /// Parses the body of a SEIP packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        if version != 1 {
            return php.fail("unknown version");
        }

        php.ok(SEIP1::new().into())
            .map(|pp| pp.set_decrypted(false))
    }
}

impl_parse_generic_packet!(SEIP);

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
                        if state.sig_group().hashes.len() > 0 {
                            let mut h = state.sig_group_mut().hashes
                                .get_mut(&HashAlgorithm::SHA1)
                                .unwrap();
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

        php.ok(Packet::MDC(MDC::new(hash, computed_hash)))
    }
}

impl_parse_generic_packet!(MDC);

impl AED {
    /// Parses the body of a AED packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));

        match version {
            1 => AED1::parse(php),
            _ => php.fail("unknown version"),
        }
    }
}

impl_parse_generic_packet!(AED);

impl AED1 {
    /// Parses the body of a AED packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let cipher: SymmetricAlgorithm =
            php_try!(php.parse_u8("sym_algo")).into();
        let aead: AEADAlgorithm =
            php_try!(php.parse_u8("aead_algo")).into();
        let chunk_size: usize =
            1 << (php_try!(php.parse_u8("chunk_size")) as usize + 6);

        let iv_size = php_try!(aead.iv_size());
        let iv = php_try!(php.parse_bytes("iv", iv_size));

        let aed = php_try!(Self::new(
            cipher, aead, chunk_size, iv.into_boxed_slice()
        ));
        php.ok(aed.into()).map(|pp| pp.set_decrypted(false))
    }
}

impl MPI {
    /// Parses an OpenPGP MPI.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    fn parse<'a>(name_len: &'static str, name: &'static str,
                 php: &mut PacketHeaderParser<'a>)
                 -> Result<Self> {
        // This function is used to parse MPIs from unknown
        // algorithms, which may use an encoding unknown to us.
        // Therefore, we need to be extra careful only to consume the
        // data once we found a well-formed MPI.
        let bits = {
            let buf = php.reader.data_hard(2)?;
            u16::from_be_bytes([buf[0], buf[1]]) as usize
        };
        if bits == 0 {
            // Now consume the data.
            php.parse_be_u16(name_len).expect("worked before");
            return Ok(MPI{ bits: 0, value: vec![].into_boxed_slice()});
        }

        let bytes = (bits + 7) / 8;
        let value = {
            let buf = php.reader.data_hard(2 + bytes)?;
            Vec::from(&buf[2..2 + bytes])
        };

        let unused_bits = bytes * 8 - bits;
        assert_eq!(bytes * 8 - unused_bits, bits);

        // Make sure the unused bits are zeroed.
        if unused_bits > 0 {
            let mask = !((1 << (8 - unused_bits)) - 1);
            let unused_value = value[0] & mask;

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

        // Now consume the data.
        php.parse_be_u16(name_len).expect("worked before");
        php.parse_bytes(name, bytes).expect("worked before");
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

impl<'a> Parse<'a, MPI> for MPI {
    // Reads an MPI from `reader`.
    fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse("(none_len)", "(none)", &mut parser)
    }
}

impl PKESK {
    /// Parses the body of an PK-ESK packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let version = php_try!(php.parse_u8("version"));
        match version {
            3 => PKESK3::parse(php),
            _ => php.fail("unknown version"),
        }
    }
}

impl_parse_generic_packet!(PKESK);

impl PKESK3 {
    /// Parses the body of an PK-ESK packet.
    fn parse<'a>(mut php: PacketHeaderParser<'a>) -> Result<PacketParser<'a>> {
        make_php_try!(php);
        let mut keyid = [0u8; 8];
        keyid.copy_from_slice(&php_try!(php.parse_bytes("keyid", 8)));
        let pk_algo: PublicKeyAlgorithm = php_try!(php.parse_u8("pk_algo")).into();
        if ! pk_algo.can_encrypt() {
            return php.fail("not an encryption algorithm");
        }
        let mpis = crypto::mpis::Ciphertext::_parse(pk_algo, &mut php)?;

        let pkesk = php_try!(PKESK3::new(KeyID::from_bytes(&keyid),
                                         pk_algo, mpis));
        php.ok(pkesk.into())
    }
}

impl<'a> Parse<'a, PKESK3> for PKESK3 {
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
        PKESK::from_reader(reader).and_then(|p| match p {
            PKESK::V3(p) => Ok(p),
            // XXX: Once we have a second variant.
            //
            // p => Err(Error::InvalidOperation(
            //     format!("Not a PKESKv3 packet: {:?}", p)).into()),
        })
    }
}

impl<'a> Parse<'a, Packet> for Packet {
    fn from_reader<R: 'a + Read>(reader: R) -> Result<Self> {
        let ppr =
            PacketParserBuilder::from_reader(reader)
            ?.buffer_unread_content().finalize()?;

        let (p, ppr) = match ppr {
            PacketParserResult::Some(mut pp) => {
                pp.next()?
            },
            PacketParserResult::EOF(_) =>
                return Err(Error::InvalidOperation(
                    "Unexpected EOF".into()).into()),
        };

        match (p, ppr) {
            (p, PacketParserResult::EOF(_)) =>
                Ok(p),
            (_, PacketParserResult::Some(_)) =>
                Err(Error::InvalidOperation(
                    "Excess data after packet".into()).into()),
        }
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

    /// Whether the packet sequence is a valid OpenPGP keyring.
    keyring_validator: ::tpk::KeyringValidator,

    /// Whether the packet sequence is a valid OpenPGP TPK.
    tpk_validator: ::tpk::TPKValidator,

    // Whether this is the first packet in the packet sequence.
    first_packet: bool,
}

impl PacketParserState {
    fn new(settings: PacketParserSettings) -> Self {
        PacketParserState {
            settings: settings,
            message_validator: Default::default(),
            keyring_validator: Default::default(),
            tpk_validator: Default::default(),
            first_packet: true,
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
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::Packet;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// # let _ = f(include_bytes!("../../tests/data/keys/public-key.gpg"));
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
///     // Start parsing the next packet.
///     ppr = pp.recurse()?.1;
/// }
/// # return Ok(());
/// # }
pub struct PacketParser<'a> {
    /// The current packet's header.
    header: Header,

    /// The packet that is being parsed.
    pub packet: Packet,

    // The path of the packet that is currently being parsed.
    path: Vec<usize>,
    // The path of the packet that was most recently returned by
    // `next()` or `recurse()`.
    last_path: Vec<usize>,

    reader: Box<BufferedReader<Cookie> + 'a>,

    // Whether the caller read the packet's content.  If so, then we
    // can't recurse, because we're missing some of the packet!
    content_was_read: bool,

    // Whether PacketParser::finish has been called.
    finished: bool,

    // Whether the content has been decrypted.
    decrypted: bool,

    /// A map of this packet.
    map: Option<map::Map>,

    state: PacketParserState,
}

impl<'a> std::fmt::Display for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PacketParser")
    }
}

impl<'a> std::fmt::Debug for PacketParser<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PacketParser")
            .field("header", &self.header)
            .field("packet", &self.packet)
            .field("path", &self.path)
            .field("last_path", &self.last_path)
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
    EOF((Box<BufferedReader<Cookie> + 'a>, PacketParserState, Vec<usize>)),
}

/// Information about the stream of packets parsed by the
/// `PacketParser`.
#[derive(Debug)]
pub struct PacketParserEOF {
    state: PacketParserState,

    last_path: Vec<usize>,
}

impl PacketParserEOF {
    /// Copies the important information in `pp` into a new
    /// `PacketParserEOF` instance.
    fn new(mut state: PacketParserState) -> Self {
        state.message_validator.finish();
        state.keyring_validator.finish();
        state.tpk_validator.finish();

        PacketParserEOF {
            state: state,
            last_path: vec![],
        }
    }

    /// Whether the message is an OpenPGP Message.
    ///
    /// As opposed to a TPK or just a bunch of packets.
    pub fn is_message(&self) -> Result<()> {
        use message::MessageValidity;

        match self.state.message_validator.check() {
            MessageValidity::Message => Ok(()),
            MessageValidity::MessagePrefix => unreachable!(),
            MessageValidity::Error(err) => Err(err),
        }
    }

    /// Whether the message is an OpenPGP keyring.
    ///
    /// As opposed to a Message or just a bunch of packets.
    pub fn is_keyring(&self) -> Result<()> {
        use tpk::KeyringValidity;

        match self.state.keyring_validator.check() {
            KeyringValidity::Keyring => Ok(()),
            KeyringValidity::KeyringPrefix => unreachable!(),
            KeyringValidity::Error(err) => Err(err),
        }
    }

    /// Whether the message is an OpenPGP TPK.
    ///
    /// As opposed to a Message or just a bunch of packets.
    pub fn is_tpk(&self) -> Result<()> {
        use tpk::TPKValidity;

        match self.state.tpk_validator.check() {
            TPKValidity::TPK => Ok(()),
            TPKValidity::TPKPrefix => unreachable!(),
            TPKValidity::Error(err) => Err(err),
        }
    }

    /// Returns the path of the last packet.
    pub fn last_path(&self) -> &[usize] {
        &self.last_path[..]
    }

    /// The last packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    pub fn last_recursion_depth(&self) -> Option<isize> {
        if self.last_path.len() == 0 {
            None
        } else {
            Some(self.last_path.len() as isize - 1)
        }
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

    /// The current packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    ///
    /// Note: if the PacketParser has reached the end of the packet
    /// sequence and is not parsing a packet, then this returns None.
    pub fn recursion_depth(&self) -> Option<isize> {
        match self {
            PacketParserResult::Some(pp) => Some(pp.recursion_depth()),
            PacketParserResult::EOF(_) => None,
        }
    }

    /// The last packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    ///
    /// Note: if no packet has been returned yet, this returns None.
    pub fn last_recursion_depth(&self) -> Option<isize> {
        match self {
            PacketParserResult::Some(pp) => pp.last_recursion_depth(),
            PacketParserResult::EOF(eof) => eof.last_recursion_depth(),
        }
    }
}

impl<'a> Parse<'a, PacketParserResult<'a>> for PacketParser<'a> {
    /// Starts parsing an OpenPGP message stored in a `std::io::Read` object.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    fn from_reader<R: io::Read + 'a>(reader: R)
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_reader(reader)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a file named `path`.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_file(path)?.finalize()
    }

    /// Starts parsing an OpenPGP message stored in a buffer.
    ///
    /// This function returns a `PacketParser` for the first packet in
    /// the stream.
    fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserResult<'a>> {
        PacketParserBuilder::from_bytes(bytes)?.finalize()
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

    /// Returns the reader stack, replacing it with a
    /// `buffered_reader::EOF` reader.
    ///
    /// This function may only be called when the `PacketParser` is in
    /// State::Body.
    fn take_reader(&mut self) -> Box<BufferedReader<Cookie> + 'a> {
        self.set_reader(
            Box::new(buffered_reader::EOF::with_cookie(Default::default())))
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

    /// Returns the path of the last packet.
    pub fn last_path(&self) -> &[usize] {
        &self.last_path[..]
    }

    /// Returns the path of the current packet.
    pub fn path(&self) -> &[usize] {
        &self.path[..]
    }

    /// The current packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    pub fn recursion_depth(&self) -> isize {
        self.path.len() as isize - 1
    }

    /// The last packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1, etc.
    ///
    /// Note: if no packet has been returned yet, this returns None.
    pub fn last_recursion_depth(&self) -> Option<isize> {
        if self.last_path.len() == 0 {
            assert_eq!(&self.path[..], &[ 0 ]);
            None
        } else {
            Some(self.last_path.len() as isize - 1)
        }
    }

    /// Returns whether the message appears to be an OpenPGP Message.
    ///
    /// Only when the whole message has been processed is it possible
    /// to say whether the message is definitely an OpenPGP Message.
    /// Before that, it is only possible to say that the message is a
    /// valid prefix or definitely not an OpenPGP message.
    pub fn possible_message(&self) -> Result<()> {
        use message::MessageValidity;

        match self.state.message_validator.check() {
            MessageValidity::Message => unreachable!(),
            MessageValidity::MessagePrefix => Ok(()),
            MessageValidity::Error(err) => Err(err),
        }
    }

    /// Returns whether the message appears to be an OpenPGP keyring.
    ///
    /// Only when the whole message has been processed is it possible
    /// to say whether the message is definitely an OpenPGP keyring.
    /// Before that, it is only possible to say that the message is a
    /// valid prefix or definitely not an OpenPGP keyring.
    pub fn possible_keyring(&self) -> Result<()> {
        use tpk::KeyringValidity;

        match self.state.keyring_validator.check() {
            KeyringValidity::Keyring => unreachable!(),
            KeyringValidity::KeyringPrefix => Ok(()),
            KeyringValidity::Error(err) => Err(err),
        }
    }

    /// Returns whether the message appears to be an OpenPGP TPK.
    ///
    /// Only when the whole message has been processed is it possible
    /// to say whether the message is definitely an OpenPGP TPK.
    /// Before that, it is only possible to say that the message is a
    /// valid prefix or definitely not an OpenPGP TPK.
    pub fn possible_tpk(&self) -> Result<()> {
        use tpk::TPKValidity;

        match self.state.tpk_validator.check() {
            TPKValidity::TPK => unreachable!(),
            TPKValidity::TPKPrefix => Ok(()),
            TPKValidity::Error(err) => Err(err),
        }
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
    fn plausible(mut bio: &mut buffered_reader::Dup<Cookie>, header: &Header) -> Result<()> {
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
            Tag::AED => bad,
        }
    }

    /// Returns a `PacketParser` for the next OpenPGP packet in the
    /// stream.  If there are no packets left, this function returns
    /// `bio`.
    fn parse(mut bio: Box<BufferedReader<Cookie> + 'a>,
             state: PacketParserState,
             path: Vec<usize>)
        -> Result<ParserResult<'a>>
    {
        assert!(path.len() > 0);

        let indent = path.len() as isize - 1;
        tracer!(TRACE, "PacketParser::parse", indent);
        t!("Parsing packet at {:?}", path);

        let recursion_depth = path.len() as isize - 1;

        // When header encounters an EOF, it returns an error.  But,
        // we want to return None.  Try a one byte read.
        if bio.data(1)?.len() == 0 {
            t!("No packet at {:?} (EOF).", path);
            return Ok(ParserResult::EOF((bio, state, path)));
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

        let mut bio = buffered_reader::Dup::with_cookie(bio, Cookie::default());
        let mut header;

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

                    if state.first_packet || skip > 32 * 1024 {
                        // Limit the search space.  This should be
                        // enough to find a reasonable recovery point
                        // in a TPK.
                        return Err(orig_error.unwrap());
                    }
                }
            }

            skip = skip + 1;
        }

        // Prepare to actually consume the header or garbage.
        let consumed = if skip == 0 {
            bio.total_out()
        } else {
            t!("turning {} bytes of junk into an Unknown packet", skip);

            // Fabricate a header.
            header = Header {
                ctb: CTB::new(Tag::Reserved),
                length: BodyLength::Full(skip as u32),
            };
            0
        };

        let tag = header.ctb.tag;

        // A buffered_reader::Dup always has an inner.
        let mut bio = Box::new(bio).into_inner().unwrap();

        // Disable hashing for literal packets, Literal::parse will
        // enable it for the body.  Signatures and OnePassSig packets
        // are only hashed by notarizing signatures.
        if tag == Tag::Literal {
            Cookie::hashing(
                &mut bio, Hashing::Disabled, recursion_depth - 1);
        } else if tag == Tag::OnePassSig || tag == Tag::Signature {
            Cookie::hashing(
                &mut bio, Hashing::Notarized, recursion_depth - 1);
        }

        // Save header for the map or nested signatures.
        let header_bytes =
            Vec::from(&bio.data_consume_hard(consumed)?[..consumed]);

        let bio : Box<BufferedReader<Cookie>>
            = match header.length {
                BodyLength::Full(len) => {
                    t!("Pushing a limitor ({} bytes), level: {}.",
                       len, recursion_depth);
                    Box::new(buffered_reader::Limitor::with_cookie(
                        bio, len as u64,
                        Cookie::new(recursion_depth)))
                },
                BodyLength::Partial(len) => {
                    t!("Pushing a partial body chunk decoder, level: {}.",
                       recursion_depth);
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
                    t!("Indeterminate length packet, not adding a limitor.");
                    bio
                },
        };

        // Our parser should not accept packets that fail our header
        // syntax check.  Doing so breaks roundtripping, and seems
        // like a bad idea anyway.
        let header_syntax_error = header.valid(true).err();
        let parser = PacketHeaderParser::new(bio, state, path,
                                             header, header_bytes);

        let mut result = match tag {
            Tag::Reserved if skip > 0 => Unknown::parse(
                parser, Error::MalformedPacket(format!(
                    "Skipped {} bytes of junk", skip)).into()),
            _ if header_syntax_error.is_some() =>
                Unknown::parse(parser, header_syntax_error.unwrap()),
            Tag::Signature =>           Signature::parse(parser),
            Tag::OnePassSig =>          OnePassSig::parse(parser),
            Tag::PublicSubkey =>        Key::parse(parser),
            Tag::PublicKey =>           Key::parse(parser),
            Tag::SecretKey =>           Key::parse(parser),
            Tag::SecretSubkey =>        Key::parse(parser),
            Tag::Trust =>               Trust::parse(parser),
            Tag::UserID =>              UserID::parse(parser),
            Tag::UserAttribute =>       UserAttribute::parse(parser),
            Tag::Marker =>              Marker::parse(parser),
            Tag::Literal =>             Literal::parse(parser),
            Tag::CompressedData =>      CompressedData::parse(parser),
            Tag::SKESK =>               SKESK::parse(parser),
            Tag::SEIP =>                SEIP::parse(parser),
            Tag::MDC =>                 MDC::parse(parser),
            Tag::PKESK =>               PKESK::parse(parser),
            Tag::AED =>                 AED::parse(parser),
            _ => Unknown::parse(parser,
                                Error::UnsupportedPacketType(tag).into()),
        }?;

        if tag == Tag::OnePassSig {
            Cookie::hashing(
                &mut result, Hashing::Enabled, recursion_depth - 1);
        }

        result.state.first_packet = false;

        t!(" -> {:?}, path: {:?}, level: {:?}.",
           result.packet.tag(), result.path, result.cookie_ref().level);

        return Ok(ParserResult::Success(result));
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  (See
    /// [`PacketParsererBuilder`] for how to configure this.)  It then
    /// creates a new packet parser for the next packet.  If the
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
    ///   - A `PacketParser` holding the new packet;
    ///
    /// To determine the two packet's position within the parse tree,
    /// you can use `last_path()` and `path()`, respectively.  To
    /// determine their depth, you can use `last_recursion_depth()`
    /// and `recursion_depth()`, respectively.
    ///
    /// Note: A recursion depth of 0 means that the packet is a
    /// top-level packet, a recursion depth of 1 means that the packet
    /// is an immediate child of a top-level-packet, etc.
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
        -> Result<(Packet, PacketParserResult<'a>)>
    {
        let indent = self.recursion_depth();
        tracer!(TRACE, "PacketParser::next", indent);
        t!("({:?}, path: {:?}, level: {:?}).",
           self.packet.tag(), self.path, self.cookie_ref().level);

        self.finish()?;

        let (mut fake_eof, mut reader) = buffered_reader_stack_pop(
            mem::replace(&mut self.reader,
                         Box::new(buffered_reader::EOF::with_cookie(
                             Default::default()))),
            self.recursion_depth())?;
        // At this point, next() has to point to a non-container
        // packet or an opaque container (due to the maximum recursion
        // level being reaching).  In this case, there can't be a fake
        // EOF.
        assert!(! fake_eof);

        self.last_path.clear();
        self.last_path.extend_from_slice(&self.path[..]);

        // Assume that we succeed in parsing the next packet.  If not,
        // then we'll adjust the path.
        *self.path.last_mut().expect("A path is never empty") += 1;

        // Now read the next packet.
        loop {
            // Parse the next packet.
            t!("Reading packet at {:?} from: {:?}", self.path, reader);

            let recursion_depth = self.recursion_depth();

            let ppr = PacketParser::parse(reader, self.state, self.path)?;
            match ppr {
                ParserResult::EOF((reader_, state_, path_)) => {
                    // We got EOF on the current container.  The
                    // container at recursion depth n is empty.  Pop
                    // it and any filters for it, i.e., those at level
                    // n (e.g., the limitor that caused us to hit
                    // EOF), and then try again.

                    t!("depth: {}, got EOF trying to read the next packet",
                       recursion_depth);

                    self.path = path_;

                    if ! fake_eof && recursion_depth == 0 {
                        t!("Popped top-level container, done reading message.");
                        let mut eof = PacketParserEOF::new(state_);
                        eof.last_path = self.last_path;
                        return Ok((self.packet,
                                   PacketParserResult::EOF(eof)));
                    } else {
                        self.state = state_;
                        self.finish()?;
                        // XXX self.content_was_read = false;
                        let (fake_eof_, reader_) = buffered_reader_stack_pop(
                            reader_, recursion_depth - 1)?;
                        fake_eof = fake_eof_;
                        if ! fake_eof {
                            self.path.pop().unwrap();
                            *self.path.last_mut()
                                .expect("A path is never empty") += 1;
                        }
                        reader = reader_;
                    }
                },
                ParserResult::Success(mut pp) => {
                    let path = pp.path().to_vec();
                    pp.state.message_validator.push(pp.packet.tag(), &path);
                    pp.state.keyring_validator.push(pp.packet.tag());
                    pp.state.tpk_validator.push(pp.packet.tag());

                    pp.last_path = self.last_path;

                    return Ok((self.packet, PacketParserResult::Some(pp)));
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
    /// packet's recursion depth will be `last_recursion_depth() + 1`;
    /// because we always visit interior nodes, we can't recurse more
    /// than one level at a time.
    ///
    ///   [`next()`]: #method.next
    pub fn recurse(self) -> Result<(Packet, PacketParserResult<'a>)> {
        let indent = self.recursion_depth();
        tracer!(TRACE, "PacketParser::recurse", indent);
        t!("({:?}, path: {:?}, level: {:?})",
           self.packet.tag(), self.path, self.cookie_ref().level);

        match self.packet {
            // Packets that recurse.
            Packet::CompressedData(_) | Packet::SEIP(_) | Packet::AED(_)
                if self.decrypted =>
            {
                if self.recursion_depth() as u8
                    >= self.state.settings.max_recursion_depth
                {
                    t!("Not recursing into the {:?} packet, maximum recursion \
                        depth ({}) reached.",
                       self.packet.tag(),
                       self.state.settings.max_recursion_depth);

                    // Drop through.
                } else if self.content_was_read {
                    t!("Not recursing into the {:?} packet, some data was \
                        already read.",
                       self.packet.tag());

                    // Drop through.
                } else {
                    let mut last_path = self.last_path;
                    last_path.clear();
                    last_path.extend_from_slice(&self.path[..]);

                    let mut path = self.path;
                    path.push(0);

                    match PacketParser::parse(self.reader, self.state,
                                              path.clone())?
                    {
                        ParserResult::Success(mut pp) => {
                            t!("Recursed into the {:?} packet, got a {:?}.",
                               self.packet.tag(), pp.packet.tag());

                            pp.state.message_validator.push(
                                pp.packet.tag(), &path);
                            pp.state.keyring_validator.push(pp.packet.tag());
                            pp.state.tpk_validator.push(pp.packet.tag());

                            pp.last_path = last_path;

                            return Ok((self.packet,
                                       PacketParserResult::Some(pp)));
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
                | Packet::Marker(_) | Packet::Trust(_)
                | Packet::UserID(_) | Packet::UserAttribute(_)
                | Packet::Literal(_) | Packet::PKESK(_) | Packet::SKESK(_)
                | Packet::SEIP(_) | Packet::MDC(_) | Packet::AED(_) => {
                // Drop through.
                t!("A {:?} packet is not a container, not recursing.",
                   self.packet.tag());
            },
        }

        // No recursion.
        self.next()
    }

    /// Causes the PacketParser to buffer the packet's contents.
    ///
    /// The packet's contents can be retrieved using `packet.body()`.
    /// In general, you should avoid buffering a packet's content and
    /// prefer streaming its content unless you are certain that the
    /// content is small.
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::Packet;
    /// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
    /// # use std::string::String;
    /// # f(include_bytes!("../../tests/data/messages/literal-mode-t-partial-body.gpg"));
    /// #
    /// # fn f(message_data: &[u8]) -> Result<()> {
    /// let mut ppr = PacketParser::from_bytes(message_data)?;
    /// while let PacketParserResult::Some(mut pp) = ppr {
    ///     // Process the packet.
    ///
    ///     if let Packet::Literal(_) = pp.packet {
    ///         assert!(pp.buffer_unread_content()?
    ///                     .starts_with(b"A Cypherpunk's Manifesto"));
    /// #       assert!(pp.buffer_unread_content()?
    /// #                   .starts_with(b"A Cypherpunk's Manifesto"));
    ///         assert!(pp.packet.body().unwrap()
    ///                     .starts_with(b"A Cypherpunk's Manifesto"));
    ///         assert_eq!(pp.packet.body().unwrap().len(), 5158);
    ///     }
    ///
    ///     // Start parsing the next packet.
    ///     ppr = pp.recurse()?.1;
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
        }

        if let Some(body) = self.packet.body.as_ref() {
            Ok(&body[..])
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
        let indent = self.recursion_depth();
        tracer!(TRACE, "PacketParser::finish", indent);

        if self.finished {
            return Ok(&mut self.packet);
        }

        let recursion_depth = self.recursion_depth();

        let unread_content = if self.state.settings.buffer_unread_content {
            t!("({:?} at depth {}): buffering {} bytes of unread content",
               self.packet.tag(), recursion_depth,
               self.data_eof().unwrap().len());

            self.buffer_unread_content()?.len() > 0
        } else {
            t!("({:?} at depth {}): dropping {} bytes of unread content",
               self.packet.tag(), recursion_depth,
               self.data_eof().unwrap().len());

            self.drop_eof()?
        };

        if unread_content {
            match self.packet.tag() {
                Tag::SEIP | Tag::AED | Tag::SED | Tag::CompressedData => {
                    // We didn't (fully) process a container's content.  Add
                    // this as opaque conent to the message validator.
                    let mut path = self.path().to_vec();
                    path.push(0);
                    self.state.message_validator.push_token(
                        message::Token::OpaqueContent, &path);
                }
                _ => {},
            }
        }

        self.finished = true;

        Ok(&mut self.packet)
    }

    /// Returns a reference to the current packet's header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns a reference to the map (if any is written).
    pub fn map(&self) -> Option<&map::Map> {
        self.map.as_ref()
    }

    /// Takes the map (if any is written).
    pub fn take_map(&mut self) -> Option<map::Map> {
        self.map.take()
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

    let expected = ::tests::manifesto();

    // A message containing a compressed packet that contains a
    // literal packet.
    let pp = PacketParser::from_bytes(
        ::tests::message("compressed-data-algo-1.gpg")).unwrap().unwrap();

    // The message has the form:
    //
    //   [ compressed data [ literal data ] ]
    //
    // packet is the compressed data packet; ppo is the literal data
    // packet.
    let (packet, ppr) = pp.recurse().unwrap();
    let packet_depth = ppr.last_recursion_depth().unwrap();
    let pp_depth = ppr.recursion_depth().unwrap();
    if let Packet::CompressedData(_) = packet {
    } else {
        panic!("Expected a compressed data packet.");
    }

    let relative_position = pp_depth - packet_depth;
    assert_eq!(relative_position, 1);

    let mut pp = ppr.unwrap();

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
    let (packet, ppr) = pp.recurse().unwrap();
    assert!(ppr.is_none());
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
    pub fn decrypt(&mut self, algo: SymmetricAlgorithm, key: &SessionKey)
        -> Result<()>
    {
        let indent = self.recursion_depth();
        tracer!(TRACE, "PacketParser::decrypt", indent);

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

        match self.packet.clone() {
            Packet::SEIP(_) => {
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
                            format!(
                                "Last two 16-bit quantities don't match: {}",
                                ::conversions::to_hex(&header[..], false)))
                                   .into());
                    }
                }

                // Ok, we can decrypt the data.  Push a Decryptor and
                // a HashedReader on the `BufferedReader` stack.

                // This can't fail, because we create a decryptor
                // above with the same parameters.
                let reader = self.take_reader();
                let mut reader = BufferedReaderDecryptor::with_cookie(
                    algo, key, reader, Cookie::default()).unwrap();
                reader.cookie_mut().level = Some(self.recursion_depth());

                t!("Pushing Decryptor, level {:?}.", reader.cookie_ref().level);

                // And the hasher.
                let mut reader = HashedReader::new(
                    reader, HashesFor::MDC, vec![HashAlgorithm::SHA1]);
                reader.cookie_mut().level = Some(self.recursion_depth());

                t!("Pushing HashedReader, level {:?}.",
                   reader.cookie_ref().level);

                // A SEIP packet is a container that always ends with
                // an MDC packet.  But, if the packet preceding the
                // MDC packet uses an indeterminate length encoding
                // (gpg generates these for compressed data packets,
                // for instance), the parser has to detect the EOF and
                // be careful to not read any further.  Unfortunately,
                // our decompressor buffers the data.  To stop the
                // decompressor from buffering the MDC packet, we use
                // a buffered_reader::Reserve.  Note: we do this
                // unconditionally, since it doesn't otherwise
                // interfere with parsing.

                // An MDC consists of a 1-byte CTB, a 1-byte length
                // encoding, and a 20-byte hash.
                let mut reader = buffered_reader::Reserve::with_cookie(
                    Box::new(reader), 1 + 1 + 20,
                    Cookie::new(self.recursion_depth()));
                reader.cookie_mut().fake_eof = true;

                t!("Pushing buffered_reader::Reserve, level: {}.",
                   self.recursion_depth());

                // Consume the header.  This shouldn't fail, because
                // it worked when reading the header.
                reader.data_consume_hard(bl + 2).unwrap();

                self.reader = Box::new(reader);
                self.decrypted = true;

                Ok(())
            },

            Packet::AED(AED::V1(aed)) => {
                // Get the first chunk and check whether we can
                // decrypt it using the provided key.  Don't actually
                // comsume them in case we can't.
                {
                    let data = self.data(aed.chunk_digest_size()?)?;
                    let mut dec = aead::Decryptor::new(
                        1, aed.symmetric_algo(), aed.aead(), aed.chunk_size(),
                        aed.iv(), key, &data[..cmp::min(data.len(), aed.chunk_digest_size()?)])?;
                    let mut chunk = Vec::new();
                    dec.take(aed.chunk_size() as u64).read_to_end(&mut chunk)?;
                }

                // Ok, we can decrypt the data.  Push a Decryptor and
                // a HashedReader on the `BufferedReader` stack.

                // This can't fail, because we create a decryptor
                // above with the same parameters.
                let reader = self.take_reader();
                let mut reader = aead::BufferedReaderDecryptor::with_cookie(
                    1, aed.symmetric_algo(), aed.aead(), aed.chunk_size(),
                    aed.iv(), key, reader, Cookie::default()).unwrap();
                reader.cookie_mut().level = Some(self.recursion_depth());

                t!("Pushing aead::Decryptor, level {:?}.",
                   reader.cookie_ref().level);

                self.reader = Box::new(reader);
                self.decrypted = true;

                Ok(())
            },

            _ =>
                Err(Error::InvalidOperation(
                    format!("Can't decrypt {:?} packets.",
                            self.packet.tag())).into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    enum Data<'a> {
        File(&'a str),
        String(&'a [u8]),
    }

    impl<'a> Data<'a> {
        fn content(&self) -> Vec<u8> {
            match self {
                Data::File(filename) => ::tests::message(filename).to_vec(),
                Data::String(data) => data.to_vec(),
            }
        }
    }

    struct DecryptTest<'a> {
        filename: &'a str,
        algo: SymmetricAlgorithm,
        key_hex: &'a str,
        plaintext: Data<'a>,
        paths: &'a[ (Tag, &'a[ usize ] ) ],
    }
    const DECRYPT_TESTS: [DecryptTest; 10] = [
        // Messages with a relatively simple structure:
        //
        //   [ SKESK SEIP [ Literal MDC ] ].
        //
        // And simple length encodings (no indeterminate length
        // encodings).
        DecryptTest {
            filename: "encrypted-aes256-password-123.gpg",
            algo: SymmetricAlgorithm::AES256,
            key_hex: "7EF4F08C44F780BEA866961423306166B8912C43352F3D9617F745E4E3939710",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "encrypted-aes192-password-123456.gpg",
            algo: SymmetricAlgorithm::AES192,
            key_hex: "B2F747F207EFF198A6C826F1D398DE037986218ED468DB61",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "encrypted-aes128-password-123456789.gpg",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "AC0553096429260B4A90B1CEC842D6A0",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "encrypted-twofish-password-red-fish-blue-fish.gpg",
            algo: SymmetricAlgorithm::Twofish,
            key_hex: "96AFE1EDFA7C9CB7E8B23484C718015E5159CFA268594180D4DB68B2543393CB",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },

        // More complex messages.  In particular, some of these
        // messages include compressed data packets, and some are
        // signed.  But what makes these particularly complex is the
        // use of an indeterminate length encoding, which checks the
        // buffered_reader::Reserve hack.
        DecryptTest {
            filename: "seip/msg-compression-not-signed-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "86A8C1C7961F55A3BE181A990D0ABB2A",
            plaintext: Data::String(b"compression, not signed\n"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::CompressedData, &[ 1, 0 ]),
                (Tag::Literal, &[ 1, 0, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "seip/msg-compression-signed-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "1B195CD35CAD4A99D9399B4CDA4CDA4E",
            plaintext: Data::String(b"compression, signed\n"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::CompressedData, &[ 1, 0 ]),
                (Tag::OnePassSig, &[ 1, 0, 0 ]),
                (Tag::Literal, &[ 1, 0, 1 ]),
                (Tag::Signature, &[ 1, 0, 2 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "seip/msg-no-compression-not-signed-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "AFB43B83A4B9D971E4B4A4C53749076A",
            plaintext: Data::String(b"no compression, not signed\n"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
                (Tag::MDC, &[ 1, 1 ]),
            ],
        },
        DecryptTest {
            filename: "seip/msg-no-compression-signed-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "9D5DB92F77F0E4A356EE53813EF2C3DC",
            plaintext: Data::String(b"no compression, signed\n"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::SEIP, &[ 1 ]),
                (Tag::OnePassSig, &[ 1, 0 ]),
                (Tag::Literal, &[ 1, 1 ]),
                (Tag::Signature, &[ 1, 2 ]),
                (Tag::MDC, &[ 1, 3 ]),
            ],
        },

        // AEAD encrypted messages.
        DecryptTest {
            filename: "aed/msg-aes128-eax-chunk-size-64-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "E88151F2B6F6F6F0AE6B56ED247AA61B",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::AED, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
            ],
        },
        DecryptTest {
            filename: "aed/msg-aes128-eax-chunk-size-134217728-password-123.pgp",
            algo: SymmetricAlgorithm::AES128,
            key_hex: "D7EE3F3B049DE011687EC9E08D6DCBB0",
            plaintext: Data::File("a-cypherpunks-manifesto.txt"),
            paths: &[
                (Tag::SKESK, &[ 0 ]),
                (Tag::AED, &[ 1 ]),
                (Tag::Literal, &[ 1, 0 ]),
            ],
        },
    ];

    // Consume packets until we get to one in `keep`.
    fn consume_until<'a>(mut ppr: PacketParserResult<'a>,
                         ignore_first: bool, keep: &[Tag], skip: &[Tag])
        -> PacketParserResult<'a>
    {
        if ignore_first {
            ppr = ppr.unwrap().recurse().unwrap().1;
        }

        while let PacketParserResult::Some(pp) = ppr {
            let tag = pp.packet.tag();
            for t in keep.iter() {
                if *t == tag {
                    return PacketParserResult::Some(pp);
                }
            }

            let mut ok = false;
            for t in skip.iter() {
                if *t == tag {
                    ok = true;
                }
            }
            if !ok {
                panic!("Packet not in keep ({:?}) or skip ({:?}) set: {:?}",
                       keep, skip, pp.packet);
            }

            ppr = pp.recurse().unwrap().1;
        }
        return ppr;
    }

    #[test]
    fn decrypt_test() {
        for test in DECRYPT_TESTS.iter() { for stream in [false, true].iter() {
            eprintln!("Decrypting {}, streaming content: {}",
                      test.filename, stream);

            let mut ppr = PacketParserBuilder::from_bytes(
                ::tests::message(test.filename)).unwrap()
                .buffer_unread_content()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            let mut ppr = consume_until(
                ppr, false, &[ Tag::SEIP, Tag::AED ][..],
                &[ Tag::SKESK, Tag::PKESK ][..] );
            if let PacketParserResult::Some(ref mut pp) = ppr {
                let key = ::conversions::from_hex(test.key_hex, false)
                    .unwrap().into();

                pp.decrypt(test.algo, &key).unwrap();
            } else {
                panic!("Expected a SEIP/AED packet.  Got: {:?}", ppr);
            }

            let mut ppr = consume_until(
                ppr, true, &[ Tag::Literal ][..],
                &[ Tag::OnePassSig, Tag::CompressedData ][..]);
            if let PacketParserResult::Some(ref mut pp) = ppr {
                if *stream {
                    let mut body = Vec::new();
                    loop {
                        let mut b = [0];
                        if pp.read(&mut b).unwrap() == 0 {
                            break;
                        }
                        body.push(b[0]);
                    }

                    assert_eq!(&body[..],
                               &test.plaintext.content()[..],
                               "{:?}", pp.packet);
                } else {
                    pp.buffer_unread_content().unwrap();
                    assert_eq!(&pp.packet.body.as_ref().unwrap()[..],
                               &test.plaintext.content()[..],
                               "{:?}", pp.packet);
                }
            } else {
                panic!("Expected a Literal packet.  Got: {:?}", ppr);
            }

            let mut ppr = consume_until(
                ppr, true, &[ Tag::MDC ][..], &[ Tag::Signature ][..]);
            if let PacketParserResult::Some(
                PacketParser { packet: Packet::MDC(ref mdc), .. }) = ppr
            {
                assert_eq!(mdc.computed_hash(), mdc.hash(),
                           "MDC doesn't match");
            }

            if ppr.is_none() {
                // AED packets don't have an MDC packet.
                continue;
            }
            let ppr = consume_until(
                ppr, true, &[][..], &[][..]);
            assert!(ppr.is_none());
        }}
    }

    #[test]
    fn message_validator() {
        for test in DECRYPT_TESTS.iter() {
            let mut ppr = PacketParserBuilder::from_bytes(
                ::tests::message(test.filename)).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            // Make sure we actually decrypted...
            let mut saw_literal = false;
            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_message().is_ok());

                match pp.packet {
                    Packet::SEIP(_) | Packet::AED(_) => {
                        let key = ::conversions::from_hex(test.key_hex, false)
                            .unwrap().into();
                        pp.decrypt(test.algo, &key).unwrap();
                    },
                    Packet::Literal(_) => {
                        assert!(! saw_literal);
                        saw_literal = true;
                    },
                    _ => {},
                }

                ppr = pp.recurse().unwrap().1;
            }
            assert!(saw_literal);
            if let PacketParserResult::EOF(eof) = ppr {
                assert!(eof.is_message().is_ok());
            } else {
                unreachable!();
            }
        }
    }

    #[test]
    fn keyring_validator() {
        use std::io::Cursor;
        for test in &["testy.pgp",
                      "lutz.gpg",
                      "testy-new.pgp",
                      "neal.pgp"]
        {
            let mut ppr = PacketParserBuilder::from_reader(
                Cursor::new(::tests::key("testy.pgp")).chain(
                    Cursor::new(::tests::key(test)))).unwrap()
                .finalize()
                .expect(&format!("Error reading {:?}", test));

            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_keyring().is_ok());
                ppr = pp.recurse().unwrap().1;
            }
            if let PacketParserResult::EOF(eof) = ppr {
                assert!(eof.is_keyring().is_ok());
                assert!(eof.is_tpk().is_err());
            } else {
                unreachable!();
            }
        }
    }

    #[test]
    fn tpk_validator() {
        for test in &["testy.pgp",
                      "lutz.gpg",
                      "testy-new.pgp",
                      "neal.pgp"]
        {
            let mut ppr = PacketParserBuilder::from_bytes(::tests::key(test))
                .unwrap()
                .finalize()
                .expect(&format!("Error reading {:?}", test));

            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_keyring().is_ok());
                assert!(pp.possible_tpk().is_ok());
                ppr = pp.recurse().unwrap().1;
            }
            if let PacketParserResult::EOF(eof) = ppr {
                assert!(eof.is_keyring().is_ok());
                assert!(eof.is_tpk().is_ok());
            } else {
                unreachable!();
            }
        }
    }

    // If we don't decrypt the SEIP packet, it shows up as opaque
    // content.
    #[test]
    fn message_validator_opaque_content() {
        for test in DECRYPT_TESTS.iter() {
            let mut ppr = PacketParserBuilder::from_bytes(
                ::tests::message(test.filename)).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            let mut saw_literal = false;
            while let PacketParserResult::Some(mut pp) = ppr {
                assert!(pp.possible_message().is_ok());

                match pp.packet {
                    Packet::Literal(_) => {
                        assert!(! saw_literal);
                        saw_literal = true;
                    },
                    _ => {},
                }

                ppr = pp.recurse().unwrap().1;
            }
            assert!(! saw_literal);
            if let PacketParserResult::EOF(eof) = ppr {
                eprintln!("eof: {:?}; message: {:?}", eof, eof.is_message());
                assert!(eof.is_message().is_ok());
            } else {
                unreachable!();
            }
        }
    }

    #[test]
    fn path() {
        for test in DECRYPT_TESTS.iter() {
            eprintln!("Decrypting {}", test.filename);

            let mut ppr = PacketParserBuilder::from_bytes(
                ::tests::message(test.filename)).unwrap()
                .finalize()
                .expect(&format!("Error reading {}", test.filename)[..]);

            let mut last_path = vec![];

            let mut paths = test.paths.to_vec();
            // We pop from the end.
            paths.reverse();

            while let PacketParserResult::Some(mut pp) = ppr {
                let path = paths.pop().expect("Message longer than expect");
                assert_eq!(path.0, pp.packet.tag());
                assert_eq!(path.1, pp.path());

                assert_eq!(last_path, pp.last_path());
                last_path = pp.path.to_vec();

                eprintln!("  {}: {:?}", pp.packet.tag(), pp.path());

                match pp.packet {
                    Packet::SEIP(_) | Packet::AED(_) => {
                        let key = ::conversions::from_hex(test.key_hex, false)
                            .unwrap().into();

                        pp.decrypt(test.algo, &key).unwrap();
                    }
                    _ => (),
                }

                ppr = pp.recurse().unwrap().1;
            }
            paths.reverse();
            assert_eq!(paths.len(), 0,
                       "Message shorter than expected (expecting: {:?})",
                       paths);

            if let PacketParserResult::EOF(mut eof) = ppr {
                assert_eq!(last_path, eof.last_path());
            } else {
                panic!("Expect an EOF");
            }
        }
    }

    #[test]
    fn corrupted_tpk() {
        use armor::{Reader, ReaderMode, Kind};

        // The following TPK is corrupted about a third the way
        // through.  Make sure we can recover.
        let mut ppr = PacketParser::from_reader(
            Reader::from_bytes(::tests::key("corrupted.pgp"),
                               ReaderMode::Tolerant(Some(Kind::PublicKey))))
            .unwrap();

        let mut sigs = 0;
        let mut subkeys = 0;
        let mut userids = 0;
        let mut uas = 0;
        let mut unknown = 0;
        while let PacketParserResult::Some(pp) = ppr {
            match pp.packet {
                Packet::Signature(_) => sigs += 1,
                Packet::PublicSubkey(_) => subkeys += 1,
                Packet::UserID(_) => userids += 1,
                Packet::UserAttribute(_) => uas += 1,
                Packet::Unknown(ref u) => {
                    unknown += 1;
                    assert_match!(Some(&Error::MalformedPacket(_))
                                  = u.error().downcast_ref());
                },
                _ => (),
            }

            ppr = pp.next().unwrap().1;
        }

        assert_eq!(sigs, 53);
        assert_eq!(subkeys, 3);
        assert_eq!(userids, 5);
        assert_eq!(uas, 0);
        assert_eq!(unknown, 2);
    }

    #[test]
    fn junk_prefix() {
        // Make sure we can read the first packet.
        let msg = ::tests::message("sig.gpg");

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(packet_parser_builder::Dearmor::Disabled)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);


        // Prepend an invalid byte and make sure we fail.  Note: we
        // have a mechanism to skip corruption, however, that is only
        // activated once we've seen a good packet.  This test checks
        // that we don't try to recover.
        let mut msg2 = Vec::new();
        msg2.push(0);
        msg2.extend_from_slice(&msg[..]);

        let ppr = PacketParserBuilder::from_bytes(&msg2[..]).unwrap()
            .dearmor(packet_parser_builder::Dearmor::Disabled)
            .finalize();
        assert_match!(Err(_) = ppr);
    }

    /// Issue #141.
    #[test]
    fn truncated_packet() {
        for msg in &[&::tests::message("literal-mode-b.gpg")[..],
                     &::tests::message("literal-mode-t-partial-body.gpg")[..],
        ] {
            // Make sure we can read the first packet.
            let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
                .dearmor(packet_parser_builder::Dearmor::Disabled)
                .finalize();
            assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

            // Now truncate the packet.
            let msg2 = &msg[..msg.len() - 1];
            let ppr = PacketParserBuilder::from_bytes(msg2).unwrap()
                .dearmor(packet_parser_builder::Dearmor::Disabled)
                .finalize().unwrap();
            if let PacketParserResult::Some(pp) = ppr {
                let err = pp.next().err().unwrap();
                assert_match!(Some(&Error::MalformedPacket(_))
                              = err.downcast_ref());
            } else {
                panic!("No packet!?");
            }
        }
    }
}
