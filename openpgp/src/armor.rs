//! ASCII Armor.
//!
//! This module deals with ASCII Armored data (see [RFC 4880, section 6]).
//!
//! [RFC 4880, section 6]: https://tools.ietf.org/html/rfc4880#section-6
//!
//! # Scope
//!
//! This implements a subset of the ASCII Armor specification.  Not
//! supported multipart messages.
//!
//! # Memory allocations
//!
//! Both the reader and the writer allocate memory in the order of the
//! size of chunks read or written.
//!
//! # Example
//!
//! ```rust, no_run
//! extern crate sequoia_openpgp as openpgp;
//! use std::fs::File;
//! use openpgp::armor::{Reader, Kind};
//!
//! let mut file = File::open("somefile.asc").unwrap();
//! let mut r = Reader::new(&mut file, Some(Kind::File));
//! ```

extern crate base64;
use buffered_reader::BufferedReader;
use std::io::{Cursor, Read, Write};
use std::io::{Result, Error, ErrorKind};
use std::path::Path;
use std::cmp::min;
use std::str;
use quickcheck::{Arbitrary, Gen};

use packet::prelude::*;
use packet::BodyLength;
use packet::ctb::{CTBNew, CTBOld};
use serialize::SerializeInto;

/// The encoded output stream must be represented in lines of no more
/// than 76 characters each (see (see [RFC 4880, section
/// 6.3](https://tools.ietf.org/html/rfc4880#section-6.3).  GnuPG uses
/// 64.
const LINE_LENGTH: usize = 64;

const LINE_ENDING: &str = "\n";

/// Specifies the type of data (see [RFC 4880, section 6.2]).
///
/// [RFC 4880, section 6.2]: https://tools.ietf.org/html/rfc4880#section-6.2
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Kind {
    /// A generic OpenPGP message.  (Since its structure hasn't been
    /// validated, in this crate's terminology, this is just a
    /// `PacketPile`.)
    Message,
    /// A transferable public key.
    PublicKey,
    /// A transferable secret key.
    SecretKey,
    /// A detached signature.
    Signature,
    /// A generic file.  This is a GnuPG extension.
    File,
}

impl Arbitrary for Kind {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use self::Kind::*;
        match u8::arbitrary(g) % 5 {
            0 => Message,
            1 => PublicKey,
            2 => SecretKey,
            3 => Signature,
            4 => File,
            _ => unreachable!(),
        }
    }
}

impl Kind {
    /// Autodetects the kind of data.
    fn detect(blurb: &[u8]) -> Option<Self> {
        if blurb.len() < "-----BEGIN PGP MESSAGE-----".len()
            || ! blurb.starts_with(b"-----BEGIN PGP ")
        {
            return None;
        }

        let kind = &blurb[15..];
        if kind.starts_with(b"MESSAGE-----") {
            Some(Kind::Message)
        } else if kind.starts_with(b"PUBLIC KEY BLOCK-----") {
            Some(Kind::PublicKey)
        } else if kind.starts_with(b"PRIVATE KEY BLOCK-----") {
            Some(Kind::SecretKey)
        } else if kind.starts_with(b"SIGNATURE-----") {
            Some(Kind::Signature)
        } else if kind.starts_with(b"ARMORED FILE-----") {
            Some(Kind::File)
        } else {
            None
        }
    }

    fn blurb(&self) -> &str {
        match self {
            &Kind::Message => "MESSAGE",
            &Kind::PublicKey => "PUBLIC KEY BLOCK",
            &Kind::SecretKey => "PRIVATE KEY BLOCK",
            &Kind::Signature => "SIGNATURE",
            &Kind::File => "ARMORED FILE",
        }
    }

    fn begin(&self) -> String {
        format!("-----BEGIN PGP {}-----", self.blurb())
    }

    fn end(&self) -> String {
        format!("-----END PGP {}-----", self.blurb())
    }

    /// Returns the length of the header.
    ///
    /// This does not include any trailing newline.  It is simply the
    /// length of:
    ///
    /// ```norun
    /// -----BEGIN PGP BLUB -----
    /// ```
    fn header_len(&self) -> usize {
        "-----BEGIN PGP -----".len()
            + self.blurb().len()
    }

    /// Returns the maximal size of the footer with CRC.
    fn footer_max_len(&self) -> usize {
        (5    // CRC
         + 4  // CR NL CR NL
         + 18 // "-----END PGP -----"
         + self.blurb().len()
         + 2  // CR NL
        )
    }
}

/// A filter that applies ASCII Armor to the data written to it.
pub struct Writer<W: Write> {
    sink: W,
    kind: Kind,
    stash: Vec<u8>,
    column: usize,
    crc: CRC,
    epilogue: Vec<u8>,
    dirty: bool,
    finalized: bool,
}

impl<W: Write> Writer<W> {
    /// Constructs a new filter for the given type of data.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::io::Write;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::armor::{Writer, Kind};
    /// # use std::io::{self, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let mut buffer = io::Cursor::new(vec![]);
    /// {
    ///     let mut writer = Writer::new(&mut buffer, Kind::File,
    ///         &[ ("Key", "Value") ][..])?;
    ///     writer.write_all(b"Hello world!")?;
    ///     // writer is drop()ed here.
    /// }
    /// assert_eq!(
    ///     String::from_utf8_lossy(buffer.get_ref()),
    ///     "-----BEGIN PGP ARMORED FILE-----
    /// Key: Value
    ///
    /// SGVsbG8gd29ybGQh
    /// =s4Gu
    /// -----END PGP ARMORED FILE-----
    /// ");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: W, kind: Kind, headers: &[(&str, &str)]) -> Result<Self> {
        let mut w = Writer {
            sink: inner,
            kind: kind,
            stash: Vec::<u8>::with_capacity(2),
            column: 0,
            crc: CRC::new(),
            epilogue: Vec::with_capacity(128),
            dirty: false,
            finalized: false,
        };

        {
            let mut cur = Cursor::new(&mut w.epilogue);
            write!(&mut cur, "{}{}", kind.begin(), LINE_ENDING)?;

            for h in headers {
                write!(&mut cur, "{}: {}{}", h.0, h.1, LINE_ENDING)?;
            }

            // A blank line separates the headers from the body.
            write!(&mut cur, "{}", LINE_ENDING)?;
        }

        Ok(w)
    }

    fn write_epilogue(&mut self) -> Result<()> {
        if ! self.dirty {
            self.dirty = true;
            self.sink.write_all(&self.epilogue)?;
            // Release memory.
            self.epilogue.clear();
            self.epilogue.shrink_to_fit();
        }
        Ok(())
    }

    /// Writes the footer.
    ///
    /// No more data can be written after this call.  If this is not
    /// called explicitly, the header is written once the writer is
    /// dropped.
    pub fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Err(Error::new(ErrorKind::BrokenPipe, "Writer is finalized."));
        }

        if ! self.dirty {
            // No data was written to us, don't emit anything.
            return Ok(());
        }
        self.write_epilogue()?;

        // Write any stashed bytes and pad.
        if self.stash.len() > 0 {
            self.sink.write_all(base64::encode_config(&self.stash,
                                                      base64::STANDARD).as_bytes())?;
            self.column += 4;
        }
        self.linebreak()?;
        if self.column > 0 {
            write!(self.sink, "{}", LINE_ENDING)?;
        }

        let crc = self.crc.finalize();
        let bytes: [u8; 3] = [
            (crc >> 16) as u8,
            (crc >>  8) as u8,
            (crc >>  0) as u8,
        ];

        // CRC and footer.
        write!(self.sink, "={}{}{}{}",
               base64::encode_config(&bytes, base64::STANDARD_NO_PAD),
               LINE_ENDING, self.kind.end(), LINE_ENDING)?;

        self.finalized = true;
        Ok(())
    }

    /// Inserts a line break if necessary.
    fn linebreak(&mut self) -> Result<()> {
        assert!(self.column <= LINE_LENGTH);
        if self.column == LINE_LENGTH {
            write!(self.sink, "{}", LINE_ENDING)?;
            self.column = 0;
        }
        Ok(())
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.finalized {
            return Err(Error::new(ErrorKind::BrokenPipe, "Writer is finalized."));
        }

        self.write_epilogue()?;

        // Update CRC on the unencoded data.
        self.crc.update(buf);

        let mut input = buf;
        let mut written = 0;

        // First of all, if there are stashed bytes, fill the stash
        // and encode it.  If writing out the stash fails below, we
        // might end up with a stash of size 3.
        assert!(self.stash.len() <= 3);
        if self.stash.len() > 0 {
            while self.stash.len() < 3 {
                if input.len() == 0 {
                    /* We exhausted the input.  Return now, any
                     * stashed bytes are encoded when finalizing the
                     * writer.  */
                    return Ok(written);
                }
                self.stash.push(input[0]);
                input = &input[1..];
                written += 1;
            }
            assert_eq!(self.stash.len(), 3);

            // If this fails for some reason, and the caller retries
            // the write, we might end up with a stash of size 3.
            self.sink.write_all(base64::encode_config(&self.stash,
                                                      base64::STANDARD_NO_PAD).as_bytes())?;
            self.column += 4;
            self.linebreak()?;
            self.stash.clear();
        }

        // Ensure that a multiple of 3 bytes are encoded, stash the
        // rest from the end of input.
        while input.len() % 3 > 0 {
            self.stash.push(input[input.len()-1]);
            input = &input[..input.len()-1];
            written += 1;
        }
        // We popped values from the end of the input, fix the order.
        self.stash.reverse();
        assert!(self.stash.len() < 3);

        // We know that we have a multiple of 3 bytes, encode them and write them out.
        assert!(input.len() % 3 == 0);
        let encoded = base64::encode_config(input, base64::STANDARD_NO_PAD);
        written += input.len();
        let mut enc = encoded.as_bytes();
        while enc.len() > 0 {
            let n = min(LINE_LENGTH - self.column, enc.len());
            self.sink.write_all(&enc[..n])?;
            enc = &enc[n..];
            self.column += n;
            self.linebreak()?;
        }

        assert_eq!(written, buf.len());
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.sink.flush()
    }
}

impl<W: Write> Drop for Writer<W> {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

/// A filter that strips ASCII Armor from a stream of data.
pub struct Reader<'a> {
    source: Box<'a + BufferedReader<()>>,
    kind: Option<Kind>,
    strict: bool,
    buffer: Vec<u8>,
    crc: CRC,
    expect_crc: Option<u32>,
    initialized: bool,
    headers: Vec<(String, String)>,
    finalized: bool,
}

impl<'a> Reader<'a> {
    /// Constructs a new filter for the given type of data.
    ///
    /// [ASCII Armor], designed to protect OpenPGP data in transit,
    /// has been a source of problems if the armor structure is
    /// damaged.  For example, copying data manually from one program
    /// to another might introduce or drop newlines.
    ///
    /// By default, the reader operates in robust mode.  It will
    /// extract the first armored OpenPGP data block it can find, even
    /// if the armor frame is damaged, or missing.
    ///
    /// To select strict mode, specify a kind argument.  In strict
    /// mode, the reader will match on the armor frame.  The reader
    /// ignores any data in front of the Armor Header Line, as long as
    /// the line the header is in is only prefixed by whitespace.
    ///
    ///   [ASCII Armor]: https://tools.ietf.org/html/rfc4880#section-6.2
    ///
    /// # Example
    ///
    /// ```
    /// # use std::io::Read;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::{Result, Message};
    /// # use openpgp::armor::Reader;
    /// # use openpgp::parse::Parse;
    /// # use std::io;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let data = "yxJiAAAAAABIZWxsbyB3b3JsZCE="; // base64 over literal data packet
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, None);
    ///
    /// let mut buf = Vec::new();
    /// reader.read_to_end(&mut buf)?;
    ///
    /// let message = Message::from_bytes(&buf)?;
    /// assert_eq!(message.body().unwrap().body().unwrap(),
    ///            b"Hello world!");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Or, in strict mode:
    ///
    /// ```
    /// # use std::io::Read;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::armor::{Reader, Kind};
    /// # use std::io::{self, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let data =
    ///     "-----BEGIN PGP ARMORED FILE-----
    ///
    ///      SGVsbG8gd29ybGQh
    ///      =s4Gu
    ///      -----END PGP ARMORED FILE-----";
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, Some(Kind::File));
    ///
    /// let mut content = String::new();
    /// reader.read_to_string(&mut content)?;
    /// assert_eq!(content, "Hello world!");
    /// assert_eq!(reader.kind(), Some(Kind::File));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<R>(inner: R, kind: Option<Kind>) -> Self
        where R: 'a + Read
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::new(inner, None)),
            kind)
    }

    /// Creates a `Reader` from an `io::Read`er.
    pub fn from_reader<R>(reader: R, kind: Option<Kind>) -> Self
        where R: 'a + Read
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::new(reader, None)),
            kind)
    }

    /// Creates a `Reader` from a file.
    pub fn from_file<P>(path: P, kind: Option<Kind>) -> Result<Self>
        where P: AsRef<Path>
    {
        Ok(Self::from_buffered_reader(
            Box::new(buffered_reader::File::open(path)?),
            kind))
    }

    /// Creates a `Reader` from a buffer.
    pub fn from_bytes(bytes: &'a [u8], kind: Option<Kind>) -> Self {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Memory::new(bytes)),
            kind)
    }

    pub(crate) fn from_buffered_reader<C: 'a>(
        inner: Box<'a + BufferedReader<C>>, kind: Option<Kind>) -> Self
    {
        Reader {
            source: Box::new(buffered_reader::Generic::new(inner, None)),
            kind: kind,
            strict: kind.is_some(),
            buffer: Vec::<u8>::with_capacity(1024),
            crc: CRC::new(),
            expect_crc: None,
            headers: Vec::new(),
            initialized: false,
            finalized: false,
        }
    }

    /// Returns the kind of data this reader is for.
    ///
    /// Useful if the kind of data is not known in advance.  If the
    /// header has not been encountered yet (try reading some data
    /// first!), this function returns None.
    pub fn kind(&self) -> Option<Kind> {
        self.kind
    }

    /// Returns the armored headers.
    ///
    /// The tuples contain a key and a value.
    ///
    /// Note: if a key occurs multiple times, then there are multiple
    /// entries in the vector with the same key; values with the same
    /// key are *not* combined.
    pub fn headers(&mut self) -> Result<&[(String, String)]> {
        self.initialize()?;
        Ok(&self.headers[..])
    }

    /// Consumes the header if not already done.
    fn initialize(&mut self) -> Result<()> {
        if self.initialized { return Ok(()) }

        // The range of the first 6 bits of a message is limited.
        // Save cpu cycles by only considering base64 data that starts
        // with one of those characters.
        lazy_static!{
            static ref START_CHARS : Vec<u8> = {
                let mut valid_start = Vec::new();
                for &tag in [ Tag::PKESK, Tag::SKESK,
                              Tag::OnePassSig, Tag::Signature,
                              Tag::PublicKey, Tag::SecretKey,
                              Tag::CompressedData, Tag::Literal ].into_iter() {
                    let mut ctb = [ 0u8; 1 ];
                    let mut o = [ 0u8; 4 ];

                    CTBNew::new(tag).serialize_into(&mut ctb[..]).unwrap();
                    base64::encode_config_slice(&ctb[..], base64::MIME, &mut o[..]);
                    valid_start.push(o[0]);

                    CTBOld::new(tag, BodyLength::Full(0)).unwrap()
                        .serialize_into(&mut ctb[..]).unwrap();
                    base64::encode_config_slice(&ctb[..], base64::MIME, &mut o[..]);
                    valid_start.push(o[0]);
                }

                // The standard start of an ASCII armor header e.g.,
                //
                //   -----BEGIN PGP MESSAGE-----
                valid_start.push('-' as u8);

                valid_start.sort();
                valid_start.dedup();
                valid_start
            };

        }

        // Look for the Armor Header Line, skipping any garbage in the
        // process.
        let mut found_blob = false;
        let start_chars = if self.strict {
            &[b'-'][..]
        } else {
            &START_CHARS[..]
        };

        let mut lines = 0;
        let n = 'search: loop {
            if lines > 0 {
                // Find the start of the next line.
                self.source.drop_through(&[b'\n'])?;
            }
            lines += 1;

            // Ignore leading whitespace, etc.
            while self.source.data_hard(1)?[0].is_ascii_whitespace() {
                self.source.consume(1);
            }

            // Don't bother if the first byte is not plausible.
            if !start_chars.binary_search(&self.source.data_hard(1)?[0]).is_ok()
            {
                self.source.consume(1);
                continue;
            }

            {
                let mut input = self.source.data(128)?;
                let n = input.len();

                if n == 0 {
                    return Err(
                        Error::new(ErrorKind::InvalidInput,
                                   "Reached EOF looking for Armor Header Line"));
                }
                if n > 128 {
                    input = &input[..128];
                }

                if input[0] == '-' as u8 {
                    // Possible ASCII-armor header.
                    if let Some(kind) = Kind::detect(&input) {
                        if self.kind == None {
                            // Found any!
                            self.kind = Some(kind);
                            break 'search kind.header_len();
                        }

                        if self.kind == Some(kind) {
                            // Found it!
                            break 'search kind.header_len();
                        }
                    }
                } else if ! self.strict {
                    // The user did not specify what kind of data she
                    // wants.  We aggressively try to decode any data,
                    // even if we do not see a valid header.
                    if is_armored_pgp_blob(input) {
                        found_blob = true;
                        break 'search 0;
                    }
                }
            }
        };
        self.source.consume(n);

        if found_blob {
            // Skip the rest of the initialization.
            self.initialized = true;
            return Ok(());
        }

        // We consumed the header above, but not any trailing
        // whitespace and the trailing new line.  We do that now.
        // Other data between the header and the new line are not
        // allowed.  But, instead of failing, we try to recover, by
        // stopping at the first non-whitespace character.
        let n = {
            let line = self.source.read_to('\n' as u8)?;
            line.iter().position(|&c| {
                !c.is_ascii_whitespace()
            }).unwrap_or(line.len())
        };
        self.source.consume(n);

        // Read the key-value headers.
        let mut n = 0;
        let mut lines = 0;
        loop {
            self.source.consume(n);

            let line = self.source.read_to('\n' as u8)?;
            n = line.len();
            lines += 1;

            let line = str::from_utf8(line);
            // Ignore---don't error out---lines that are not valid UTF8.
            if line.is_err() {
                continue;
            }

            let line = line.unwrap();

            // The line almost certainly ends with \n: the only reason
            // it couldn't is if we encountered EOF.  We need to strip
            // it.  But, if it ends with \r\n, then we also want to
            // strip the \r too.
            let line = if line.ends_with(&"\r\n"[..]) {
                // \r\n.
                &line[..line.len() - 2]
            } else if line.len() > 0 {
                // \n.
                &line[..line.len() - 1]
            } else {
                // EOF.
                line
            };

            /* Process headers.  */
            let key_value = line.splitn(2, ": ").collect::<Vec<&str>>();
            if key_value.len() == 1 {
                if line.trim_start().len() == 0 {
                    // Empty line.
                    break;
                } else if lines == 1 {
                    // This is the first line and we don't have a
                    // key-value pair.  It seems more likely that
                    // we're just missing a newline and this invalid
                    // header is actually part of the body.
                    n = 0;
                    break;
                }
            } else {
                let key = key_value[0];
                let value = key_value[1];

                self.headers.push((key.into(), value.into()));
            }
        }
        self.source.consume(n);

        self.initialized = true;
        Ok(())
    }

    /// Parses the footer.
    fn finalize(footer: &[u8], kind: Option<Kind>) -> Result<Option<u32>> {
        let mut off = 0;

        /* Look for CRC.  The CRC is optional.  */
        let crc = if footer.len() >= 6 && footer[0] == '=' as u8
            && footer[1..5].iter().all(is_base64_char)
        {
            /* Found.  */
            let crc = match base64::decode_config(&footer[1..5], base64::MIME) {
                Ok(d) => d,
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
            };

            assert_eq!(crc.len(), 3);
            let crc =
                (crc[0] as u32) << 16
                | (crc[1] as u32) << 8
                | crc[2] as u32;

            /* Update offset, skip whitespace.  */
            off += 5;
            while off < footer.len() && footer[off].is_ascii_whitespace() {
                off += 1;
            }

            Some(crc)
        } else {
            None
        };

        if let Some(kind) = kind {
            if ! footer[off..].starts_with(&kind.end().into_bytes()) {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid ASCII Armor footer."));
            }
        }

        Ok(crc)
    }
}

/// Checks whether the given bytes contain armored OpenPGP data.
fn is_armored_pgp_blob(bytes: &[u8]) -> bool {
    let bytes = if let Some(msg) = get_base64_prefix(bytes) {
        msg
    }  else {
        return false;
    };

    // We may need to drop some characters at the end.
    let mut end = bytes.len();
    loop {
        match base64::decode_config(&bytes[..end], base64::MIME) {
            Ok(d) => {
                // Don't consider an empty message to be valid.
                if d.len() == 0 {
                    break false;
                }
                let mut br = buffered_reader::Memory::new(&d);
                break if let Ok(header) = Header::parse(&mut br) {
                    header.ctb.tag.valid_start_of_message()
                        && header.valid(false).is_ok()
                } else {
                    false
                };
            },
            Err(_) =>
                if end == 0 {
                    break false;
                } else {
                    end -= 1;
                },
        }
    }
}

/// Gets a slice containing the largest valid base64 prefix.
fn get_base64_prefix(bytes: &[u8]) -> Option<&[u8]> {
    let mut seen_padding = false;
    for (i, c) in bytes.iter().enumerate() {
        if c.is_ascii_whitespace() {
            continue;
        }

        if seen_padding && *c != '=' as u8 {
            return Some(&bytes[..i]);
        }

        if *c == '=' as u8 {
            seen_padding = true;
        } else if ! is_base64_char(c) {
            if i == 0 {
                return None;
            } else {
                return Some(&bytes[..i]);
            }
        }
    }

    return Some(bytes);
}

/// Checks whether the given byte is in the base64 character set.
fn is_base64_char(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == '+' as u8 || *b == '/' as u8
}

/// Checks whether the given slice looks like an armor footer.  If so,
/// returns the size of the footer.
fn is_footer(buf: &[u8], reference: &[u8]) -> Option<usize> {
    if buf.len() < reference.len() {
        return None;
    }

    let mut off = 0;

    // Look for CRC.  The CRC is optional.
    if buf.len() >= 6 && buf[0] == '=' as u8
        && buf[1..5].iter().all(is_base64_char)
    {
        // Found.  Update offset, skip whitespace.
        off += 5;
        while off < buf.len() && buf[off].is_ascii_whitespace() {
            off += 1;
        }
    }

    if buf[off..].starts_with(reference) {
        Some(off + reference.len())
    } else {
        None
    }
}

/// Looks for the footer, returning the footer's offset, and the end
/// of the footer.
fn find_footer(buf: &[u8], kind: Kind) -> Option<(usize, usize)> {
    let reference = kind.end().into_bytes();

    if buf.len() < reference.len() {
        return None;
    }

    for i in 0..buf.len() - reference.len() {
        if let Some(length) = is_footer(&buf[i..], &reference) {
            // Found footer at offset i.
            return Some((i, i + length));
        }
    }
    None
}

impl<'a> Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.initialize()?;

        /* How much did we get?  */
        let mut read = 0;

        // First, use what we have in the buffer.
        let amount = min(buf.len(), self.buffer.len());
        &mut buf[..amount].copy_from_slice(&self.buffer[..amount]);
        self.buffer.drain(..amount);
        read += amount;

        // If we could satisfy the read from the buffer, we're done.
        if read == buf.len() {
            return Ok(read);
        }
        assert_eq!(self.buffer.len(), 0);

        // Our buffer is drained.  If we are finalized, nothing more
        // can be read.
        if self.finalized {
            return Ok(read);
        }

        let (consumed, decoded) = {
            // Try to get enough bytes to fill buf, account for bytes
            // filled using our buffer, round up, and add enough for
            // the footer.
            //
            // Later, we may have to get some more until we have a
            // multiple of four non-whitespace ASCII characters.
            let mut want = (buf.len() - read + 2) / 3 * 4
                + self.kind.map(|k| k.footer_max_len()).unwrap_or(46);

            // Keep track of how much we got last time to detect
            // hitting EOF.
            let mut got = 0;

            'readloop: loop {
                let raw = self.source.data(want)?;
                if raw.len() == got {
                    // EOF.  Decide how to proceed.

                    if self.strict {
                        // If we are here, we should have seen an
                        // footer by now.
                        return Err(Error::new(ErrorKind::UnexpectedEof,
                                              "Armor footer is missing"));
                    } else {
                        // Otherwise, we may have found only the blob,
                        // or the footer is damaged, or missing.  Try
                        // to decode what we have got, then we are
                        // done.

                        // We need to try to discard garbage at the end.
                        let mut end = min(raw.len(), want);
                        loop {
                            match base64::decode_config(&raw[..end],
                                                        base64::MIME) {
                                Ok(d) => break 'readloop (end, d),
                                Err(_) =>
                                    if end == 0 {
                                        // No more valid data.
                                        break 'readloop (raw.len(), vec![]);
                                    } else {
                                        end -= 1;
                                    },
                            }
                        }
                    }
                } else {
                    got = raw.len();
                }

                // Check if we see the footer.  If so, we're almost done.
                if let Some(kind) = self.kind {
                    if let Some((n, end)) = find_footer(&raw, kind) {
                        self.expect_crc = Reader::finalize(&raw[n..], self.kind)?;
                        self.finalized = true;
                        match base64::decode_config(&raw[..n], base64::MIME) {
                            Ok(d) => break (end, d),
                            Err(e) =>
                                return Err(Error::new(ErrorKind::InvalidInput, e)),
                        }
                    }
                }

                // See how many valid characters we got.
                let n = &raw.iter().filter(
                    |c| ! (**c).is_ascii_whitespace()).count();
                if n % 4 == 0 {
                    // Enough!  Try to decode them.

                    // We need to try to discard garbage at the end.
                    let mut end = raw.len();
                    loop {
                        match base64::decode_config(&raw[..end],
                                                    base64::MIME) {
                            Ok(d) => break 'readloop (end, d),
                            Err(_) =>
                                if end == 0 {
                                    // No more valid data.
                                    break 'readloop (raw.len(), vec![]);
                                } else {
                                    end -= 1;
                                },
                        }
                    }
                }

                // Otherwise, get some more bytes.
                want = got + 4 - n % 4;
            }
        };
        self.source.consume(consumed);
        self.crc.update(&decoded);

        /* Check how much we got vs how much was requested.  */
        if decoded.len() <= (buf.len() - read) {
            &mut buf[read..read + decoded.len()].copy_from_slice(&decoded);
            read += decoded.len();
        } else {
            // We got more than we wanted, spill the surplus into our
            // buffer.
            let spill = decoded.len() - (buf.len() - read);

            &mut buf[read..read + decoded.len() - spill].copy_from_slice(
                &decoded[..decoded.len() - spill]);
            read += decoded.len() - spill;

            self.buffer.extend_from_slice(&decoded[decoded.len() - spill..]);
        }

        /* If we are finalized, we may have found a crc sum.  */
        if let Some(crc) = self.expect_crc {
            if self.crc.finalize() != crc {
                return Err(Error::new(ErrorKind::InvalidInput, "Bad CRC sum."));
            }
        }
        Ok(read)
    }
}

// XXX: impl BufferedReader for Reader

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

struct CRC {
    n: u32,
}

/// Computess the CRC-24, (see [RFC 4880, section 6.1]).
///
/// [RFC 4880, section 6.1]: https://tools.ietf.org/html/rfc4880#section-6.1
impl CRC {
    fn new() -> Self {
        CRC { n: CRC24_INIT }
    }

    fn update(&mut self, buf: &[u8]) -> &Self {
        for octet in buf {
            self.n ^= (*octet as u32) << 16;
            for _ in 0..8 {
                self.n <<= 1;
                if self.n & 0x1000000 > 0 {
                    self.n ^= CRC24_POLY;
                }
            }
        }
        self
    }

    fn finalize(&self) -> u32 {
        self.n & 0xFFFFFF
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;
    use super::CRC;
    use super::Kind;
    use super::Writer;

    #[test]
    fn crc() {
        let b = b"foobarbaz";
        let crcs = [
            0xb704ce,
            0x6d2804,
            0xa2d10d,
            0x4fc255,
            0x7aafca,
            0xc79c46,
            0x7334de,
            0x77dc72,
            0x000f65,
            0xf40d86,
        ];

        for len in 0..b.len() + 1 {
            assert_eq!(CRC::new().update(&b[..len]).finalize(), crcs[len]);
        }
    }

    use std::fs::File;
    use std::io::prelude::*;

    const TEST_VECTORS: [u8; 9] = [0, 1, 2, 3, 47, 48, 49, 50, 51];

    #[test]
    fn enarmor() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let mut asc = Vec::<u8>::new();
            file.read_to_end(&mut asc).unwrap();

            let mut buf = Vec::new();
            {
                let mut w = Writer::new(&mut buf, Kind::File, &[]).unwrap();
                w.write(&[]).unwrap();  // Avoid zero-length optimization.
                w.write_all(&bin).unwrap();
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(&asc));
        }
    }

    #[test]
    fn enarmor_bytewise() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let mut asc = Vec::<u8>::new();
            file.read_to_end(&mut asc).unwrap();

            let mut buf = Vec::new();
            {
                let mut w = Writer::new(&mut buf, Kind::File, &[]).unwrap();
                w.write(&[]).unwrap();  // Avoid zero-length optimization.
                for (i, _) in bin.iter().enumerate() {
                    w.write(&bin[i..i+1]).unwrap();
                }
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(&asc));
        }
    }

    #[test]
    fn drop_writer() {
        // No ASCII frame shall be emitted if the writer is dropped
        // unused.
        let mut buf = Vec::new();
        {
            drop(Writer::new(&mut buf, Kind::File, &[]).unwrap());
        }
        assert!(buf.is_empty());

        // However, if the user insists, we will encode a zero-byte
        // string.
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf, Kind::File, &[]).unwrap();
            w.write(&[]).unwrap();
        }
        assert_eq!(
            &buf[..],
            &b"-----BEGIN PGP ARMORED FILE-----\n\
               \n\
               =twTO\n\
               -----END PGP ARMORED FILE-----\n"[..]);
    }

    use super::Reader;

    #[test]
    fn dearmor_robust() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/literal-{}.bin",
                                              len)).unwrap();
            let mut reference = Vec::<u8>::new();
            file.read_to_end(&mut reference).unwrap();

            for test in &["", "-no-header-with-chksum", "-no-header",
                          "-no-newlines"] {
                let filename = format!("tests/data/armor/literal-{}{}.asc",
                                       len, test);
                let mut file = File::open(filename).unwrap();
                let mut r = Reader::new(&mut file, None);
                let mut dearmored = Vec::<u8>::new();
                r.read_to_end(&mut dearmored).unwrap();

                assert_eq!(&reference, &dearmored);
            }
        }
    }

    #[test]
    fn dearmor_binary() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut r = Reader::new(&mut file, Some(Kind::Message));
            let mut buf = [0; 5];
            let e = r.read(&mut buf);
            assert!(e.is_err());
        }
    }

    #[test]
    fn dearmor_wrong_kind() {
        let mut file = File::open("tests/data/armor/test-0.asc").unwrap();
        let mut r = Reader::new(&mut file, Some(Kind::Message));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_crc() {
        let mut file = File::open("tests/data/armor/test-0.bad-crc.asc").unwrap();
        let mut r = Reader::new(&mut file, Some(Kind::File));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_footer() {
        let mut file = File::open("tests/data/armor/test-2.bad-footer.asc").unwrap();
        let mut r = Reader::new(&mut file, Some(Kind::File));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_no_crc() {
        let mut file = File::open("tests/data/armor/test-1.no-crc.asc").unwrap();
        let mut r = Reader::new(&mut file, Some(Kind::File));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.unwrap() == 1 && buf[0] == 0xde);
    }

    #[test]
    fn dearmor_with_header() {
        let mut file = File::open("tests/data/armor/test-3.with-headers.asc").unwrap();
        let mut r = Reader::new(&mut file, Some(Kind::File));
        assert_eq!(r.headers().unwrap(),
                   &[("Comment".into(), "Some Header".into()),
                     ("Comment".into(), "Another one".into())]);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_any() {
        let mut file = File::open("tests/data/armor/test-3.with-headers.asc").unwrap();
        let mut r = Reader::new(&mut file, None);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(r.kind() == Some(Kind::File));
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_with_garbage() {
        use std::io::Cursor;

        // Get some valid data.
        let mut armored = Vec::new();
        File::open("tests/data/armor/test-3.with-headers.asc")
            .unwrap()
            .read_to_end(&mut armored)
            .unwrap();

        // Slap some garbage in front and make sure it still reads ok.
        let mut garbage = Vec::new();
        write!(&mut garbage, "Some\ngarbage\nlines\n\t\r  ").unwrap();
        garbage.extend_from_slice(&armored);

        let mut r = Reader::new(Cursor::new(&garbage), None);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(r.kind() == Some(Kind::File));
        assert!(e.is_ok());

        // Again, but this time add a non-whitespace character in the
        // line of the header.
        let mut garbage = Vec::new();
        write!(&mut garbage, "Some\ngarbage\nlines\n\t.\r  ").unwrap();
        garbage.extend_from_slice(&armored);

        let mut r = Reader::new(Cursor::new(&garbage), None);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let mut r = Reader::new(&mut file, Some(Kind::File));
            let mut dearmored = Vec::<u8>::new();
            r.read_to_end(&mut dearmored).unwrap();

            assert_eq!(&bin, &dearmored);
        }
    }

    #[test]
    fn dearmor_bytewise() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let r = Reader::new(&mut file, Some(Kind::File));
            let mut dearmored = Vec::<u8>::new();
            for c in r.bytes() {
                dearmored.push(c.unwrap());
            }

            assert_eq!(&bin, &dearmored);
        }
    }

    #[test]
    fn dearmor_yuge() {
        let mut file =
            File::open("tests/data/keys/yuge-key-so-yuge-the-yugest.asc")
            .unwrap();
        let mut r = Reader::new(&mut file, None);
        let mut dearmored = Vec::<u8>::new();
        r.read_to_end(&mut dearmored).unwrap();

        let mut file =
            File::open("tests/data/keys/yuge-key-so-yuge-the-yugest.asc")
            .unwrap();
        let r = Reader::new(&mut file, None);
        let mut dearmored = Vec::<u8>::new();
        for c in r.bytes() {
            dearmored.push(c.unwrap());
        }
    }

    quickcheck! {
        fn roundtrip(kind: Kind, payload: Vec<u8>) -> bool {
            use std::io::Cursor;

            if payload.is_empty() {
                // Empty payloads do not emit an armor framing unless
                // one does an explicit empty write (and .write_all()
                // does not).
                return true;
            }

            let mut encoded = Vec::new();
            Writer::new(&mut encoded, kind, &[]).unwrap()
                .write_all(&payload)
                .unwrap();

            let mut recovered = Vec::new();
            Reader::new(Cursor::new(&encoded), Some(kind))
                .read_to_end(&mut recovered)
                .unwrap();

            let mut recovered_any = Vec::new();
            Reader::new(Cursor::new(&encoded), None)
                .read_to_end(&mut recovered_any)
                .unwrap();

            payload == recovered && payload == recovered_any
        }
    }
}
