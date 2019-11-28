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
//! use openpgp::armor::{Reader, ReaderMode, Kind};
//!
//! let mut file = File::open("somefile.asc").unwrap();
//! let mut r = Reader::new(&mut file, ReaderMode::Tolerant(Some(Kind::File)));
//! ```

extern crate base64;
use buffered_reader::BufferedReader;
use std::io::{Cursor, Read, Write};
use std::io::{Result, Error, ErrorKind};
use std::path::Path;
use std::cmp;
use std::str;
use std::borrow::Cow;
use quickcheck::{Arbitrary, Gen};

use crate::vec_truncate;
use crate::packet::prelude::*;
use crate::packet::header::BodyLength;
use crate::packet::header::ctb::{CTBNew, CTBOld};
use crate::serialize::SerializeInto;

/// The encoded output stream must be represented in lines of no more
/// than 76 characters each (see (see [RFC 4880, section
/// 6.3](https://tools.ietf.org/html/rfc4880#section-6.3).  GnuPG uses
/// 64.
pub(crate) const LINE_LENGTH: usize = 64;

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
    /// A certificate.
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
}

/// A filter that applies ASCII Armor to the data written to it.
pub struct Writer<W: Write> {
    sink: Option<W>,
    kind: Kind,
    stash: Vec<u8>,
    column: usize,
    crc: CRC,
    header: Vec<u8>,
    dirty: bool,
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
            sink: Some(inner),
            kind: kind,
            stash: Vec::<u8>::with_capacity(2),
            column: 0,
            crc: CRC::new(),
            header: Vec::with_capacity(128),
            dirty: false,
        };

        {
            let mut cur = Cursor::new(&mut w.header);
            write!(&mut cur, "{}{}", kind.begin(), LINE_ENDING)?;

            for h in headers {
                write!(&mut cur, "{}: {}{}", h.0, h.1, LINE_ENDING)?;
            }

            // A blank line separates the headers from the body.
            write!(&mut cur, "{}", LINE_ENDING)?;
        }

        Ok(w)
    }

    fn e_finalized() -> Error {
        Error::new(ErrorKind::BrokenPipe, "Writer is finalized.")
    }

    fn finalize_headers(&mut self) -> Result<()> {
        if ! self.dirty {
            self.dirty = true;
            self.sink.as_mut().ok_or_else(Self::e_finalized)?
                .write_all(&self.header)?;
            // Release memory.
            crate::vec_truncate(&mut self.header, 0);
            self.header.shrink_to_fit();
        }
        Ok(())
    }

    /// Writes the footer.
    ///
    /// No more data can be written after this call.  If this is not
    /// called explicitly, the footer is written once the writer is
    /// dropped.
    pub fn finalize(mut self) -> Result<W> {
        if ! self.dirty {
            // No data was written to us, don't emit anything.
            return Ok(self.sink.take().ok_or_else(Self::e_finalized)?);
        }
        self.finalize_armor()?;
        if let Some(sink) = self.sink.take() {
            Ok(sink)
        } else {
            Err(Self::e_finalized())
        }
    }

    /// Writes the footer.
    fn finalize_armor(&mut self) -> Result<()> {
        if ! self.dirty {
            // No data was written to us, don't emit anything.
            return Ok(());
        }
        self.finalize_headers()?;
        if let Some(sink) = self.sink.as_mut() {
            // Write any stashed bytes and pad.
            if self.stash.len() > 0 {
                sink.write_all(base64::encode_config(
                    &self.stash, base64::STANDARD).as_bytes())?;
                self.column += 4;
            }

            // Inserts a line break if necessary.
            //
            // Unfortunately, we cannot use
            //self.linebreak()?;
            //
            // Therefore, we inline it here.  This is a bit sad.
            assert!(self.column <= LINE_LENGTH);
            if self.column == LINE_LENGTH {
                write!(sink, "{}", LINE_ENDING)?;
                self.column = 0;
            }

            if self.column > 0 {
                write!(sink, "{}", LINE_ENDING)?;
            }

            let crc = self.crc.finalize();
            let bytes: [u8; 3] = [
                (crc >> 16) as u8,
                (crc >>  8) as u8,
                (crc >>  0) as u8,
            ];

            // CRC and footer.
            write!(sink, "={}{}{}{}",
                   base64::encode_config(&bytes, base64::STANDARD_NO_PAD),
                   LINE_ENDING, self.kind.end(), LINE_ENDING)?;

            Ok(())
        } else {
            Err(Self::e_finalized())
        }
    }

    /// Inserts a line break if necessary.
    fn linebreak(&mut self) -> Result<()> {
        assert!(self.column <= LINE_LENGTH);
        if self.column == LINE_LENGTH {
            write!(self.sink.as_mut().ok_or_else(Self::e_finalized)?,
                   "{}", LINE_ENDING)?;
            self.column = 0;
        }
        Ok(())
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.finalize_headers()?;

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
            self.sink.as_mut().ok_or_else(Self::e_finalized)?
                .write_all(base64::encode_config(
                    &self.stash, base64::STANDARD_NO_PAD).as_bytes())?;
            self.column += 4;
            self.linebreak()?;
            crate::vec_truncate(&mut self.stash, 0);
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
            let n = cmp::min(LINE_LENGTH - self.column, enc.len());
            self.sink.as_mut().ok_or_else(Self::e_finalized)?
                .write_all(&enc[..n])?;
            enc = &enc[n..];
            self.column += n;
            self.linebreak()?;
        }

        assert_eq!(written, buf.len());
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.sink.as_mut().ok_or_else(Self::e_finalized)?.flush()
    }
}

impl<W: Write> Drop for Writer<W> {
    fn drop(&mut self) {
        let _ = self.finalize_armor();
    }
}

/// How an ArmorReader should act.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReaderMode {
    /// Makes the armor reader tolerant of simple errors.
    ///
    /// The armor reader will be tolerant of common formatting errors,
    /// such as incorrect line folding, but the armor header line
    /// (e.g., `----- BEGIN PGP MESSAGE -----`) and the footer must be
    /// intact.
    ///
    /// If a Kind is specified, then only ASCII Armor blocks with the
    /// appropriate header are recognized.
    ///
    /// This mode is appropriate when reading from a file.
    Tolerant(Option<Kind>),

    /// Makes the armor reader very tolerant of errors.
    ///
    /// Unlike in `Tolerant` mode, in this mode, the armor reader
    /// doesn't require an armor header line.  Instead, it examines
    /// chunks that look like valid base64 data, and attempts to parse
    /// them.
    ///
    /// Although this mode looks for OpenPGP fingerprints before
    /// invoking the full parser, due to the number of false
    /// positives, this mode of operation is CPU intense, particularly
    /// on large text files.  It is primarily appropriate when reading
    /// text that the user cut and pasted into a text area.
    VeryTolerant,
}

/// A filter that strips ASCII Armor from a stream of data.
pub struct Reader<'a> {
    source: Box<dyn BufferedReader<()> + 'a>,
    kind: Option<Kind>,
    mode: ReaderMode,
    buffer: Vec<u8>,
    crc: CRC,
    expect_crc: Option<u32>,
    initialized: bool,
    headers: Vec<(String, String)>,
    finalized: bool,
    prefix_len: usize,
    prefix_remaining: usize,
}

impl Default for ReaderMode {
    fn default() -> Self {
        ReaderMode::Tolerant(None)
    }
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
    /// the line the header is only prefixed by whitespace.
    ///
    ///   [ASCII Armor]: https://tools.ietf.org/html/rfc4880#section-6.2
    ///
    /// # Example
    ///
    /// ```
    /// # use std::io::Read;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::{Result, Message};
    /// # use openpgp::armor::{Reader, ReaderMode};
    /// # use openpgp::parse::Parse;
    /// # use std::io;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let data = "yxJiAAAAAABIZWxsbyB3b3JsZCE="; // base64 over literal data packet
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, ReaderMode::VeryTolerant);
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
    /// # use openpgp::armor::{Reader, ReaderMode, Kind};
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
    /// let mut reader = Reader::new(&mut cursor, ReaderMode::Tolerant(Some(Kind::File)));
    ///
    /// let mut content = String::new();
    /// reader.read_to_string(&mut content)?;
    /// assert_eq!(content, "Hello world!");
    /// assert_eq!(reader.kind(), Some(Kind::File));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<R, M>(inner: R, mode: M) -> Self
        where R: 'a + Read,
              M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::new(inner, None)),
            mode)
    }

    /// Creates a `Reader` from an `io::Read`er.
    pub fn from_reader<R, M>(reader: R, mode: M) -> Self
        where R: 'a + Read,
              M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::new(reader, None)),
            mode)
    }

    /// Creates a `Reader` from a file.
    pub fn from_file<P, M>(path: P, mode: M) -> Result<Self>
        where P: AsRef<Path>,
              M: Into<Option<ReaderMode>>
    {
        Ok(Self::from_buffered_reader(
            Box::new(buffered_reader::File::open(path)?),
            mode))
    }

    /// Creates a `Reader` from a buffer.
    pub fn from_bytes<M>(bytes: &'a [u8], mode: M) -> Self
        where M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Memory::new(bytes)),
            mode)
    }

    pub(crate) fn from_buffered_reader<C: 'a, M>(
        inner: Box<dyn BufferedReader<C> + 'a>, mode: M) -> Self
        where M: Into<Option<ReaderMode>>
    {
        let mode = mode.into().unwrap_or(Default::default());

        Reader {
            source: Box::new(buffered_reader::Generic::new(inner, None)),
            kind: None,
            mode: mode,
            buffer: Vec::<u8>::with_capacity(1024),
            crc: CRC::new(),
            expect_crc: None,
            headers: Vec::new(),
            initialized: false,
            finalized: false,
            prefix_len: 0,
            prefix_remaining: 0,
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
                    base64::encode_config_slice(&ctb[..], base64::STANDARD, &mut o[..]);
                    valid_start.push(o[0]);

                    CTBOld::new(tag, BodyLength::Full(0)).unwrap()
                        .serialize_into(&mut ctb[..]).unwrap();
                    base64::encode_config_slice(&ctb[..], base64::STANDARD, &mut o[..]);
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
        let start_chars = if self.mode != ReaderMode::VeryTolerant {
            &[b'-'][..]
        } else {
            &START_CHARS[..]
        };

        let mut lines = 0;
        let mut prefix = Vec::new();
        let n = 'search: loop {
            if lines > 0 {
                // Find the start of the next line.
                self.source.drop_through(&[b'\n'], true)?;
                crate::vec_truncate(&mut prefix, 0);
            }
            lines += 1;

            // Ignore leading whitespace, etc.
            while match self.source.data_hard(1)?[0] {
                // Skip some whitespace (previously .is_ascii_whitespace())
                b' ' | b'\t' | b'\r' | b'\n' => true,
                // Also skip common quote characters
                b'>' | b'|' | b']' | b'}' => true,
                // Do not skip anything else
                _ => false,
            } {
                let c = self.source.data(1)?[0];
                if c == b'\n' {
                    // We found a newline while walking whitespace, reset prefix
                    crate::vec_truncate(&mut prefix, 0);
                } else {
                    prefix.push(self.source.data_hard(1)?[0]);
                }
                self.source.consume(1);
            }

            // Don't bother if the first byte is not plausible.
            let start = self.source.data_hard(1)?[0];
            if !start_chars.binary_search(&start).is_ok()
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
                        let mut expected_kind = None;
                        if let ReaderMode::Tolerant(Some(kind)) = self.mode {
                            expected_kind = Some(kind);
                        }

                        if expected_kind == None {
                            // Found any!
                            self.kind = Some(kind);
                            break 'search kind.header_len();
                        }

                        if expected_kind == Some(kind) {
                            // Found it!
                            self.kind = Some(kind);
                            break 'search kind.header_len();
                        }
                    }
                } else if self.mode == ReaderMode::VeryTolerant {
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
            self.prefix_len = prefix.len();
            self.prefix_remaining = prefix.len();
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

        let next_prefix = &self.source.data_hard(prefix.len())?[..prefix.len()];
        if prefix != next_prefix {
            // If the next line doesn't start with the same prefix, we assume
            // it was garbage on the front and drop the prefix so long as it
            // was purely whitespace.  Any non-whitespace remains an error
            // while searching for the armor header if it's not repeated.
            if prefix.iter().all(|b| (*b as char).is_ascii_whitespace()) {
                crate::vec_truncate(&mut prefix, 0);
            } else {
                // Nope, we have actually failed to read this properly
                return Err(
                    Error::new(ErrorKind::InvalidInput,
                               "Reached EOF looking for Armor Header Line"));
            }
        }

        // Read the key-value headers.
        let mut n = 0;
        let mut lines = 0;
        loop {
            // Skip any known prefix on lines
            self.source.consume(prefix.len());

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
        self.prefix_len = prefix.len();
        self.prefix_remaining = prefix.len();
        Ok(())
    }
}

// Remove whitespace, etc. from the base64 data.
//
// This function returns the filtered base64 data (i.e., stripped of
// all skipable data like whitespace), and the amount of unfiltered
// data that corresponds to.  Thus, if we have the following 7 bytes:
//
//     ab  cde
//     0123456
//
// This function returns ("abcd", 6), because the 'd' is the last
// character in the last complete base64 chunk, and it is at offset 5.
//
// If 'd' is follow by whitespace, it is undefined whether that
// whitespace is included in the count.
//
// This function only returns full chunks of base64 data.  As a
// consequence, if base64_data_max is less than 4, then this will not
// return any data.
//
// This function will stop after it sees base64 padding, and if it
// sees invalid base64 data.
fn base64_filter(mut bytes: Cow<[u8]>, base64_data_max: usize,
                 mut prefix_remaining: usize, prefix_len: usize)
    -> (Cow<[u8]>, usize, usize)
{
    let mut leading_whitespace = 0;

    // Round down to the nearest chunk size.
    let base64_data_max = base64_data_max / 4 * 4;

    // Number of bytes of base64 data.  Since we update `bytes` in
    // place, the base64 data is `&bytes[..base64_len]`.
    let mut base64_len = 0;

    // Offset of the next byte of unfiltered data to process.
    let mut unfiltered_offset = 0;

    // Offset of the last byte of the last ***complete*** base64 chunk
    // in the unfiltered data.
    let mut unfiltered_complete_len = 0;

    // Number of bytes of padding that we've seen so far.
    let mut padding = 0;

    while unfiltered_offset < bytes.len()
        && base64_len < base64_data_max
        // A valid base64 chunk never starts with padding.
        && ! (padding > 0 && base64_len % 4 == 0)
    {
        // If we have some prefix to skip, skip it.
        if prefix_remaining > 0 {
            prefix_remaining -= 1;
            if unfiltered_offset == 0 {
                match bytes {
                    Cow::Borrowed(s) => {
                        // We're at the beginning.  Avoid moving
                        // data by cutting off the start of the
                        // slice.
                        bytes = Cow::Borrowed(&s[1..]);
                        leading_whitespace += 1;
                        continue;
                    }
                    Cow::Owned(_) => (),
                }
            }
            unfiltered_offset += 1;
            continue;
        }
        match bytes[unfiltered_offset] {
            // White space.
            c if c.is_ascii_whitespace() => {
                if c == b'\n' {
                    prefix_remaining = prefix_len;
                }
                if unfiltered_offset == 0 {
                    match bytes {
                        Cow::Borrowed(s) => {
                            // We're at the beginning.  Avoid moving
                            // data by cutting off the start of the
                            // slice.
                            bytes = Cow::Borrowed(&s[1..]);
                            leading_whitespace += 1;
                            continue;
                        }
                        Cow::Owned(_) => (),
                    }
                }
            }

            // Padding.
            b'=' => {
                if padding == 2 {
                    // There can never be more than two bytes of
                    // padding.
                    break;
                }
                if base64_len % 4 == 0 {
                    // Padding can never occur at the start of a
                    // base64 chunk.
                    break;
                }

                if unfiltered_offset != base64_len {
                    bytes.to_mut()[base64_len] = b'=';
                }
                base64_len += 1;
                if base64_len % 4 == 0 {
                    unfiltered_complete_len = unfiltered_offset + 1;
                }
                padding += 1;
            }

            // The only thing that can occur after padding is
            // whitespace or padding.  Those cases were covered above.
            _ if padding > 0 => break,

            // Base64 data!
            b if is_base64_char(&b) => {
                if unfiltered_offset != base64_len {
                    bytes.to_mut()[base64_len] = b;
                }
                base64_len += 1;
                if base64_len % 4 == 0 {
                    unfiltered_complete_len = unfiltered_offset + 1;
                }
            }

            // Not base64 data.
            _ => break,
        }

        unfiltered_offset += 1;
    }

    let base64_len = base64_len - (base64_len % 4);
    unfiltered_complete_len += leading_whitespace;
    match bytes {
        Cow::Borrowed(s) =>
            (Cow::Borrowed(&s[..base64_len]), unfiltered_complete_len,
             prefix_remaining),
        Cow::Owned(mut v) => {
            vec_truncate(&mut v, base64_len);
            (Cow::Owned(v), unfiltered_complete_len, prefix_remaining)
        }
    }
}

/// Checks whether the given bytes contain armored OpenPGP data.
fn is_armored_pgp_blob(bytes: &[u8]) -> bool {
    // Get up to 32 bytes of base64 data.  That's 24 bytes of data
    // (ignoring padding), which is more than enough to get the first
    // packet's header.
    let (bytes, _, _) = base64_filter(Cow::Borrowed(bytes), 32, 0, 0);

    match base64::decode_config(&bytes, base64::STANDARD) {
        Ok(d) => {
            // Don't consider an empty message to be valid.
            if d.len() == 0 {
                false
            } else {
                let mut br = buffered_reader::Memory::new(&d);
                if let Ok(header) = Header::parse(&mut br) {
                    header.ctb().tag().valid_start_of_message()
                        && header.valid(false).is_ok()
                } else {
                    false
                }
            }
        },
        Err(_err) => false,
    }
}

/// Checks whether the given byte is in the base64 character set.
fn is_base64_char(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == '+' as u8 || *b == '/' as u8
}

/// Returns the number of bytes of base64 data are needed to encode
/// `s` bytes of raw data.
fn base64_size(s: usize) -> usize {
    (s + 3 - 1) / 3 * 4
}

#[test]
fn base64_size_test() {
    assert_eq!(base64_size(0), 0);
    assert_eq!(base64_size(1), 4);
    assert_eq!(base64_size(2), 4);
    assert_eq!(base64_size(3), 4);
    assert_eq!(base64_size(4), 8);
    assert_eq!(base64_size(5), 8);
    assert_eq!(base64_size(6), 8);
    assert_eq!(base64_size(7), 12);
}

impl<'a> Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if ! self.initialized {
            self.initialize()?;
        }

        if self.finalized {
            assert_eq!(self.buffer.len(), 0);
            return Ok(0);
        }

        let (consumed, decoded) = if self.buffer.len() > 0 {
            // We have something buffered, use that.

            let amount = cmp::min(buf.len(), self.buffer.len());
            buf[..amount].copy_from_slice(&self.buffer[..amount]);
            self.buffer.drain(..amount);

            (0, amount)
        } else {
            // We need to decode some data.  We consider three cases,
            // all a function of the size of `buf`:
            //
            //   - Tiny: if `buf` can hold less than three bytes, then
            //     we almost certainly have to double buffer: except
            //     at the very end, a base64 chunk consists of 3 bytes
            //     of data.
            //
            //     Note: this happens if the caller does `for c in
            //     Reader::new(...).bytes() ...`.  Then it reads one
            //     byte of decoded data at a time.
            //
            //   - Small: if the caller only requests a few bytes at a
            //     time, we may as well double buffer to reduce
            //     decoding overhead.
            //
            //   - Large: if `buf` is large, we can decode directly
            //     into `buf` and avoid double buffering.  But,
            //     because we ignore whitespace, it is hard to
            //     determine exactly how much data to read to
            //     maximally fill `buf`.

            // We use 64, because ASCII-armor text usually contains 64
            // characters of base64 data per line, and this prevents
            // turning the borrow into an own.
            const THRESHOLD : usize = 64;

            let to_read =
                cmp::max(
                    // Tiny or small:
                    THRESHOLD + 2,

                    // Large: a heuristic:

                    base64_size(buf.len())
                    // Assume about 2 bytes of whitespace (crlf) per
                    // 64 character line.
                        + 2 * ((buf.len() + 63) / 64));

            let base64data = self.source.data(to_read)?;
            let base64data = if base64data.len() > to_read {
                &base64data[..to_read]
            } else {
                base64data
            };

            let (base64data, consumed, prefix_remaining)
                = base64_filter(Cow::Borrowed(base64data),
                                // base64_size rounds up, but we want
                                // to round down as we have to double
                                // buffer partial chunks.
                                cmp::max(THRESHOLD, buf.len() / 3 * 4),
                                self.prefix_remaining,
                                self.prefix_len);

            // We shouldn't have any partial chunks.
            assert_eq!(base64data.len() % 4, 0);

            let decoded = if base64data.len() / 4 * 3 > buf.len() {
                // We need to double buffer.  Decode into a vector.
                // (Note: the computed size *might* be a slight
                // overestimate, because the last base64 chunk may
                // include padding.)
                self.buffer = base64::decode_config(
                    &base64data, base64::STANDARD)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

                self.crc.update(&self.buffer);

                let copied = cmp::min(buf.len(), self.buffer.len());
                buf[..copied].copy_from_slice(&self.buffer[..copied]);
                self.buffer.drain(..copied);

                copied
            } else {
                // We can decode directly into the caller-supplied
                // buffer.
                let decoded = base64::decode_config_slice(
                    &base64data, base64::STANDARD, buf)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

                self.crc.update(&buf[..decoded]);

                decoded
            };

            self.prefix_remaining = prefix_remaining;

            (consumed, decoded)
        };

        self.source.consume(consumed);
        if decoded == 0 {
            self.finalized = true;

            /* Look for CRC.  The CRC is optional.  */
            let consumed = {
                // Skip whitespace.
                while self.source.data(1)?.len() > 0
                    && self.source.buffer()[0].is_ascii_whitespace()
                {
                    self.source.consume(1);
                }

                let data = self.source.data(5)?;
                let data = if data.len() > 5 {
                    &data[..5]
                } else {
                    data
                };

                if data.len() == 5
                    && data[0] == '=' as u8
                    && data[1..5].iter().all(is_base64_char)
                {
                    /* Found.  */
                    let crc = match base64::decode_config(
                        &data[1..5], base64::STANDARD)
                    {
                        Ok(d) => d,
                        Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
                    };

                    assert_eq!(crc.len(), 3);
                    let crc =
                        (crc[0] as u32) << 16
                        | (crc[1] as u32) << 8
                        | crc[2] as u32;

                    self.expect_crc = Some(crc);
                    5
                } else {
                    0
                }
            };
            self.source.consume(consumed);

            // Skip any expected prefix
            self.source.consume(self.prefix_len);
            // Look for a footer.
            let consumed = {
                // Skip whitespace.
                while self.source.data(1)?.len() > 0
                    && self.source.buffer()[0].is_ascii_whitespace()
                {
                    self.source.consume(1);
                }

                // If we had a header, we require a footer.
                if let Some(kind) = self.kind {
                    let footer = kind.end();
                    let got = self.source.data(footer.len())?;
                    let got = if got.len() > footer.len() {
                        &got[..footer.len()]
                    } else {
                        got
                    };
                    if footer.as_bytes() != got {
                        return Err(Error::new(ErrorKind::InvalidInput,
                                              "Invalid ASCII Armor footer."));
                    }

                    footer.len()
                } else {
                    0
                }
            };
            self.source.consume(consumed);

            if let Some(crc) = self.expect_crc {
                if self.crc.finalize() != crc {
                    return Err(Error::new(ErrorKind::InvalidInput,
                                          "Bad CRC sum."));
                }
            }
        }

        Ok(decoded)
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
    use std::io::{Cursor, Read, Write};
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

    macro_rules! t {
        ( $path: expr ) => {
            include_bytes!(concat!("../tests/data/armor/", $path))
        }
    }
    macro_rules! vectors {
        ( $prefix: expr, $suffix: expr ) => {
            &[t!(concat!($prefix, "-0", $suffix)),
              t!(concat!($prefix, "-1", $suffix)),
              t!(concat!($prefix, "-2", $suffix)),
              t!(concat!($prefix, "-3", $suffix)),
              t!(concat!($prefix, "-47", $suffix)),
              t!(concat!($prefix, "-48", $suffix)),
              t!(concat!($prefix, "-49", $suffix)),
              t!(concat!($prefix, "-50", $suffix)),
              t!(concat!($prefix, "-51", $suffix))]
        }
    }

    const TEST_BIN: &[&[u8]] = vectors!("test", ".bin");
    const TEST_ASC: &[&[u8]] = vectors!("test", ".asc");
    const LITERAL_BIN: &[&[u8]] = vectors!("literal", ".bin");
    const LITERAL_ASC: &[&[u8]] = vectors!("literal", ".asc");
    const LITERAL_NO_HEADER_ASC: &[&[u8]] =
        vectors!("literal", "-no-header.asc");
    const LITERAL_NO_HEADER_WITH_CHKSUM_ASC: &[&[u8]] =
        vectors!("literal", "-no-header-with-chksum.asc");
    const LITERAL_NO_NEWLINES_ASC: &[&[u8]] =
        vectors!("literal", "-no-newlines.asc");

    #[test]
    fn enarmor() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut buf = Vec::new();
            {
                let mut w = Writer::new(&mut buf, Kind::File, &[]).unwrap();
                w.write(&[]).unwrap();  // Avoid zero-length optimization.
                w.write_all(bin).unwrap();
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(asc));
        }
    }

    #[test]
    fn enarmor_bytewise() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut buf = Vec::new();
            {
                let mut w = Writer::new(&mut buf, Kind::File, &[]).unwrap();
                w.write(&[]).unwrap();  // Avoid zero-length optimization.
                for b in bin.iter() {
                    w.write(&[*b]).unwrap();
                }
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(asc));
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

    use super::{Reader, ReaderMode};

    #[test]
    fn dearmor_robust() {
        for (i, reference) in LITERAL_BIN.iter().enumerate() {
            for test in &[LITERAL_ASC[i],
                          LITERAL_NO_HEADER_WITH_CHKSUM_ASC[i],
                          LITERAL_NO_HEADER_ASC[i],
                          LITERAL_NO_NEWLINES_ASC[i]] {
                let mut r = Reader::new(Cursor::new(test),
                                        ReaderMode::VeryTolerant);
                let mut dearmored = Vec::<u8>::new();
                r.read_to_end(&mut dearmored).unwrap();

                assert_eq!(&dearmored, reference);
            }
        }
    }

    #[test]
    fn dearmor_binary() {
        for bin in TEST_BIN.iter() {
            let mut r = Reader::new(
                Cursor::new(bin), ReaderMode::Tolerant(Some(Kind::Message)));
            let mut buf = [0; 5];
            let e = r.read(&mut buf);
            assert!(e.is_err());
        }
    }

    #[test]
    fn dearmor_wrong_kind() {
        let mut r = Reader::new(
            Cursor::new(&include_bytes!("../tests/data/armor/test-0.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::Message)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_crc() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-0.bad-crc.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_footer() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-2.bad-footer.asc")[..]
            ),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut read = 0;
        loop {
            let mut buf = [0; 5];
            match r.read(&mut buf) {
                Ok(0) => panic!("Reached EOF, but expected an error!"),
                Ok(r) => read += r,
                Err(_) => break,
            }
        }
        assert!(read <= 2);
    }

    #[test]
    fn dearmor_no_crc() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-1.no-crc.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.unwrap() == 1 && buf[0] == 0xde);
    }

    #[test]
    fn dearmor_with_header() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers.asc")[..]
            ),
            ReaderMode::Tolerant(Some(Kind::File)));
        assert_eq!(r.headers().unwrap(),
                   &[("Comment".into(), "Some Header".into()),
                     ("Comment".into(), "Another one".into())]);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_any() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(r.kind() == Some(Kind::File));
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_with_garbage() {
        let armored =
            include_bytes!("../tests/data/armor/test-3.with-headers.asc");
        // Slap some garbage in front and make sure it still reads ok.
        let mut b: Vec<u8> = "Some\ngarbage\nlines\n\t\r  ".into();
        b.extend_from_slice(armored);
        let mut r = Reader::new(Cursor::new(b), ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());

        // Again, but this time add a non-whitespace character in the
        // line of the header.
        let mut b: Vec<u8> = "Some\ngarbage\nlines\n\t.\r  ".into();
        b.extend_from_slice(armored);
        let mut r = Reader::new(Cursor::new(b), ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut r = Reader::new(
                Cursor::new(asc),
                ReaderMode::Tolerant(Some(Kind::File)));
            let mut dearmored = Vec::<u8>::new();
            r.read_to_end(&mut dearmored).unwrap();

            assert_eq!(&dearmored, bin);
        }
    }

    #[test]
    fn dearmor_bytewise() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let r = Reader::new(
                Cursor::new(asc),
                ReaderMode::Tolerant(Some(Kind::File)));
            let mut dearmored = Vec::<u8>::new();
            for c in r.bytes() {
                dearmored.push(c.unwrap());
            }

            assert_eq!(&dearmored, bin);
        }
    }

    #[test]
    fn dearmor_yuge() {
        let yuge_key = crate::tests::key("yuge-key-so-yuge-the-yugest.asc");
        let mut r = Reader::new(Cursor::new(&yuge_key[..]),
                                ReaderMode::VeryTolerant);
        let mut dearmored = Vec::<u8>::new();
        r.read_to_end(&mut dearmored).unwrap();

        let r = Reader::new(Cursor::new(&yuge_key[..]),
                            ReaderMode::VeryTolerant);
        let mut dearmored = Vec::<u8>::new();
        for c in r.bytes() {
            dearmored.push(c.unwrap());
        }
    }

    #[test]
    fn dearmor_quoted() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(r.kind() == Some(Kind::File));
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_quoted_a_lot() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted-a-lot.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        // Loop over the input to ensure we read and verify all the way to the
        // end of the input in order to check the checksum and footer validation
        loop {
            let e = r.read(&mut buf);
            assert!(r.kind() == Some(Kind::File));
            assert!(e.is_ok());
            if e.unwrap() == 0 {
                break;
            }
        }
    }

    #[test]
    fn dearmor_quoted_badly() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted-badly.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    quickcheck! {
        fn roundtrip(kind: Kind, payload: Vec<u8>) -> bool {
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
            Reader::new(Cursor::new(&encoded),
                        ReaderMode::Tolerant(Some(kind)))
                .read_to_end(&mut recovered)
                .unwrap();

            let mut recovered_any = Vec::new();
            Reader::new(Cursor::new(&encoded), ReaderMode::VeryTolerant)
                .read_to_end(&mut recovered_any)
                .unwrap();

            payload == recovered && payload == recovered_any
        }
    }
}
