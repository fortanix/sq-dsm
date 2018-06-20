//! ASCII Armor.
//!
//! This module deals with ASCII Armored data (see [RFC 4880, section 6]).
//!
//! [RFC 4880, section 6]: https://tools.ietf.org/html/rfc4880#section-6
//!
//! # Scope
//!
//! This implements a subset of the ASCII Armor specification.  Not
//! supported features are:
//!
//!  - Multipart messages
//!  - Headers
//!
//! The former is likely no longer useful today, and the latter seems
//! to be of questionable value because the data is not authenticated.
//! Reading armored data with headers is supported, but they are
//! merely swallowed.
//!
//! # Memory allocations
//!
//! Both the reader and the writer allocate memory in the order of the
//! size of chunks read or written.
//!
//! # Example
//!
//! ```rust, no_run
//! use std::fs::File;
//! use openpgp::armor::{Reader, Kind};
//!
//! let mut file = File::open("somefile.asc").unwrap();
//! let mut r = Reader::new(&mut file, Kind::File);
//! ```

extern crate base64;
use std::io::{Read, Write};
use std::io::{Result, Error, ErrorKind};
use std::cmp::min;

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
    PrivateKey,
    /// Alias for PrivateKey.
    SecretKey,
    /// A detached signature.
    Signature,
    /// A generic file.  This is a GnuPG extension.
    File,
    /// When reading an Armored file, accept any type.
    Any,
}

impl Kind {
    /// Autodetects the kind of data.
    fn detect(blurb: &[u8]) -> Option<Self> {
        if blurb.len() < 16 || ! blurb.starts_with(b"-----BEGIN PGP ") {
            return None;
        }

        match &blurb[15..17] {
            b"ME" => Some(Kind::Message),
            b"PU" => Some(Kind::PublicKey),
            b"PR" => Some(Kind::SecretKey),
            b"SI" => Some(Kind::Signature),
            b"AR" => Some(Kind::File),
            _ => None,
        }
    }

    fn blurb(&self) -> &str {
        match self {
            &Kind::Message => "MESSAGE",
            &Kind::PublicKey => "PUBLIC KEY BLOCK",
            &Kind::PrivateKey => "PRIVATE KEY BLOCK",
            &Kind::SecretKey => "PRIVATE KEY BLOCK",
            &Kind::Signature => "SIGNATURE",
            &Kind::File => "ARMORED FILE",
            &Kind::Any => unreachable!(),
        }
    }

    fn begin(&self) -> String {
        format!("-----BEGIN PGP {}-----", self.blurb())
    }

    fn begin_len(&self) -> usize {
        20 + self.blurb().len()
    }

    fn end(&self) -> String {
        format!("-----END PGP {}-----", self.blurb())
    }
}

/// A filter that applies ASCII Armor to the data written to it.
pub struct Writer<W: Write> {
    sink: W,
    kind: Kind,
    stash: Vec<u8>,
    column: usize,
    crc: CRC,
    initialized: bool,
    finalized: bool,
}

impl<W: Write> Writer<W> {
    /// Constructs a new filter for the given type of data.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::io::Write;
    /// # extern crate openpgp;
    /// # use openpgp::armor::{Writer, Kind};
    /// # use std::io::{self, Result};
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let mut buffer = io::Cursor::new(vec![]);
    /// {
    ///     let mut writer = Writer::new(&mut buffer, Kind::File);
    ///     writer.write_all(b"Hello world!")?;
    ///     // writer is drop()ed here.
    /// }
    /// assert_eq!(
    ///     String::from_utf8_lossy(buffer.get_ref()),
    ///     "-----BEGIN PGP ARMORED FILE-----
    ///
    /// SGVsbG8gd29ybGQh
    /// =s4Gu
    /// -----END PGP ARMORED FILE-----
    /// ");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: W, kind: Kind) -> Self {
        assert!(kind != Kind::Any);
        Writer {
            sink: inner,
            kind: kind,
            stash: Vec::<u8>::with_capacity(2),
            column: 0,
            crc: CRC::new(),
            initialized: false,
            finalized: false,
        }
    }

    /// Writes the header if not already done.
    fn initialize(&mut self) -> Result<()> {
        if self.initialized { return Ok(()) }

        write!(self.sink, "{}{}{}", self.kind.begin(),
               LINE_ENDING, LINE_ENDING)?;

        self.initialized = true;
        Ok(())
    }

    /// Writes the footer.
    ///
    /// No more data can be written after this call.  If this is not
    /// called explicitly, the header is written once the writer is
    /// dropped.
    pub fn finalize(&mut self) -> Result<()> {
        self.initialize()?;
        if self.finalized {
            return Err(Error::new(ErrorKind::BrokenPipe, "Writer is finalized."));
        }

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
        self.initialize()?;
        if self.finalized {
            return Err(Error::new(ErrorKind::BrokenPipe, "Writer is finalized."));
        }

        // Update CRC on the unencoded data.
        self.crc.update(buf);

        let mut input = buf;
        let mut written = 0;

        // First of all, if there are stashed bytes, fill the stash
        // and encode it.
        assert!(self.stash.len() < 3);
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
pub struct Reader<R: Read> {
    source: R,
    kind: Kind,
    stash: Vec<u8>,
    crc: CRC,
    expect_crc: Option<u32>,
    initialized: bool,
    finalized: bool,
}

impl<R: Read> Reader<R> {
    /// Constructs a new filter for the given type of data.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::io::Read;
    /// # extern crate openpgp;
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
    /// let mut reader = Reader::new(&mut cursor, Kind::Any);
    ///
    /// let mut content = String::new();
    /// reader.read_to_string(&mut content)?;
    /// assert_eq!(content, "Hello world!");
    /// assert_eq!(reader.kind(), Kind::File);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: R, kind: Kind) -> Self {
        Reader {
            source: inner,
            kind: kind,
            stash: Vec::<u8>::with_capacity(2),
            crc: CRC::new(),
            expect_crc: None,
            initialized: false,
            finalized: false,
        }
    }

    /// Returns the kind of data this reader is for.
    ///
    /// Useful in combination with `Kind::Any`.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Consumes the header if not already done.
    fn initialize(&mut self) -> Result<()> {
        if self.initialized { return Ok(()) }

        let buf = if self.kind == Kind::Any {
            let peek = 17;
            let mut buf: Vec<u8> = vec![0; peek];
            self.source.read_exact(&mut buf)?;

            if let Some(k) = Kind::detect(&buf) {
                self.kind = k;
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid ASCII Armor header."));
            }

            buf.resize(self.kind.begin_len(), 0);
            self.source.read_exact(&mut buf[peek..])?;
            buf
        } else {
            let mut buf: Vec<u8> = vec![0; self.kind.begin_len()];
            self.source.read_exact(&mut buf)?;
            buf
        };

        if buf != self.kind.begin().into_bytes() {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid ASCII Armor header."));
        }
        self.linebreak()?;

        while self.line()? != 0 {
            /* Swallow headers.  */
        }

        self.initialized = true;
        Ok(())
    }

    /// Consumes the footer.
    ///
    /// No more data can be read after this call.
    fn finalize(&mut self, buf: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(Error::new(ErrorKind::BrokenPipe, "Reader is finalized."));
        }

        let mut rest = Vec::new();
        self.source.read_to_end(&mut rest)?;

        let mut footer = Vec::new();
        footer.extend(buf);
        footer.extend(&rest);
        let mut off = 0;

        /* Look for CRC.  The CRC is optional.  */
        if footer.len() >= 6 && footer[0] == '=' as u8 {
            /* Found.  */
            let crc = match base64::decode_config(&footer[1..5], base64::MIME) {
                Ok(d) => d,
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
            };
            self.expect_crc = Some((crc[0] as u32) << 16
                                   | (crc[1] as u32) << 8
                                   | crc[2] as u32);

            /* Update offset, skip whitespace.  */
            off += 5;
            while off < footer.len() && footer[off].is_ascii_whitespace() {
                off += 1;
            }
        }

        if ! footer[off..].starts_with(&self.kind.end().into_bytes()) {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid ASCII Armor footer."));
        }

        self.finalized = true;
        Ok(())
    }

    /// Consumes a linebreak.
    fn linebreak(&mut self) -> Result<()> {
        if self.line()? != 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "Expected newline."));
        }
        Ok(())
    }

    /// Consumes a line, returning the number of non-whitespace bytes.
    fn line(&mut self) -> Result<usize> {
        let mut buf = [0; 1];
        let mut c = 0;

        loop {
            self.source.read_exact(&mut buf)?;
            if ! buf[0].is_ascii_whitespace() {
                c += 1;
            }

            if buf[0] == '\n' as u8 {
                break;
            }
        }

        Ok(c)
    }
}

/// Looks for the CRC sum or the footer.
fn find_footer(buf: &[u8]) -> Option<usize> {
    if buf.len() == 0 {
        return None;
    }

    if buf[0] == '=' as u8 || buf[0] == '-' as u8 {
        return Some(0);
    }

    for i in 0..buf.len() - 1 {
        if buf[i].is_ascii_whitespace() && (buf[i+1] == '=' as u8
                                            || buf[i+1] == '-' as u8) {
            return Some(i + 1);
        }
    }
    None
}

impl<W: Read> Read for Reader<W> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.initialize()?;
        if self.finalized { return Ok(0) }

        /* How much did we get?  */
        let mut read = 0;

        /* See if there are stashed bytes, and use them.  */
        assert!(self.stash.len() < 3);
        while self.stash.len() > 0 && buf.len() > read {
            buf[read] = self.stash.pop().unwrap();
            read += 1;
        }

        /* Try to get enough bytes to fill buf, account for bytes
         * filled using the stash, round up.  */
        let mut raw: Vec<u8> = vec![0; (buf.len() - read + 2) / 3 * 4];
        let got = self.source.read(&mut raw)?;
        raw.truncate(got);

        /* Check if we see the footer.  If so, we're almost done.  */
        let decoded = if let Some(n) = find_footer(&raw) {
            self.finalize(&raw[n..])?;
            match base64::decode_config(&raw[..n], base64::MIME) {
                Ok(d) => d,
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
            }
        } else {
            /* We may have to get some more until we have a multiple
             * of four non-whitespace ASCII characters.  */
            loop {
                let n = &raw.iter().filter(|c| ! (**c).is_ascii_whitespace()).count();
                if n % 4 == 0 { break }

                /* Get some more bytes.  */
                let mut m: Vec<u8> = vec![0; 4 - n % 4];
                let got = self.source.read(&mut m)?;
                if got == 0 {
                    /* Tough.  This will fail in the decoder.  */
                    break;
                }
                m.truncate(got);
                raw.append(&mut m);
            }

            match base64::decode_config(&raw, base64::MIME) {
                Ok(d) => d,
                Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
            }
        };

        self.crc.update(&decoded);

        /* Check how much we got vs how much was requested.  */
        if decoded.len() <= (buf.len() - read) {
            &mut buf[read..read + decoded.len()].copy_from_slice(&decoded);
            read += decoded.len();
        } else {
            /* We got more than we wanted, spill the surplus into our
             * stash.  */
            let spill = decoded.len() - (buf.len() - read);
            assert!(spill < 3);

            &mut buf[read..read + decoded.len() - spill].copy_from_slice(
                &decoded[..decoded.len() - spill]);

            for c in &decoded[decoded.len() - spill..] {
                self.stash.push(*c);
            }
            assert!(self.stash.len() < 3);
            self.stash.reverse();
            read += decoded.len() - spill;
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

#[macro_export]
/// Constructs a reader from an armored string literal.
///
/// # Example
///
/// ```
/// use std::io::Read;
/// #[macro_use] extern crate openpgp;
/// # use std::io::Result;
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
///
/// let mut reader = armored!(
///     "-----BEGIN PGP ARMORED FILE-----
///
///      SGVsbG8gd29ybGQh
///      =s4Gu
///      -----END PGP ARMORED FILE-----"
/// );
///
/// let mut content = String::new();
/// reader.read_to_string(&mut content)?;
/// assert_eq!(content, "Hello world!");
/// # Ok(())
/// # }
/// ```
macro_rules! armored {
    ($data:expr) => {{
        use ::std::io::Cursor;
        $crate::armor::Reader::new(Cursor::new(&$data),
                                   $crate::armor::Kind::Any)
    }};
}

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
                let mut w = Writer::new(&mut buf, Kind::File);
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
                let mut w = Writer::new(&mut buf, Kind::File);
                for (i, _) in bin.iter().enumerate() {
                    w.write(&bin[i..i+1]).unwrap();
                }
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(&asc));
        }
    }

    use super::Reader;

    #[test]
    fn dearmor_binary() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut r = Reader::new(&mut file, Kind::Message);
            let mut buf = [0; 5];
            let e = r.read(&mut buf);
            assert!(e.is_err());
        }
    }

    #[test]
    fn dearmor_wrong_kind() {
        let mut file = File::open("tests/data/armor/test-0.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::Message);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_crc() {
        let mut file = File::open("tests/data/armor/test-0.bad-crc.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::File);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_footer() {
        let mut file = File::open("tests/data/armor/test-2.bad-footer.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::File);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_no_crc() {
        let mut file = File::open("tests/data/armor/test-1.no-crc.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::File);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.unwrap() == 1 && buf[0] == 0xde);
    }

    #[test]
    fn dearmor_with_header() {
        let mut file = File::open("tests/data/armor/test-3.with-headers.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::File);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor_any() {
        let mut file = File::open("tests/data/armor/test-3.with-headers.asc").unwrap();
        let mut r = Reader::new(&mut file, Kind::Any);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(r.kind() == Kind::File);
        assert!(e.is_ok());
    }

    #[test]
    fn dearmor() {
        for len in TEST_VECTORS.iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let mut r = Reader::new(&mut file, Kind::File);
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
            let r = Reader::new(&mut file, Kind::File);
            let mut dearmored = Vec::<u8>::new();
            for c in r.bytes() {
                dearmored.push(c.unwrap());
            }

            assert_eq!(&bin, &dearmored);
        }
    }
}
