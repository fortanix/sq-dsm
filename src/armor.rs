//! Handling ASCII Armor (see [RFC 4880, section
//! 6](https://tools.ietf.org/html/rfc4880#section-6)).

extern crate base64;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::cmp::min;

/// The encoded output stream must be represented in lines of no more
/// than 76 characters each (see (see [RFC 4880, section
/// 6.3](https://tools.ietf.org/html/rfc4880#section-6.3).  GnuPG uses
/// 64.
const LINE_LENGTH: usize = 64;

const LINE_ENDING: &str = "\n";

/// Specifies the type of data that is to be encoded (see [RFC 4880,
/// section 6.2](https://tools.ietf.org/html/rfc4880#section-6.2)).
pub enum Kind {
    /// A generic OpenPGP message.
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
}

impl Kind {
    fn blurb(&self) -> &str {
        match self {
            &Kind::Message => "MESSAGE",
            &Kind::PublicKey => "PUBLIC KEY BLOCK",
            &Kind::PrivateKey => "PRIVATE KEY BLOCK",
            &Kind::SecretKey => "PRIVATE KEY BLOCK",
            &Kind::Signature => "SIGNATURE",
            &Kind::File => "ARMORED FILE",
        }
    }
}

/// A filter that applies ASCII Armor to the data written to it.
pub struct Writer<'a, W: 'a + Write> {
    sink: &'a mut W,
    kind: Kind,
    stash: Vec<u8>,
    column: usize,
    crc: CRC,
    initialized: bool,
    finalized: bool,
}

impl<'a, W: Write> Writer<'a, W> {
    /// Construct a new filter for the given type of data.
    pub fn new(inner: &'a mut W, kind: Kind) -> Self {
        Writer {
            sink: inner,
            kind: kind,
            stash: Vec::<u8>::with_capacity(3),
            column: 0,
            crc: CRC::new(),
            initialized: false,
            finalized: false,
        }
    }

    /// Write the header if not already done.
    fn initialize(&mut self) -> Result<(), Error> {
        if self.initialized { return Ok(()) }

        write!(self.sink, "-----BEGIN PGP {}-----{}{}", self.kind.blurb(),
               LINE_ENDING, LINE_ENDING)?;

        self.initialized = true;
        Ok(())
    }

    /// Write the footer.  No more data can be written after this
    /// call.  If this is not called explicitly, the header is written
    /// once the writer is dropped.
    pub fn finalize(&mut self) -> Result<(), Error> {
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
        write!(self.sink, "={}{}-----END PGP {}-----{}",
               base64::encode_config(&bytes, base64::STANDARD_NO_PAD),
               LINE_ENDING, self.kind.blurb(), LINE_ENDING)?;

        self.finalized = true;
        Ok(())
    }

    /// Insert a line break if necessary.
    fn linebreak(&mut self) -> Result<(), Error> {
        assert!(self.column <= LINE_LENGTH);
        if self.column == LINE_LENGTH {
            write!(self.sink, "{}", LINE_ENDING)?;
            self.column = 0;
        }
        Ok(())
    }
}

impl<'a, W: Write> Write for Writer<'a, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
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
        if self.stash.len() > 0 {
            while self.stash.len() < 3 {
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

        // We know that we have a multiple of 3 bytes, encode them and write them out.
        assert!(input.len() % 3 == 0);
        let encoded = base64::encode_config(input, base64::STANDARD_NO_PAD);
        let mut enc = encoded.as_bytes();
        while enc.len() > 0 {
            let n = min(LINE_LENGTH - self.column, enc.len());
            self.sink.write_all(&enc[..n])?;
            enc = &enc[n..];
            written += n;
            self.column += n;
            self.linebreak()?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.sink.flush()
    }
}

impl<'a, W: Write> Drop for Writer<'a, W> {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

struct CRC {
    n: u32,
}

/// Computes the CRC-24, (see [RFC 4880, section
/// 6.1](https://tools.ietf.org/html/rfc4880#section-6.1)).
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

    #[test]
    fn enarmor() {
        for len in [0, 1, 2, 3, 47, 48, 49, 50, 51].into_iter() {
            let mut file = File::open(format!("tests/data/armor/test-{}.bin", len)).unwrap();
            let mut bin = Vec::<u8>::new();
            file.read_to_end(&mut bin).unwrap();

            let mut file = File::open(format!("tests/data/armor/test-{}.asc", len)).unwrap();
            let mut asc = Vec::<u8>::new();
            file.read_to_end(&mut asc).unwrap();

            let mut buf = Vec::new();
            {
                let mut w = Writer::new(&mut buf, Kind::File);
                w.write(&bin).unwrap();
            }
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(&asc));
        }
    }
}
