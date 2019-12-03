//! Conversions for primitive OpenPGP types.

use crate::Error;
use crate::Result;

/// Converts buffers to and from hexadecimal numbers.
pub mod hex {
    use std::io;

    /// Encodes the given buffer as hexadecimal number.
    pub fn encode<B: AsRef<[u8]>>(buffer: B) -> String {
        super::to_hex(buffer.as_ref(), false)
    }

    /// Encodes the given buffer as hexadecimal number with spaces.
    pub fn encode_pretty<B: AsRef<[u8]>>(buffer: B) -> String {
        super::to_hex(buffer.as_ref(), true)
    }

    /// Decodes the given hexadecimal number.
    pub fn decode<H: AsRef<str>>(hex: H) -> crate::Result<Vec<u8>> {
        super::from_hex(hex.as_ref(), false)
    }

    /// Decodes the given hexadecimal number, ignoring whitespace.
    pub fn decode_pretty<H: AsRef<str>>(hex: H) -> crate::Result<Vec<u8>> {
        super::from_hex(hex.as_ref(), true)
    }

    /// Writes annotated hex dumps, like hd(1).
    ///
    /// # Example
    ///
    /// ```rust
    ///  use sequoia_openpgp::conversions::hex;
    ///
    /// let mut dumper = hex::Dumper::new(Vec::new(), "");
    /// dumper.write(&[0x89, 0x01, 0x33], "frame").unwrap();
    /// dumper.write(&[0x04], "version").unwrap();
    /// dumper.write(&[0x00], "type").unwrap();
    ///
    /// let buf = dumper.into_inner();
    /// assert_eq!(
    ///     ::std::str::from_utf8(&buf[..]).unwrap(),
    ///     "00000000  89 01 33                                           frame\n\
    ///      00000003           04                                        version\n\
    ///      00000004              00                                     type\n\
    ///      ");
    /// ```
    pub struct Dumper<W: io::Write> {
        inner: W,
        indent: String,
        offset: usize,
    }

    impl<W: io::Write> Dumper<W> {
        /// Creates a new dumper.
        ///
        /// The dump is written to `inner`.  Every line is indented with
        /// `indent`.
        pub fn new<I: AsRef<str>>(inner: W, indent: I) -> Self {
            Dumper {
                inner: inner,
                indent: indent.as_ref().into(),
                offset: 0,
            }
        }

        /// Returns the inner writer.
        pub fn into_inner(self) -> W {
            self.inner
        }

        /// Writes a chunk of data.
        ///
        /// The `msg` is printed at the end of the first line.
        pub fn write(&mut self, buf: &[u8], msg: &str) -> io::Result<()> {
            let mut first = true;
            self.write_labeled(buf, move |_, _| {
                if first {
                    first = false;
                    Some(msg.into())
                } else {
                    None
                }
            })
        }

        /// Writes a chunk of data.
        ///
        /// For each line, the given function is called to compute a
        /// label that printed at the end of the first line.  The
        /// functions first argument is the offset in the current line
        /// (0..16), the second the slice of the displayed data.
        pub fn write_labeled<L>(&mut self, buf: &[u8], mut labeler: L)
                                -> io::Result<()>
            where L: FnMut(usize, &[u8]) -> Option<String>
        {
            let mut first_label_offset = self.offset % 16;

            write!(self.inner, "{}{:08x} ", self.indent, self.offset)?;
            for i in 0 .. self.offset % 16 {
                if i != 7 {
                    write!(self.inner, "   ")?;
                } else {
                    write!(self.inner, "    ")?;
                }
            }

            let mut offset_printed = true;
            let mut data_start = 0;
            for (i, c) in buf.iter().enumerate() {
                if ! offset_printed {
                    write!(self.inner,
                           "\n{}{:08x} ", self.indent, self.offset)?;
                    offset_printed = true;
                }

                write!(self.inner, " {:02x}", c)?;
                self.offset += 1;
                match self.offset % 16 {
                    0 => {
                        if let Some(msg) = labeler(
                            first_label_offset, &buf[data_start..i + 1])
                        {
                            write!(self.inner, "   {}", msg)?;
                            // Only the first label is offset.
                            first_label_offset = 0;
                        }
                        data_start = i + 1;
                        offset_printed = false;
                    },
                    8 => write!(self.inner, " ")?,
                    _ => (),
                }
            }

            if let Some(msg) = labeler(
                first_label_offset, &buf[data_start..])
            {
                for i in self.offset % 16 .. 16 {
                    if i != 7 {
                        write!(self.inner, "   ")?;
                    } else {
                        write!(self.inner, "    ")?;
                    }
                }

                write!(self.inner, "   {}", msg)?;
            }
            writeln!(self.inner)?;
            Ok(())
        }
    }
}

/// A helpful debugging function.
#[allow(dead_code)]
pub(crate) fn to_hex(s: &[u8], pretty: bool) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for (i, b) in s.iter().enumerate() {
        // Add spaces every four digits to make the output more
        // readable.
        if pretty && i > 0 && i % 2 == 0 {
            write!(&mut result, " ").unwrap();
        }
        write!(&mut result, "{:02X}", b).unwrap();
    }
    result
}

/// A helpful function for converting a hexadecimal string to binary.
/// This function skips whitespace if `pretty` is set.
pub(crate) fn from_hex(hex: &str, pretty: bool) -> Result<Vec<u8>> {
    const BAD: u8 = 255u8;
    const X: u8 = 'x' as u8;

    let mut nibbles = hex.chars().filter_map(|x| {
        match x {
            '0' => Some(0u8),
            '1' => Some(1u8),
            '2' => Some(2u8),
            '3' => Some(3u8),
            '4' => Some(4u8),
            '5' => Some(5u8),
            '6' => Some(6u8),
            '7' => Some(7u8),
            '8' => Some(8u8),
            '9' => Some(9u8),
            'a' | 'A' => Some(10u8),
            'b' | 'B' => Some(11u8),
            'c' | 'C' => Some(12u8),
            'd' | 'D' => Some(13u8),
            'e' | 'E' => Some(14u8),
            'f' | 'F' => Some(15u8),
            'x' | 'X' if pretty => Some(X),
            _ if pretty && x.is_whitespace() => None,
            _ => Some(BAD),
        }
    }).collect::<Vec<u8>>();

    if pretty && nibbles.len() >= 2 && nibbles[0] == 0 && nibbles[1] == X {
        // Drop '0x' prefix.
        nibbles.remove(0);
        nibbles.remove(0);
    }

    if nibbles.iter().any(|&b| b == BAD || b == X) {
        // Not a hex character.
        return
            Err(Error::InvalidArgument("Invalid characters".into()).into());
    }

    // We need an even number of nibbles.
    if nibbles.len() % 2 != 0 {
        return
            Err(Error::InvalidArgument("Odd number of nibbles".into()).into());
    }

    let bytes = nibbles.chunks(2).map(|nibbles| {
        (nibbles[0] << 4) | nibbles[1]
    }).collect::<Vec<u8>>();

    Ok(bytes)
}

pub(crate) fn read_be_u64(b: &[u8]) -> u64 {
    assert_eq!(b.len(), 8);
    ((b[0] as u64) << 56) as u64
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) <<  8)
        | ((b[7] as u64) <<  0)
}

pub(crate) fn write_be_u64(b: &mut [u8], n: u64) {
    assert_eq!(b.len(), 8);
    b[0] = (n >> 56) as u8;
    b[1] = (n >> 48) as u8;
    b[2] = (n >> 40) as u8;
    b[3] = (n >> 32) as u8;
    b[4] = (n >> 24) as u8;
    b[5] = (n >> 16) as u8;
    b[6] = (n >>  8) as u8;
    b[7] = (n >>  0) as u8;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_hex() {
        use super::from_hex as fh;
        assert_eq!(fh("", false).ok(), Some(vec![]));
        assert_eq!(fh("0", false).ok(), None);
        assert_eq!(fh("00", false).ok(), Some(vec![0x00]));
        assert_eq!(fh("09", false).ok(), Some(vec![0x09]));
        assert_eq!(fh("0f", false).ok(), Some(vec![0x0f]));
        assert_eq!(fh("99", false).ok(), Some(vec![0x99]));
        assert_eq!(fh("ff", false).ok(), Some(vec![0xff]));
        assert_eq!(fh("000", false).ok(), None);
        assert_eq!(fh("0000", false).ok(), Some(vec![0x00, 0x00]));
        assert_eq!(fh("0009", false).ok(), Some(vec![0x00, 0x09]));
        assert_eq!(fh("000f", false).ok(), Some(vec![0x00, 0x0f]));
        assert_eq!(fh("0099", false).ok(), Some(vec![0x00, 0x99]));
        assert_eq!(fh("00ff", false).ok(), Some(vec![0x00, 0xff]));
        assert_eq!(fh("\t\n\x0c\r ", false).ok(), None);
        assert_eq!(fh("a", false).ok(), None);
        assert_eq!(fh("0x", false).ok(), None);
        assert_eq!(fh("0x0", false).ok(), None);
        assert_eq!(fh("0x00", false).ok(), None);
    }

    #[test]
    fn from_pretty_hex() {
        use super::from_hex as fh;
        assert_eq!(fh(" ", true).ok(), Some(vec![]));
        assert_eq!(fh(" 0", true).ok(), None);
        assert_eq!(fh(" 00", true).ok(), Some(vec![0x00]));
        assert_eq!(fh(" 09", true).ok(), Some(vec![0x09]));
        assert_eq!(fh(" 0f", true).ok(), Some(vec![0x0f]));
        assert_eq!(fh(" 99", true).ok(), Some(vec![0x99]));
        assert_eq!(fh(" ff", true).ok(), Some(vec![0xff]));
        assert_eq!(fh(" 00 0", true).ok(), None);
        assert_eq!(fh(" 00 00", true).ok(), Some(vec![0x00, 0x00]));
        assert_eq!(fh(" 00 09", true).ok(), Some(vec![0x00, 0x09]));
        assert_eq!(fh(" 00 0f", true).ok(), Some(vec![0x00, 0x0f]));
        assert_eq!(fh(" 00 99", true).ok(), Some(vec![0x00, 0x99]));
        assert_eq!(fh(" 00 ff", true).ok(), Some(vec![0x00, 0xff]));
        assert_eq!(fh("\t\n\x0c\r ", true).ok(), Some(vec![]));
        // Fancy Unicode spaces are ok too:
        assert_eq!(fh("     23", true).ok(), Some(vec![0x23]));
        assert_eq!(fh("a", true).ok(), None);
        assert_eq!(fh(" 0x", true).ok(), Some(vec![]));
        assert_eq!(fh(" 0x0", true).ok(), None);
        assert_eq!(fh(" 0x00", true).ok(), Some(vec![0x00]));
    }

    quickcheck! {
        fn hex_roundtrip(data: Vec<u8>) -> bool {
            let hex = super::to_hex(&data, false);
            data == super::from_hex(&hex, false).unwrap()
        }
    }

    quickcheck! {
        fn pretty_hex_roundtrip(data: Vec<u8>) -> bool {
            let hex = super::to_hex(&data, true);
            data == super::from_hex(&hex, true).unwrap()
        }
    }

    #[test]
    fn hex_dumper() {
        use super::hex::Dumper;

        let mut dumper = Dumper::new(Vec::new(), "III");
        dumper.write(&[0x89, 0x01, 0x33], "frame").unwrap();
        let buf = dumper.into_inner();
        assert_eq!(
            ::std::str::from_utf8(&buf[..]).unwrap(),
            "III00000000  \
             89 01 33                                           \
             frame\n");

        let mut dumper = Dumper::new(Vec::new(), "III");
        dumper.write(&[0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01], "frame")
            .unwrap();
        let buf = dumper.into_inner();
        assert_eq!(
            ::std::str::from_utf8(&buf[..]).unwrap(),
            "III00000000  \
             89 01 33 89 01 33 89 01                            \
             frame\n");

        let mut dumper = Dumper::new(Vec::new(), "III");
        dumper.write(&[0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01,
                       0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01], "frame")
            .unwrap();
        let buf = dumper.into_inner();
        assert_eq!(
            ::std::str::from_utf8(&buf[..]).unwrap(),
            "III00000000  \
             89 01 33 89 01 33 89 01  89 01 33 89 01 33 89 01   \
             frame\n");

        let mut dumper = Dumper::new(Vec::new(), "III");
        dumper.write(&[0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01,
                       0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01,
                       0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01,
                       0x89, 0x01, 0x33, 0x89, 0x01, 0x33, 0x89, 0x01], "frame")
            .unwrap();
        let buf = dumper.into_inner();
        assert_eq!(
            ::std::str::from_utf8(&buf[..]).unwrap(),
            "III00000000  \
             89 01 33 89 01 33 89 01  89 01 33 89 01 33 89 01   \
             frame\n\
             III00000010  \
             89 01 33 89 01 33 89 01  89 01 33 89 01 33 89 01\n");

        let mut dumper = Dumper::new(Vec::new(), "");
        dumper.write(&[0x89, 0x01, 0x33], "frame").unwrap();
        dumper.write(&[0x04], "version").unwrap();
        dumper.write(&[0x00], "type").unwrap();
        let buf = dumper.into_inner();
        assert_eq!(
            ::std::str::from_utf8(&buf[..]).unwrap(),
            "00000000  89 01 33                                           \
             frame\n\
             00000003           04                                        \
             version\n\
             00000004              00                                     \
             type\n\
             ");
    }

    quickcheck! {
        fn be_u64_roundtrip(n: u64) -> bool {
            let mut b = [0; 8];
            write_be_u64(&mut b, n);
            n == read_be_u64(&b)
        }
    }
}
