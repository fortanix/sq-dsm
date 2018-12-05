use std::fmt;
use std::cmp;
use time;

use constants::DataFormat;
use conversions::Time;
use Error;
use packet;
use Packet;
use Result;

/// Holds a literal packet.
///
/// A literal packet contains unstructured data.  Since the size can
/// be very large, it is advised to process messages containing such
/// packets using a `PacketParser` or a `PacketPileParser` and process
/// the data in a streaming manner rather than the using the
/// `PacketPile::from_file` and related interfaces.
///
/// See [Section 5.9 of RFC 4880] for details.
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Literal {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// A one-octet field that describes how the data is formatted.
    pub(crate) format: DataFormat,
    /// filename is a string, but strings in Rust are valid UTF-8.
    /// There is no guarantee, however, that the filename is valid
    /// UTF-8.  Thus, we leave filename as a byte array.  It can be
    /// converted to a string using String::from_utf8() or
    /// String::from_utf8_lossy().
    pub(crate) filename: Option<Vec<u8>>,
    /// A four-octet number that indicates a date associated with the
    /// literal data.
    pub(crate) date: time::Tm,
}

impl fmt::Debug for Literal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let filename = if let Some(ref filename) = self.filename {
            Some(String::from_utf8_lossy(filename))
        } else {
            None
        };

        let body = if let Some(ref body) = self.common.body {
            &body[..]
        } else {
            &b""[..]
        };

        let threshold = 36;
        let prefix = &body[..cmp::min(threshold, body.len())];
        let mut prefix_fmt = String::from_utf8_lossy(prefix).into_owned();
        if body.len() > threshold {
            prefix_fmt.push_str("...");
        }
        prefix_fmt.push_str(&format!(" ({} bytes)", body.len())[..]);

        f.debug_struct("Literal")
            .field("format", &self.format)
            .field("filename", &filename)
            .field("date", &self.date)
            .field("body", &prefix_fmt)
            .finish()
    }
}

impl Literal {
    /// Returns a new `Literal` packet.
    pub fn new(format: DataFormat) -> Literal {
        Literal {
            common: Default::default(),
            format: format,
            filename: None,
            date: time::Tm::from_pgp(0),
        }
    }

    /// Gets the Literal packet's body.
    pub fn body(&self) -> Option<&[u8]> {
        self.common.body.as_ref().map(|b| b.as_slice())
    }

    /// Sets the Literal packet's body to the provided byte string.
    pub fn set_body(&mut self, data: Vec<u8>) {
        self.common.body = Some(data);
    }

    /// Gets the Literal packet's content disposition.
    pub fn format(&self) -> DataFormat {
        self.format
    }

    /// Sets the Literal packet's content disposition.
    pub fn set_format(&mut self, format: DataFormat) {
        self.format = format;
    }

    /// Gets the literal packet's filename.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn filename(&self) -> Option<&[u8]> {
        self.filename.as_ref().map(|b| b.as_slice())
    }

    /// Sets the literal packet's filename field from a byte sequence.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_filename_from_bytes(&mut self, filename: &[u8]) -> Result<()> {
        self.filename = match filename.len() {
            0 => None,
            1...255 => Some(filename.to_vec()),
            n => return
                Err(Error::InvalidArgument(
                    format!("filename too long: {} bytes", n)).into()),
        };
        Ok(())
    }

    /// Sets the literal packet's filename field from a UTF-8 encoded
    /// string.
    ///
    /// This is a convenience function, since the field is actually a
    /// raw byte string.  Filenames must not be longer than 255 bytes.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_filename(&mut self, filename: &str) -> Result<()> {
        self.set_filename_from_bytes(filename.as_bytes())
    }

    /// Gets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn date(&self) -> Option<&time::Tm> {
        if self.date.to_pgp().unwrap_or(0) == 0 {
            None
        } else {
            Some(&self.date)
        }
    }

    /// Sets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_date(&mut self, timestamp: Option<time::Tm>) {
        self.date = timestamp.map(|t| t.canonicalize())
            .unwrap_or(time::Tm::from_pgp(0));
    }

    /// Convert the `Literal` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Literal(self)
    }
}

impl From<Literal> for Packet {
    fn from(s: Literal) -> Self {
        s.to_packet()
    }
}
