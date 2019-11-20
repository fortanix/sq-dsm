use std::fmt;
use std::cmp;
use std::time;
use quickcheck::{Arbitrary, Gen};

use crate::constants::DataFormat;
use crate::conversions::Time;
use crate::Error;
use crate::packet;
use crate::Packet;
use crate::Result;

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
    format: DataFormat,
    /// filename is a string, but strings in Rust are valid UTF-8.
    /// There is no guarantee, however, that the filename is valid
    /// UTF-8.  Thus, we leave filename as a byte array.  It can be
    /// converted to a string using String::from_utf8() or
    /// String::from_utf8_lossy().
    filename: Option<Vec<u8>>,
    /// A four-octet number that indicates a date associated with the
    /// literal data.
    date: time::SystemTime, // XXX Should be Option<SystemTime>
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
            date: time::SystemTime::from_pgp(0),
        }
    }

    /// Gets the Literal packet's body.
    pub fn body(&self) -> Option<&[u8]> {
        self.common.body.as_ref().map(|b| b.as_slice())
    }

    /// Sets the Literal packet's body to the provided byte string.
    pub fn set_body(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.common.set_body(data)
    }

    /// Gets the Literal packet's content disposition.
    pub fn format(&self) -> DataFormat {
        self.format
    }

    /// Sets the Literal packet's content disposition.
    pub fn set_format(&mut self, format: DataFormat) -> DataFormat {
        ::std::mem::replace(&mut self.format, format)
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
    pub fn set_filename_from_bytes(&mut self, filename: &[u8])
                                   -> Result<Option<Vec<u8>>> {
        Ok(::std::mem::replace(&mut self.filename, match filename.len() {
            0 => None,
            1..=255 => Some(filename.to_vec()),
            n => return
                Err(Error::InvalidArgument(
                    format!("filename too long: {} bytes", n)).into()),
        }))
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
    pub fn set_filename(&mut self, filename: &str)
                        -> Result<Option<Vec<u8>>> {
        self.set_filename_from_bytes(filename.as_bytes())
    }

    /// Gets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn date(&self) -> Option<time::SystemTime> {
        if self.date.to_pgp().unwrap_or(0) == 0 {
            None
        } else {
            Some(self.date)
        }
    }

    /// Sets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_date(&mut self, timestamp: Option<time::SystemTime>)
                    -> Option<time::SystemTime>
    {
        let old = ::std::mem::replace(
            &mut self.date,
            timestamp.map(|t| t.canonicalize())
                .unwrap_or(time::SystemTime::from_pgp(0)));
        if old == time::SystemTime::from_pgp(0) {
            None
        } else {
            Some(old)
        }
    }
}

impl From<Literal> for Packet {
    fn from(s: Literal) -> Self {
        Packet::Literal(s)
    }
}

impl Arbitrary for Literal {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut l = Literal::new(DataFormat::arbitrary(g));
        l.set_body(Vec::<u8>::arbitrary(g));
        while let Err(_) = l.set_filename_from_bytes(&Vec::<u8>::arbitrary(g)) {
            // Too long, try again.
        }
        l.set_date(Option::<u32>::arbitrary(g)
                   .map(|t| time::SystemTime::from_pgp(t)));
        l
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: Literal) -> bool {
            let q = Literal::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
