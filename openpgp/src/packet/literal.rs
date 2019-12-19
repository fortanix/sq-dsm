use std::fmt;
use std::cmp;
use std::convert::TryInto;
use std::time;
use quickcheck::{Arbitrary, Gen};

use crate::types::{DataFormat, Timestamp};
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
    date: Option<Timestamp>,
    /// The literal data.
    ///
    /// This is written when serialized, and set by the packet parser
    /// if `buffer_unread_content` is used.
    body: Vec<u8>,
}

impl fmt::Debug for Literal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let filename = if let Some(ref filename) = self.filename {
            Some(String::from_utf8_lossy(filename))
        } else {
            None
        };

        let threshold = 36;
        let prefix = &self.body[..cmp::min(threshold, self.body.len())];
        let mut prefix_fmt = String::from_utf8_lossy(prefix).into_owned();
        if self.body.len() > threshold {
            prefix_fmt.push_str("...");
        }
        prefix_fmt.push_str(&format!(" ({} bytes)", self.body.len())[..]);

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
            date: None,
            body: Vec::with_capacity(0),
        }
    }

    /// Gets a reference to the Literal packet's body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Gets a mutable reference to the Literal packet's body.
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    /// Sets the Literal packet's body.
    pub fn set_body(&mut self, data: Vec<u8>) -> Vec<u8> {
        std::mem::replace(&mut self.body, data)
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

    /// Sets the literal packet's filename field.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_filename<F>(&mut self, filename: F)
                           -> Result<Option<Vec<u8>>>
        where F: AsRef<[u8]>
    {
        let filename = filename.as_ref();
        Ok(::std::mem::replace(&mut self.filename, match filename.len() {
            0 => None,
            1..=255 => Some(filename.to_vec()),
            n => return
                Err(Error::InvalidArgument(
                    format!("filename too long: {} bytes", n)).into()),
        }))
    }

    /// Gets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should normally be ignored.
    pub fn date(&self) -> Option<time::SystemTime> {
        self.date.map(|d| d.into())
    }

    /// Sets the literal packet's date field.
    ///
    /// Note: when a literal data packet is protected by a signature,
    /// only the literal data packet's body is protected, not the
    /// meta-data.  As such, this field should not be used.
    pub fn set_date<T>(&mut self, timestamp: T)
                       -> Result<Option<time::SystemTime>>
        where T: Into<Option<time::SystemTime>>
    {
        let date = if let Some(d) = timestamp.into() {
            let t = d.try_into()?;
            if u32::from(t) == 0 {
                None // RFC4880, section 5.9: 0 =^= "no specific time".
            } else {
                Some(t)
            }
        } else {
            None
        };
        Ok(std::mem::replace(&mut self.date, date).map(|d| d.into()))
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
        while let Err(_) = l.set_filename(&Vec::<u8>::arbitrary(g)) {
            // Too long, try again.
        }
        l.set_date(Some(Timestamp::arbitrary(g).into())).unwrap();
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
