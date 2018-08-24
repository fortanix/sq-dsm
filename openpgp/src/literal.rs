use std::fmt;
use std::cmp;
use time;

use constants::DataFormat;
use conversions::Time;
use Error;
use Literal;
use Packet;
use Result;

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
    pub fn filename(&self) -> Option<&[u8]> {
        self.filename.as_ref().map(|b| b.as_slice())
    }

    /// Sets the literal packet's filename field from a byte sequence.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.
    pub fn set_filename_from_bytes(&mut self, filename: &[u8]) -> Result<()> {
        if filename.len() > 255 {
            return
                Err(Error::InvalidArgument("filename too long".into()).into());
        }
        self.filename = Some(filename.to_vec());
        Ok(())
    }

    /// Sets the literal packet's filename field from a UTF-8 encoded
    /// string.
    ///
    /// This is a convenience function, since the field is actually a
    /// raw byte string.  Filenames must not be longer than 255 bytes.
    pub fn set_filename(&mut self, filename: &str) -> Result<()> {
        let filename = filename.as_bytes().to_vec();
        if filename.len() > 255 {
            return
                Err(Error::InvalidArgument("filename too long".into()).into());
        }
        self.filename = Some(filename);
        Ok(())
    }

    /// Gets the literal packet's date field.
    pub fn date(&self) -> &time::Tm {
        &self.date
    }

    /// Sets the literal packet's date field.
    pub fn set_date(&mut self, timestamp: time::Tm) {
        self.date = timestamp;
    }

    /// Convert the `Literal` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Literal(self)
    }
}
