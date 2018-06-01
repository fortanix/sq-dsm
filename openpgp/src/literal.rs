use std::fmt;
use std::cmp;

use Literal;
use Packet;

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
            .field("format", &(self.format as char))
            .field("filename", &filename)
            .field("date", &self.date)
            .field("body", &prefix_fmt)
            .finish()
    }
}

impl Literal {
    /// Returns a new `Literal` packet.
    pub fn new(format: char) -> Literal {
        Literal {
            common: Default::default(),
            format: format as u8,
            filename: None,
            date: 0
        }
    }

    /// Sets the Literal packet's body to the provided byte string.
    pub fn body(mut self, data: Vec<u8>) -> Literal {
        self.common.body = Some(data);
        self
    }

    /// Sets the Literal packet's content disposition to text.
    ///
    /// This is a hint that the content is probably text; the encoding
    /// is not specified.
    pub fn text(mut self) -> Literal {
        self.format = 't' as u8;
        self
    }

    /// Sets the Literal packet's content disposition to UTF-8.
    ///
    /// This is a hint that the content is probably UTF-8 encoded.
    pub fn utf8(mut self) -> Literal {
        self.format = 'u' as u8;
        self
    }

    /// Sets the Literal packet's content disposition to binary.
    ///
    /// This is a hint that the content is probably binary data.
    pub fn binary(mut self) -> Literal {
        self.format = 'b' as u8;
        self
    }

    /// Sets the Literal packet's content disposition to MIME.
    ///
    /// This is specified in RFC 4880bis, which has not yet been
    /// standardized.
    pub fn mime(mut self) -> Literal {
        self.format = 'm' as u8;
        self
    }

    /// Sets the literal packet's filename field from a byte sequence.
    ///
    /// The standard does not specify the encoding.
    ///
    /// This function panics, if the filename is longer than 255
    /// bytes, which is the limit imposed by RFC 4880.
    pub fn filename_from_bytes(mut self, filename: &[u8]) -> Literal {
        if filename.len() > 255 {
            panic!("Filename too long.");
        }
        self.filename = Some(filename.to_vec());
        self
    }

    /// Sets the literal packet's filename field from a UTF-8 encoded
    /// string.
    ///
    /// This is a convenience function, since the field is actually a
    /// raw byte string.
    ///
    /// This function panics, if the filename is longer than 255
    /// bytes, which is the limit imposed by RFC 4880.
    pub fn filename(mut self, filename: &str) -> Literal {
        if filename.len() > 255 {
            panic!("Filename too long.");
        }
        self.filename = Some(filename.as_bytes().to_vec());
        self
    }

    /// Sets the literal packet's date field using a Unix timestamp.
    ///
    /// A Unix timestamp is the number of seconds since the Unix
    /// epoch.
    pub fn date(mut self, timestamp: u32) -> Literal {
        self.date = timestamp;
        self
    }

    /// Convert the `Literal` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Literal(self)
    }
}
