use std::io;
use std::path::Path;
use std::fs::File;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderGeneric;
use buffered_reader::BufferedReaderMemory;

use Result;
use parse::PacketParser;
use parse::PacketParserSettings;
use parse::ParserResult;
use parse::Cookie;

/// A builder for configuring a `PacketParser`.
///
/// Since the default settings are usually appropriate, this mechanism
/// will only be needed in exceptional circumstances.  Instead use,
/// for instance, `PacketParser::from_file` or
/// `PacketParser::from_reader` to start parsing an OpenPGP message.
pub struct PacketParserBuilder<R: BufferedReader<Cookie>> {
    bio: R,
    settings: PacketParserSettings,
}

impl<R: BufferedReader<Cookie>> PacketParserBuilder<R> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `BufferedReader` object.
    ///
    /// Note: this clears the `level` field of the
    /// `Cookie` cookie.
    pub fn from_buffered_reader(mut bio: R)
            -> Result<PacketParserBuilder<R>> {
        bio.cookie_mut().level = None;
        Ok(PacketParserBuilder {
            bio: bio,
            settings: PacketParserSettings::default(),
        })
    }

    /// Sets the maximum recursion depth.
    ///
    /// Setting this to 0 means that the `PacketParser` will never
    /// recurse; it will only parse the top-level packets.
    ///
    /// This is a u8, because recursing more than 255 times makes no
    /// sense.  The default is `MAX_RECURSION_DEPTH`.  (GnuPG defaults
    /// to a maximum recursion depth of 32.)
    pub fn max_recursion_depth(mut self, value: u8)
            -> PacketParserBuilder<R> {
        self.settings.max_recursion_depth = value;
        self
    }

    /// Causes `PacketParser::finish()` to buffer any unread content.
    ///
    /// The unread content is stored in the `Packet::content` Option.
    pub fn buffer_unread_content(mut self)
            -> PacketParserBuilder<R> {
        self.settings.buffer_unread_content = true;
        self
    }

    /// Causes `PacketParser::finish()` to drop any unread content.
    /// This is the default.
    pub fn drop_unread_content(mut self)
            -> PacketParserBuilder<R> {
        self.settings.buffer_unread_content = false;
        self
    }

    /// Causes the `PacketParser` functionality to print a trace of
    /// its execution on stderr.
    pub fn trace(mut self) -> PacketParserBuilder<R> {
        self.settings.trace = true;
        self
    }

    /// Controls mapping.
    ///
    /// Note that enabling mapping buffers all the data.
    pub fn map(mut self, enable: bool) -> PacketParserBuilder<R> {
        self.settings.map = enable;
        self
    }

    /// Finishes configuring the `PacketParser` and returns an
    /// `Option<PacketParser>`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use openpgp::Result;
    /// # use openpgp::parse::{PacketParser,PacketParserBuilder};
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8])
    /// #     -> Result<Option<PacketParser>> {
    /// let ppo = PacketParserBuilder::from_bytes(message_data)?.finalize()?;
    /// # return Ok(ppo);
    /// # }
    /// ```
    pub fn finalize<'a>(self)
            -> Result<Option<PacketParser<'a>>> where Self: 'a {
        // Parse the first packet.
        let pp = PacketParser::parse(Box::new(self.bio), &self.settings, 0)?;

        if let ParserResult::Success(mut pp) = pp {
            // We successfully parsed the first packet's header.

            // Override the defaults.
            pp.settings = self.settings;

            Ok(Some(pp))
        } else {
            // `bio` is empty.  We're done.
            Ok(None)
        }
    }
}

impl<'a, R: io::Read + 'a>
        PacketParserBuilder<BufferedReaderGeneric<R, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    pub fn from_reader(reader: R)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<R, Cookie>>> {
        Ok(PacketParserBuilder {
            bio: BufferedReaderGeneric::with_cookie(
                reader, None, Cookie::default()),
            settings: PacketParserSettings::default(),
        })
    }
}

impl PacketParserBuilder<BufferedReaderGeneric<File, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    pub fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketParserBuilder<
                          BufferedReaderGeneric<File, Cookie>>> {
        PacketParserBuilder::from_reader(File::open(path)?)
    }
}

impl <'a> PacketParserBuilder<BufferedReaderMemory<'a, Cookie>> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the specified buffer.
    pub fn from_bytes(bytes: &'a [u8])
            -> Result<PacketParserBuilder<
                          BufferedReaderMemory<'a, Cookie>>> {
        PacketParserBuilder::from_buffered_reader(
            BufferedReaderMemory::with_cookie(
                bytes, Cookie::default()))
    }
}
