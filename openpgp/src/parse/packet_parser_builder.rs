use std::io;
use std::path::Path;
use std::fs::File;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderGeneric;
use buffered_reader::BufferedReaderMemory;

use Result;
use parse::PacketParserResult;
use parse::PacketParser;
use parse::PacketParserEOF;
use parse::PacketParserState;
use parse::PacketParserSettings;
use parse::ParserResult;
use parse::Cookie;

/// A builder for configuring a `PacketParser`.
///
/// Since the default settings are usually appropriate, this mechanism
/// will only be needed in exceptional circumstances.  Instead use,
/// for instance, `PacketParser::from_file` or
/// `PacketParser::from_reader` to start parsing an OpenPGP message.
pub struct PacketParserBuilder<'a> {
    bio: Box<'a + BufferedReader<Cookie>>,
    settings: PacketParserSettings,
}

impl<'a> PacketParserBuilder<'a> {
    // Creates a `PacketParserBuilder` for an OpenPGP message stored
    // in a `BufferedReader` object.
    //
    // Note: this clears the `level` field of the
    // `Cookie` cookie.
    pub(crate) fn from_buffered_reader(mut bio: Box<'a + BufferedReader<Cookie>>)
            -> Result<Self> {
        bio.cookie_mut().level = None;
        Ok(PacketParserBuilder {
            bio: bio,
            settings: PacketParserSettings::default(),
        })
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    pub fn from_reader<R: io::Read + 'a>(reader: R) -> Result<Self> {
        Ok(PacketParserBuilder {
            bio: Box::new(BufferedReaderGeneric::with_cookie(
                reader, None, Cookie::default())),
            settings: PacketParserSettings::default(),
        })
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        PacketParserBuilder::from_reader(File::open(path)?)
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the specified buffer.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<PacketParserBuilder> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(BufferedReaderMemory::with_cookie(
                bytes, Cookie::default())))
    }

    /// Sets the maximum recursion depth.
    ///
    /// Setting this to 0 means that the `PacketParser` will never
    /// recurse; it will only parse the top-level packets.
    ///
    /// This is a u8, because recursing more than 255 times makes no
    /// sense.  The default is `MAX_RECURSION_DEPTH`.  (GnuPG defaults
    /// to a maximum recursion depth of 32.)
    pub fn max_recursion_depth(mut self, value: u8) -> Self {
        self.settings.max_recursion_depth = value;
        self
    }

    /// Causes `PacketParser::finish()` to buffer any unread content.
    ///
    /// The unread content is stored in the `Packet::content` Option.
    pub fn buffer_unread_content(mut self) -> Self {
        self.settings.buffer_unread_content = true;
        self
    }

    /// Causes `PacketParser::finish()` to drop any unread content.
    /// This is the default.
    pub fn drop_unread_content(mut self) -> Self {
        self.settings.buffer_unread_content = false;
        self
    }

    /// Causes the `PacketParser` functionality to print a trace of
    /// its execution on stderr.
    pub fn trace(mut self) -> Self {
        self.settings.trace = true;
        self
    }

    /// Controls mapping.
    ///
    /// Note that enabling mapping buffers all the data.
    pub fn map(mut self, enable: bool) -> Self {
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
    /// # use openpgp::parse::{
    /// #     PacketParserResult, PacketParser, PacketParserBuilder
    /// # };
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8])
    /// #     -> Result<PacketParserResult> {
    /// let ppr = PacketParserBuilder::from_bytes(message_data)?.finalize()?;
    /// # return Ok(ppr);
    /// # }
    /// ```
    pub fn finalize(self)
        -> Result<PacketParserResult<'a>>
        where Self: 'a
    {
        let state = PacketParserState::new(self.settings);

        // Parse the first packet.
        match PacketParser::parse(Box::new(self.bio), state, 0)? {
            ParserResult::Success(mut pp) => {
                // We successfully parsed the first packet's header.
                pp.state.message_validator.push(pp.packet.tag(), 0);
                Ok(PacketParserResult::Some(pp))
            },
            ParserResult::EOF((_reader, state)) => {
                // `bio` is empty.  We're done.
                Ok(PacketParserResult::EOF(PacketParserEOF::new(state)))
            }
        }
    }
}
