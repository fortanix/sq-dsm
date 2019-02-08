use std::io;
use std::path::Path;

use buffered_reader::BufferedReader;
use buffered_reader::BufferedReaderGeneric;
use buffered_reader::BufferedReaderMemory;
use buffered_reader::BufferedReaderFile;

use Result;
use parse::PacketParserResult;
use parse::PacketParser;
use parse::PacketParserEOF;
use parse::PacketParserState;
use parse::PacketParserSettings;
use parse::ParserResult;
use parse::Parse;
use parse::Cookie;
use armor;
use packet;

/// How to decode the input.
#[derive(PartialEq)]
pub enum Dearmor {
    /// Unconditionally treat the input as if it were an OpenPGP
    /// message encoded using ASCII armor.
    Enabled,
    /// Unconditionally treat the input as if it were a binary OpenPGP
    /// message.
    Disabled,
    /// If input does not appear to be a binary encoded OpenPGP
    /// message, treat it as if it were encoded using ASCII armor.
    Auto,
}

/// A builder for configuring a `PacketParser`.
///
/// Since the default settings are usually appropriate, this mechanism
/// will only be needed in exceptional circumstances.  Instead use,
/// for instance, `PacketParser::from_file` or
/// `PacketParser::from_reader` to start parsing an OpenPGP message.
pub struct PacketParserBuilder<'a> {
    bio: Box<'a + BufferedReader<Cookie>>,
    dearmor: Dearmor,
    settings: PacketParserSettings,
}

impl<'a> Parse<'a, PacketParserBuilder<'a>> for PacketParserBuilder<'a> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    fn from_reader<R: io::Read + 'a>(reader: R) -> Result<Self> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(BufferedReaderGeneric::with_cookie(
                reader, None, Cookie::default())))
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(BufferedReaderFile::with_cookie(path, Cookie::default())?))
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the specified buffer.
    fn from_bytes(bytes: &'a [u8]) -> Result<PacketParserBuilder> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(BufferedReaderMemory::with_cookie(
                bytes, Cookie::default())))
    }
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
            dearmor: Dearmor::Auto,
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

    /// Controls mapping.
    ///
    /// Note that enabling mapping buffers all the data.
    pub fn map(mut self, enable: bool) -> Self {
        self.settings.map = enable;
        self
    }

    /// How to treat the input stream.
    pub fn dearmor(mut self, mode: Dearmor) -> Self {
        self.dearmor = mode;
        self
    }

    /// Finishes configuring the `PacketParser` and returns an
    /// `Option<PacketParser>`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::parse::{
    /// #     Parse, PacketParserResult, PacketParser, PacketParserBuilder
    /// # };
    /// # f(include_bytes!("../../tests/data/messages/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8])
    /// #     -> Result<PacketParserResult> {
    /// let ppr = PacketParserBuilder::from_bytes(message_data)?.finalize()?;
    /// # return Ok(ppr);
    /// # }
    /// ```
    pub fn finalize(mut self)
        -> Result<PacketParserResult<'a>>
        where Self: 'a
    {
        let state = PacketParserState::new(self.settings);

        let dearmor = match self.dearmor {
            Dearmor::Enabled => true,
            Dearmor::Disabled => false,
            Dearmor::Auto => {
                if let Err(_) = packet::Header::plausible(&mut self.bio) {
                    true
                } else {
                    false
                }
            }
        };

        if dearmor {
            self.bio = Box::new(BufferedReaderGeneric::with_cookie(
                armor::Reader::from_buffered_reader(self.bio, None),
                None,
                Default::default()));
        }

        // Parse the first packet.
        match PacketParser::parse(Box::new(self.bio), state, vec![ 0 ])? {
            ParserResult::Success(mut pp) => {
                // We successfully parsed the first packet's header.
                pp.state.message_validator.push(pp.packet.tag(), 0);
                pp.state.keyring_validator.push(pp.packet.tag());
                pp.state.tpk_validator.push(pp.packet.tag());
                Ok(PacketParserResult::Some(pp))
            },
            ParserResult::EOF((_reader, state, _path)) => {
                // `bio` is empty.  We're done.
                Ok(PacketParserResult::EOF(PacketParserEOF::new(state)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/messages/", $x)) };
    }

    #[test]
    fn armor() {
        // Not ASCII armor encoded data.
        let msg = bytes!("sig.gpg");

        // Make sure we can read the first packet.
        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Disabled)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Auto)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Enabled)
            .finalize();
        // XXX: If the dearmorer doesn't find a header and has no
        // data, then it should return an error.  Fix this when
        // https://gitlab.com/sequoia-pgp/sequoia/issues/174 is
        // resolved.
        //
        // assert_match!(Err(_) = ppr);
        assert_match!(Ok(PacketParserResult::EOF(ref _pp)) = ppr);

        // ASCII armor encoded data.
        let msg = bytes!("a-cypherpunks-manifesto.txt.ed25519.sig");

        // Make sure we can read the first packet.
        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Disabled)
            .finalize();
        assert_match!(Err(_) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Auto)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Enabled)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);
    }
}
