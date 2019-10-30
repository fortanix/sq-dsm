use std::io;
use std::path::Path;

use buffered_reader::BufferedReader;

use crate::Result;
use crate::parse::PacketParserResult;
use crate::parse::PacketParser;
use crate::parse::PacketParserEOF;
use crate::parse::PacketParserState;
use crate::parse::PacketParserSettings;
use crate::parse::ParserResult;
use crate::parse::Parse;
use crate::parse::Cookie;
use crate::armor;
use crate::packet;

/// How to decode the input.
#[derive(PartialEq)]
pub enum Dearmor {
    /// Unconditionally treat the input as if it were an OpenPGP
    /// message encoded using ASCII armor.
    Enabled(armor::ReaderMode),
    /// Unconditionally treat the input as if it were a binary OpenPGP
    /// message.
    Disabled,
    /// If input does not appear to be a binary encoded OpenPGP
    /// message, treat it as if it were encoded using ASCII armor.
    Auto(armor::ReaderMode),
}

/// A builder for configuring a `PacketParser`.
///
/// Since the default settings are usually appropriate, this mechanism
/// will only be needed in exceptional circumstances.  Instead use,
/// for instance, `PacketParser::from_file` or
/// `PacketParser::from_reader` to start parsing an OpenPGP message.
pub struct PacketParserBuilder<'a> {
    bio: Box<dyn BufferedReader<Cookie> + 'a>,
    dearmor: Dearmor,
    settings: PacketParserSettings,
}

impl<'a> Parse<'a, PacketParserBuilder<'a>> for PacketParserBuilder<'a> {
    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in a `std::io::Read` object.
    fn from_reader<R: io::Read + 'a>(reader: R) -> Result<Self> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(
                reader, None, Cookie::default())))
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the file named `path`.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path, Cookie::default())?))
    }

    /// Creates a `PacketParserBuilder` for an OpenPGP message stored
    /// in the specified buffer.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<PacketParserBuilder<'a>> {
        PacketParserBuilder::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(
                data.as_ref(), Cookie::default())))
    }
}

impl<'a> PacketParserBuilder<'a> {
    // Creates a `PacketParserBuilder` for an OpenPGP message stored
    // in a `BufferedReader` object.
    //
    // Note: this clears the `level` field of the
    // `Cookie` cookie.
    pub(crate) fn from_buffered_reader(mut bio: Box<dyn BufferedReader<Cookie> + 'a>)
            -> Result<Self> {
        bio.cookie_mut().level = None;
        Ok(PacketParserBuilder {
            bio: bio,
            dearmor: Dearmor::Auto(Default::default()),
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

    /// Sets the maximum size of non-container packets.
    ///
    /// Packets that exceed this limit will be returned as
    /// `Packet::Unknown`, with the error set to
    /// `Error::PacketTooLarge`.
    ///
    /// This limit applies to any packet type that is *not* a
    /// container packet, i.e. any packet that is not a literal data
    /// packet, a compressed data packet, a symmetrically encrypted
    /// data packet, or an AEAD encrypted data packet.
    ///
    /// The default is 1 MiB.
    pub fn max_packet_size(mut self, value: u32) -> Self {
        self.settings.max_packet_size = value;
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
    /// # f(include_bytes!("../../tests/data/keys/public-key.gpg"));
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

        let dearmor_mode = match self.dearmor {
            Dearmor::Enabled(mode) => Some(mode),
            Dearmor::Disabled => None,
            Dearmor::Auto(mode) => {
                if self.bio.eof() {
                    None
                } else {
                    let mut reader = buffered_reader::Dup::with_cookie(
                        self.bio, Cookie::default());
                    let header = packet::Header::parse(&mut reader);
                    self.bio = Box::new(reader).into_inner().unwrap();
                    if let Ok(header) = header {
                        if let Err(_) = header.valid(false) {
                            // Invalid header: better try an ASCII armor
                            // decoder.
                            Some(mode)
                        } else {
                            None
                        }
                    } else {
                        // Failed to parse the header: better try an ASCII
                        // armor decoder.
                        Some(mode)
                    }
                }
            }
        };

        if let Some(mode) = dearmor_mode {
            self.bio = Box::new(buffered_reader::Generic::with_cookie(
                armor::Reader::from_buffered_reader(self.bio, Some(mode)),
                None,
                Default::default()));
        }

        // Parse the first packet.
        match PacketParser::parse(Box::new(self.bio), state, vec![ 0 ])? {
            ParserResult::Success(mut pp) => {
                // We successfully parsed the first packet's header.
                pp.state.message_validator.push(pp.packet.tag(), &[0]);
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

    #[test]
    fn armor() {
        // Not ASCII armor encoded data.
        let msg = crate::tests::message("sig.gpg");

        // Make sure we can read the first packet.
        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Disabled)
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Auto(Default::default()))
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Enabled(Default::default()))
            .finalize();
        assert_match!(Err(_) = ppr);

        // ASCII armor encoded data.
        let msg = crate::tests::message("a-cypherpunks-manifesto.txt.ed25519.sig");

        // Make sure we can read the first packet.
        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Disabled)
            .finalize();
        assert_match!(Err(_) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Auto(Default::default()))
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);

        let ppr = PacketParserBuilder::from_bytes(msg).unwrap()
            .dearmor(Dearmor::Enabled(Default::default()))
            .finalize();
        assert_match!(Ok(PacketParserResult::Some(ref _pp)) = ppr);
    }
}
