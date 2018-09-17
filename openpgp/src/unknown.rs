use Tag;
use packet;
use Packet;

/// Holds an unknown packet.
///
/// This is used by the parser to hold packets that it doesn't know
/// how to process rather than abort.
///
/// This packet effectively holds a binary blob.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Unknown {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Packet tag.
    pub(crate) tag: Tag,
}

impl Unknown {
    /// Returns a new `Unknown` packet.
    pub fn new(tag: Tag) -> Self {
        Unknown {
            common: Default::default(),
            tag: tag,
        }
    }

    /// Gets the unknown packet's tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Sets the unknown packet's tag.
    pub fn set_tag(&mut self, tag: Tag) {
        self.tag = tag;
    }

    /// Sets the packet's contents.
    ///
    /// This is the raw packet content not include the CTB and length
    /// information, and not encoded using something like OpenPGP's
    /// partial body encoding.
    pub fn body(&self) -> Option<&[u8]> {
        self.common.body.as_ref().map(|b| b.as_slice())
    }

    /// Sets the packet's contents.
    ///
    /// This is the raw packet content not include the CTB and length
    /// information, and not encoded using something like OpenPGP's
    /// partial body encoding.
    pub fn set_body(&mut self, data: Vec<u8>) {
        self.common.body = Some(data);
    }

    /// Convert the `Unknown` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Unknown(self)
    }
}

impl From<Unknown> for Packet {
    fn from(s: Unknown) -> Self {
        s.to_packet()
    }
}
