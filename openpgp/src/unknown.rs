use Tag;
use Unknown;
use Packet;

impl Unknown {
    /// Returns a new `Unknown` packet.
    pub fn new(tag: Tag) -> Self {
        Unknown {
            common: Default::default(),
            tag: tag,
        }
    }

    /// Sets the unknown packet's tag.
    pub fn tag(mut self, tag: Tag) -> Self {
        self.tag = tag;
        self
    }

    /// Sets the packet's contents.
    ///
    /// This is the raw packet content not include the CTB and length
    /// information, and not encoded using something like OpenPGP's
    /// partial body encoding.
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.common.body = Some(data);
        self
    }

    /// Convert the `Unknown` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Unknown(self)
    }
}
