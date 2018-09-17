use packet;
use Packet;

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 4880] for details.
///
/// [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct SEIP {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// SEIP version. Must be 1.
    pub(crate) version: u8,
}

impl SEIP {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Convert the `SEIP` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::SEIP(self)
    }
}

