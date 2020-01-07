//! Symmetrically Encrypted Integrity Protected data packets.
//!
//! An encrypted data packet is a container.  See [Section 5.13 of RFC
//! 4880] for details.
//!
//! [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13

use crate::packet;
use crate::Packet;

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 4880] for details.
///
/// [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct SEIP1 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// This is a container packet.
    container: packet::Container,
}

impl SEIP1 {
    /// Creates a new SEIP1 packet.
    pub fn new() -> Self {
        Self {
            common: Default::default(),
            container: Default::default(),
        }
    }
}

impl_container_forwards!(SEIP1);

impl From<SEIP1> for super::SEIP {
    fn from(p: SEIP1) -> Self {
        super::SEIP::V1(p)
    }
}

impl From<SEIP1> for Packet {
    fn from(s: SEIP1) -> Self {
        Packet::SEIP(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut s = SEIP1::new();
        assert_eq!(s.body(), &[]);
        s.set_body(vec![0, 1, 2]);
        assert_eq!(s.body(), &[0, 1, 2]);
    }
}
