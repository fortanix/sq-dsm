use std::ops::{Deref, DerefMut};
use packet::{self, Common};
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
    version: u8,
}

impl SEIP {
    pub(crate) fn new() -> Self {
        Self {
            common: Default::default(),
            version: 1,
        }
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }
}

impl From<SEIP> for Packet {
    fn from(s: SEIP) -> Self {
        Packet::SEIP(s)
    }
}

// Allow transparent access of common fields.
impl<'a> Deref for SEIP {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

// Allow transparent access of common fields.
impl<'a> DerefMut for SEIP {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut s = SEIP {
            common: Default::default(),
            version: 1,
        };
        assert_eq!(s.body(), None);
        s.set_body(vec![0, 1, 2]);
        assert_eq!(s.body(), Some(&[0, 1, 2][..]));
    }
}
