//! Symmetrically Encrypted Integrity Protected data packets.
//!
//! An encrypted data packet is a container.  See [Section 5.13 of RFC
//! 4880] for details.
//!
//! [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13

use std::ops::{Deref, DerefMut};
use crate::packet::{self, Common};
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
}

impl SEIP1 {
    /// Creates a new SEIP1 packet.
    pub fn new() -> Self {
        Self {
            common: Default::default(),
        }
    }
}

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

// Allow transparent access of common fields.
impl<'a> Deref for SEIP1 {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

// Allow transparent access of common fields.
impl<'a> DerefMut for SEIP1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut s = SEIP1 {
            common: Default::default(),
        };
        assert_eq!(s.body(), None);
        s.set_body(vec![0, 1, 2]);
        assert_eq!(s.body(), Some(&[0, 1, 2][..]));
    }
}
