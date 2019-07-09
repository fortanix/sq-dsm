use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::packet::{self, Common};
use crate::Packet;
use crate::Container;
use crate::constants::CompressionAlgorithm;

/// Holds a compressed data packet.
///
/// A compressed data packet is a container.  See [Section 5.6 of RFC
/// 4880] for details.
///
/// When the parser encounters a compressed data packet with an
/// unknown compress algorithm, it returns an `Unknown` packet instead
/// of a `CompressedData` packet.
///
/// [Section 5.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.6
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct CompressedData {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Algorithm used to compress the payload.
    algo: CompressionAlgorithm,
}

impl fmt::Debug for CompressedData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CompressedData")
            .field("algo", &self.algo)
            .field("children",
                   &self.common.children.as_ref()
                       .map(|c| &c.packets).unwrap_or(&Vec::new()))
            .field("body (bytes)",
                   &self.common.body.as_ref().unwrap_or(&b"".to_vec()).len())
            .finish()
    }
}

impl CompressedData {
    /// Returns a new `CompressedData` packet.
    pub fn new(algo: CompressionAlgorithm) -> Self {
        CompressedData {
            common: Default::default(),
            algo: algo,
        }
    }

    /// Gets the compression algorithm.
    pub fn algorithm(&self) -> CompressionAlgorithm {
        self.algo
    }

    /// Sets the compression algorithm.
    pub fn set_algorithm(&mut self, algo: CompressionAlgorithm) -> CompressionAlgorithm {
        ::std::mem::replace(&mut self.algo, algo)
    }

    /// Adds a new packet to the container.
    pub fn push(mut self, packet: Packet) -> Self {
        if self.common.children.is_none() {
            self.common.children = Some(Container::new());
        }
        self.common.children.as_mut().unwrap().push(packet);
        self
    }

    /// Inserts a new packet to the container at a particular index.
    /// If `i` is 0, the new packet is insert at the front of the
    /// container.  If `i` is one, it is inserted after the first
    /// packet, etc.
    pub fn insert(mut self, i: usize, packet: Packet) -> Self {
        if self.common.children.is_none() {
            self.common.children = Some(Container::new());
        }
        self.common.children.as_mut().unwrap().insert(i, packet);
        self
    }
}

impl From<CompressedData> for Packet {
    fn from(s: CompressedData) -> Self {
        Packet::CompressedData(s)
    }
}

// Allow transparent access of common fields.
impl<'a> Deref for CompressedData {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

// Allow transparent access of common fields.
impl<'a> DerefMut for CompressedData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
