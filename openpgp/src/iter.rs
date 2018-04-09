use std::slice;
use std::vec;

use Packet;
use Message;
use packet::{Container, PacketIter};

impl Message {
    /// Turns a vector of [`Packet`s] into a `Message`.
    ///
    /// This is a simple wrapper function; it does not process the
    /// packets in any way.
    ///
    ///   [`Packet`s]: struct.Packet.html
    pub fn from_packets(p: Vec<Packet>) -> Self {
        Message { top_level: Container { packets: p } }
    }

    /// Turns a  [`Packet`] into a `Message`.
    ///
    /// This is a simple wrapper function; it does not process the
    /// packets in any way.
    ///
    ///   [`Packet`]: struct.Packet.html
    pub fn from_packet(p: Packet) -> Self {
        let mut top_level = Vec::with_capacity(1);
        top_level.push(p);
        Self::from_packets(top_level)
    }

    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub fn descendants(&self) -> PacketIter {
        self.top_level.descendants()
    }

    /// Returns an iterator over the top-level packets.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.top_level.children()
    }

    /// Returns an `IntoIter` over the top-level packets.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.top_level.into_children()
    }
}
