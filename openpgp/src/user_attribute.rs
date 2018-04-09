use std::fmt;

use UserAttribute;
use Packet;

impl fmt::Debug for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserAttribute")
            .field("value (bytes)", &self.value.len())
            .finish()
    }
}

impl UserAttribute {
    /// Returns a new `UserAttribute` packet.
    pub fn new() -> UserAttribute {
        UserAttribute {
            common: Default::default(),
            value: Vec::new(),
        }
    }

    /// Sets the user ID packet's value field from a byte sequence.
    pub fn user_attribute_from_bytes(mut self, value: &[u8])
            -> UserAttribute {
        self.value = value.to_vec();
        self
    }

    /// Convert the `UserAttribute` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::UserAttribute(self)
    }
}
