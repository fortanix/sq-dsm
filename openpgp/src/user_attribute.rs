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

    /// Gets the user attribute packet's value.
    pub fn user_attribute(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Sets the user attribute packet's value from a byte sequence.
    pub fn set_user_attribute(&mut self, value: &[u8]) {
        self.value = value.to_vec();
    }

    /// Convert the `UserAttribute` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::UserAttribute(self)
    }
}
