use std::fmt;

use UserID;
use Packet;

impl fmt::Display for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);
        write!(f, "{}", userid)
    }
}

impl fmt::Debug for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);

        f.debug_struct("UserID")
            .field("value", &userid)
            .finish()
    }
}

impl UserID {
    /// Returns a new `UserID` packet.
    pub fn new() -> UserID {
        UserID {
            common: Default::default(),
            value: Vec::new(),
        }
    }

    /// Gets the user ID packet's value.
    pub fn userid(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Sets the user ID packet's value from a byte sequence.
    pub fn set_userid_from_bytes(&mut self, userid: &[u8]) {
        self.value = userid.to_vec();
    }

    /// Sets the user ID packet's value from a UTF-8 encoded string.
    pub fn set_userid(&mut self, userid: &str) {
        self.set_userid_from_bytes(userid.as_bytes())
    }

    /// Convert the `UserID` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::UserID(self)
    }
}
