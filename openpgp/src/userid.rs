use std::fmt;

use PacketCommon;
use UserID;
use Packet;

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
            common: PacketCommon::default(),
            value: Vec::new(),
        }
    }

    /// Sets the user ID packet's filename field from a byte sequence.
    pub fn userid_from_bytes(mut self, userid: &[u8]) -> UserID {
        self.value = userid.to_vec();
        self
    }

    /// Sets the user ID packet's filename field from a UTF-8 encoded
    /// string.
    pub fn userid(self, userid: &str) -> UserID {
        self.userid_from_bytes(userid.as_bytes())
    }

    /// Convert the `UserID` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::UserID(self)
    }
}
