use std::fmt;

use packet;
use Packet;

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct UserID {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// The user id.
    ///
    /// According to [RFC 4880], the text is by convention UTF-8 encoded
    /// and in "mail name-addr" form, i.e., "Name (Comment)
    /// <email@example.com>".
    ///
    ///   [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
    ///
    /// Use `UserID::default()` to get a UserID with a default settings.
    pub(crate) value: Vec<u8>,
}

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
