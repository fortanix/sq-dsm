use std::fmt;
use quickcheck::{Arbitrary, Gen};

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
    value: Vec<u8>,
}

impl From<Vec<u8>> for UserID {
    fn from(u: Vec<u8>) -> Self {
        UserID {
            common: Default::default(),
            value: u,
        }
    }
}

impl<'a> From<&'a str> for UserID {
    fn from(u: &'a str) -> Self {
        let b = u.as_bytes();
        let mut v = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        v.into()
    }
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
    pub fn set_userid_from_bytes(&mut self, userid: &[u8]) -> Vec<u8> {
        ::std::mem::replace(&mut self.value, userid.to_vec())
    }

    /// Sets the user ID packet's value from a UTF-8 encoded string.
    pub fn set_userid(&mut self, userid: &str) -> Vec<u8> {
        self.set_userid_from_bytes(userid.as_bytes())
    }
}

impl From<UserID> for Packet {
    fn from(s: UserID) -> Self {
        Packet::UserID(s)
    }
}

impl Arbitrary for UserID {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut u = UserID::new();
        u.set_userid_from_bytes(&Vec::<u8>::arbitrary(g));
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::Parse;
    use serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: UserID) -> bool {
            let q = UserID::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
