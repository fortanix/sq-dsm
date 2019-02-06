use nettle;
use packet;
use Packet;

/// Holds an MDC packet.
///
/// A modification detection code packet.  This packet appears after a
/// SEIP packet.  See [Section 5.14 of RFC 4880] for details.
///
/// [Section 5.14 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.14
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct MDC {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Our SHA-1 hash.
    computed_hash: [u8; 20],
    /// A 20-octet SHA-1 hash of the preceding plaintext data.
    hash: [u8; 20],
}

impl MDC {
    /// Creates an MDC packet.
    pub(crate) fn new_(hash: [u8; 20], computed_hash: [u8; 20]) -> Self {
        MDC {
            common: Default::default(),
            computed_hash: computed_hash,
            hash: hash,
        }
    }

    /// Gets the packet's hash value.
    pub fn hash(&self) -> &[u8] {
        &self.hash[..]
    }

    /// Gets the computed hash value.
    pub fn computed_hash(&self) -> &[u8] {
        &self.computed_hash[..]
    }

    /// Returns whether the data protected by the MDC is valid.
    pub fn valid(&self) -> bool {
        if self.hash == [ 0; 20 ] {
            // If the computed_hash and hash are uninitialized, then
            // return false.
            false
        } else {
            self.computed_hash == self.hash
        }
    }
}

impl From<MDC> for Packet {
    fn from(s: MDC) -> Self {
        Packet::MDC(s)
    }
}

impl From<[u8; 20]> for MDC {
    fn from(hash: [u8; 20]) -> Self {
        MDC {
            common: Default::default(),
            // All 0s.
            computed_hash: Default::default(),
            hash: hash,
        }
    }
}

impl From<Box<nettle::Hash>> for MDC {
    fn from(mut hash: Box<nettle::Hash>) -> Self {
        let mut value : [u8; 20] = Default::default();
        hash.digest(&mut value[..]);
        value.into()
    }
}

