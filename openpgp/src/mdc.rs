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
    pub(crate) computed_hash: [u8; 20],
    /// A 20-octet SHA-1 hash of the preceding plaintext data.
    pub(crate) hash: [u8; 20],
}

impl MDC {
    /// Creates a new MDC packet for the data hashed into `hash` Hash context.
    pub fn new(hash: &mut nettle::Hash) -> Self {
        let mut value : [u8; 20] = Default::default();
        hash.digest(&mut value[..]);

        Self::for_hash(value)
    }

    /// Creates an MDC packet containing the hash value `hash`.
    pub fn for_hash(hash: [u8; 20]) -> Self {
        MDC {
            common: Default::default(),
            // All 0s.
            computed_hash: Default::default(),
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

    /// Converts the `MDC` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::MDC(self)
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

