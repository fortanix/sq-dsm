use std::hash::{Hash, Hasher};
use std::cmp::Ordering;

use crate::packet::Tag;
use crate::packet;
use crate::Packet;
use crate::policy::HashAlgoSecurity;

/// Holds an unknown packet.
///
/// This is used by the parser to hold packets that it doesn't know
/// how to process rather than abort.
///
/// This packet effectively holds a binary blob.
///
/// # A note on equality
///
/// Two `Unknown` packets are considered equal if their tags and their
/// bodies are equal.
#[derive(Debug)]
pub struct Unknown {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Packet tag.
    tag: Tag,
    /// Error that caused parsing or processing to abort.
    error: anyhow::Error,
    /// The unknown data packet is a container packet, but cannot
    /// store packets.
    ///
    /// This is written when serialized, and set by the packet parser
    /// if `buffer_unread_content` is used.
    container: packet::Container,
}

assert_send_and_sync!(Unknown);

impl PartialEq for Unknown {
    fn eq(&self, other: &Unknown) -> bool {
        self.tag == other.tag
            && self.container == other.container
    }
}

impl Eq for Unknown { }

impl Hash for Unknown {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tag.hash(state);
        self.container.hash(state);
    }
}

impl Clone for Unknown {
    fn clone(&self) -> Self {
        Unknown {
            common: self.common.clone(),
            tag: self.tag,
            error: anyhow::anyhow!("{}", self.error),
            container: self.container.clone(),
        }
    }
}


impl Unknown {
    /// Returns a new `Unknown` packet.
    pub fn new(tag: Tag, error: anyhow::Error) -> Self {
        Unknown {
            common: Default::default(),
            tag,
            error,
            container: packet::Container::default_unprocessed(),
        }
    }

    /// The security requirements of the hash algorithm for
    /// self-signatures.
    ///
    /// A cryptographic hash algorithm usually has [three security
    /// properties]: pre-image resistance, second pre-image
    /// resistance, and collision resistance.  If an attacker can
    /// influence the signed data, then the hash algorithm needs to
    /// have both second pre-image resistance, and collision
    /// resistance.  If not, second pre-image resistance is
    /// sufficient.
    ///
    ///   [three security properties]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Properties
    ///
    /// In general, an attacker may be able to influence third-party
    /// signatures.  But direct key signatures, and binding signatures
    /// are only over data fully determined by signer.  And, an
    /// attacker's control over self signatures over User IDs is
    /// limited due to their structure.
    ///
    /// These observations can be used to extend the life of a hash
    /// algorithm after its collision resistance has been partially
    /// compromised, but not completely broken.  For more details,
    /// please refer to the documentation for [HashAlgoSecurity].
    ///
    ///   [HashAlgoSecurity]: super::policy::HashAlgoSecurity
    pub fn hash_algo_security(&self) -> HashAlgoSecurity {
        HashAlgoSecurity::CollisionResistance
    }

    /// Gets the unknown packet's tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Sets the unknown packet's tag.
    pub fn set_tag(&mut self, tag: Tag) -> Tag {
        ::std::mem::replace(&mut self.tag, tag)
    }

    /// Gets the unknown packet's error.
    ///
    /// This is the error that caused parsing or processing to abort.
    pub fn error(&self) -> &anyhow::Error {
        &self.error
    }

    /// Sets the unknown packet's error.
    ///
    /// This is the error that caused parsing or processing to abort.
    pub fn set_error(&mut self, error: anyhow::Error) -> anyhow::Error {
        ::std::mem::replace(&mut self.error, error)
    }

    /// Best effort Ord implementation.
    ///
    /// The Cert canonicalization needs to order Unknown packets.
    /// However, due to potential streaming, Unknown cannot implement
    /// Eq.  This is cheating a little, we simply ignore the streaming
    /// case.
    pub(crate) // For cert/mod.rs
    fn best_effort_cmp(&self, other: &Unknown) -> Ordering {
        self.tag.cmp(&other.tag).then_with(|| self.body().cmp(&other.body()))
    }
}

impl_body_forwards!(Unknown);

impl From<Unknown> for Packet {
    fn from(s: Unknown) -> Self {
        Packet::Unknown(s)
    }
}
