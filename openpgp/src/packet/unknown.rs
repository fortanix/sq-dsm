use std::hash::{Hash, Hasher};
use std::cmp::Ordering;

use failure;

use crate::packet::Tag;
use crate::packet;
use crate::Packet;

/// Holds an unknown packet.
///
/// This is used by the parser to hold packets that it doesn't know
/// how to process rather than abort.
///
/// This packet effectively holds a binary blob.
#[derive(Debug)]
pub struct Unknown {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Packet tag.
    tag: Tag,
    /// Error that caused parsing or processing to abort.
    error: failure::Error,
    /// The unknown data packet is a container packet, but cannot
    /// store packets.
    ///
    /// This is written when serialized, and set by the packet parser
    /// if `buffer_unread_content` is used.
    container: packet::Container,
}

impl PartialEq for Unknown {
    fn eq(&self, other: &Unknown) -> bool {
        self.common == other.common
            && self.tag == other.tag
            && self.container == other.container
    }
}

impl Hash for Unknown {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.common.hash(state);
        self.tag.hash(state);
        self.container.hash(state);
    }
}

impl Clone for Unknown {
    fn clone(&self) -> Self {
        Unknown {
            common: self.common.clone(),
            tag: self.tag,
            error: failure::err_msg(format!("{}", self.error)),
            container: self.container.clone(),
        }
    }
}


impl Unknown {
    /// Returns a new `Unknown` packet.
    pub fn new(tag: Tag, error: failure::Error) -> Self {
        Unknown {
            common: Default::default(),
            tag: tag,
            error: error,
            container: Default::default(),
        }
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
    pub fn error(&self) -> &failure::Error {
        &self.error
    }

    /// Sets the unknown packet's error.
    ///
    /// This is the error that caused parsing or processing to abort.
    pub fn set_error(&mut self, error: failure::Error) -> failure::Error {
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
