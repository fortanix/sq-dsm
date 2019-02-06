use failure;
use std::hash::{Hash, Hasher};

use packet::Tag;
use packet;
use Packet;

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
}

impl Eq for Unknown {}

impl PartialEq for Unknown {
    fn eq(&self, other: &Unknown) -> bool {
        self.common == other.common && self.tag == other.tag
    }
}

impl Hash for Unknown {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.common.hash(state);
        self.tag.hash(state);
    }
}

impl Clone for Unknown {
    fn clone(&self) -> Self {
        Unknown {
            common: self.common.clone(),
            tag: self.tag,
            error: failure::err_msg(format!("{}", self.error)),
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

    /// Sets the packet's contents.
    ///
    /// This is the raw packet content not include the CTB and length
    /// information, and not encoded using something like OpenPGP's
    /// partial body encoding.
    pub fn body(&self) -> Option<&[u8]> {
        self.common.body.as_ref().map(|b| b.as_slice())
    }

    /// Sets the packet's contents.
    ///
    /// This is the raw packet content not include the CTB and length
    /// information, and not encoded using something like OpenPGP's
    /// partial body encoding.
    pub fn set_body(&mut self, data: Vec<u8>) -> Option<Vec<u8>> {
        ::std::mem::replace(&mut self.common.body, Some(data))
    }
}

impl From<Unknown> for Packet {
    fn from(s: Unknown) -> Self {
        Packet::Unknown(s)
    }
}
