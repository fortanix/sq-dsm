use std::convert::TryFrom;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    Result,
};

/// Identifies OpenPGP keys.
///
/// An `ID` is either a `Fingerprint` or a `KeyID`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum ID {
    /// A Fingerprint.
    Fingerprint(Fingerprint),
    /// A KeyID.
    KeyID(KeyID),
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ID::Fingerprint(v) => v.fmt(f),
            ID::KeyID(v) => v.fmt(f),
        }
    }
}

impl From<KeyID> for ID {
    fn from(i: KeyID) -> Self {
        ID::KeyID(i)
    }
}

impl From<ID> for KeyID {
    fn from(i: ID) -> Self {
        match i {
            ID::Fingerprint(i) => i.into(),
            ID::KeyID(i) => i,
        }
    }
}

impl From<Fingerprint> for ID {
    fn from(i: Fingerprint) -> Self {
        ID::Fingerprint(i)
    }
}

impl TryFrom<ID> for Fingerprint {
    type Error = failure::Error;
    fn try_from(i: ID) -> Result<Self> {
        match i {
            ID::Fingerprint(i) => Ok(i),
            ID::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}
