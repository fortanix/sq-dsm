use std::convert::TryFrom;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    Result,
};

/// Identifies OpenPGP keys.
///
/// An `KeyHandle` is either a `Fingerprint` or a `KeyID`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum KeyHandle {
    /// A Fingerprint.
    Fingerprint(Fingerprint),
    /// A KeyID.
    KeyID(KeyID),
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyHandle::Fingerprint(v) => v.fmt(f),
            KeyHandle::KeyID(v) => v.fmt(f),
        }
    }
}

impl From<KeyID> for KeyHandle {
    fn from(i: KeyID) -> Self {
        KeyHandle::KeyID(i)
    }
}

impl From<KeyHandle> for KeyID {
    fn from(i: KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.into(),
            KeyHandle::KeyID(i) => i,
        }
    }
}

impl From<Fingerprint> for KeyHandle {
    fn from(i: Fingerprint) -> Self {
        KeyHandle::Fingerprint(i)
    }
}

impl TryFrom<KeyHandle> for Fingerprint {
    type Error = failure::Error;
    fn try_from(i: KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}
