use std::convert::TryFrom;
use std::cmp;
use std::cmp::Ordering;
use std::borrow::Borrow;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    Result,
};

/// Identifies certificates and keys.
///
/// A `KeyHandle` is either a `Fingerprint` or a `KeyID`.
#[derive(Debug, Clone)]
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

impl std::fmt::UpperHex for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            KeyHandle::Fingerprint(ref fpr) => write!(f, "{:X}", fpr),
            KeyHandle::KeyID(ref keyid) => write!(f, "{:X}", keyid),
        }
    }
}

impl std::fmt::LowerHex for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            KeyHandle::Fingerprint(ref fpr) => write!(f, "{:x}", fpr),
            KeyHandle::KeyID(ref keyid) => write!(f, "{:x}", keyid),
        }
    }
}

impl From<KeyID> for KeyHandle {
    fn from(i: KeyID) -> Self {
        KeyHandle::KeyID(i)
    }
}

impl From<&KeyID> for KeyHandle {
    fn from(i: &KeyID) -> Self {
        KeyHandle::KeyID(i.clone())
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

impl From<&KeyHandle> for KeyID {
    fn from(i: &KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.clone().into(),
            KeyHandle::KeyID(i) => i.clone(),
        }
    }
}

impl From<Fingerprint> for KeyHandle {
    fn from(i: Fingerprint) -> Self {
        KeyHandle::Fingerprint(i)
    }
}

impl From<&Fingerprint> for KeyHandle {
    fn from(i: &Fingerprint) -> Self {
        KeyHandle::Fingerprint(i.clone())
    }
}

impl TryFrom<KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl TryFrom<&KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: &KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i.clone()),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl PartialOrd for KeyHandle {
    fn partial_cmp(&self, other: &KeyHandle) -> Option<Ordering> {
        let a = self.as_bytes();
        let b = other.as_bytes();

        let l = cmp::min(a.len(), b.len());

        // Do a little endian comparison so that for v4 keys (where
        // the KeyID is a suffix of the Fingerprint) equivalent KeyIDs
        // and Fingerprints sort next to each other.
        for (a, b) in a[a.len()-l..].iter().zip(b[b.len()-l..].iter()) {
            let cmp = a.cmp(b);
            if cmp != Ordering::Equal {
                return Some(cmp);
            }
        }

        if a.len() == b.len() {
            Some(Ordering::Equal)
        } else {
            // One (a KeyID) is the suffix of the other (a
            // Fingerprint).
            None
        }
    }
}

impl PartialEq for KeyHandle {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl KeyHandle {
    /// Returns a reference to the raw identifier.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyHandle::Fingerprint(i) => i.as_bytes(),
            KeyHandle::KeyID(i) => i.as_bytes(),
        }
    }

    /// Returns whether `self` and `other` could be aliases of each other.
    ///
    /// `KeyHandle`'s `PartialEq` implementation cannot assert that a
    /// `Fingerprint` and a `KeyID` are equal, because distinct
    /// fingerprints may have the same `KeyID`, and `PartialEq` must
    /// be [transitive], i.e.,
    ///
    /// ```text
    /// a == b and b == c implies a == c.
    /// ```
    ///
    /// [transitive]: https://doc.rust-lang.org/std/cmp/trait.PartialEq.html
    ///
    /// That is, if `fpr1` and `fpr2` are distinct fingerprints with the
    /// same key ID then:
    ///
    /// ```text
    /// fpr1 == keyid and fpr2 == keyid, but fpr1 != fpr2.
    /// ```
    ///
    /// In these cases (and only these cases) `KeyHandle`'s
    /// `PartialOrd` implementation returns `None` to correctly
    /// indicate that a comparison is not possible.
    ///
    /// This definition of equality makes searching for a given
    /// `KeyHandle` using `PartialEq` awkward.  This function fills
    /// that gap.  It answers the question: given two `KeyHandles`,
    /// could they be aliases?  That is, it implements the desired,
    /// non-transitive equality relation:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::KeyID;
    /// # use openpgp::KeyHandle;
    /// #
    /// # let fpr1 : KeyHandle
    /// #     = "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>().unwrap().into();
    /// #
    /// # let fpr2 : KeyHandle
    /// #     = "0123 4567 8901 2345 6789  0123 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>().unwrap().into();
    /// #
    /// # let keyid : KeyHandle = "AACB 3243 6300 52D9".parse::<KeyID>()
    /// #     .unwrap().into();
    /// #
    /// // fpr1 and fpr2 are different fingerprints with the same KeyID.
    /// assert!(! fpr1.eq(&fpr2));
    /// assert!(fpr1.aliases(&keyid));
    /// assert!(fpr2.aliases(&keyid));
    /// assert!(! fpr1.aliases(&fpr2));
    /// ```
    pub fn aliases<H>(&self, other: H) -> bool
        where H: Borrow<KeyHandle>
    {
        // This works, because the PartialOrd implementation only
        // returns None if one value is a fingerprint and the other is
        // a key id that matches the fingerprint's key id.
        self.partial_cmp(other.borrow()).unwrap_or(Ordering::Equal)
            == Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upper_hex_formatting() {
        let handle = KeyHandle::Fingerprint(Fingerprint::V4([1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]));
        assert_eq!(format!("{:X}", handle), "0102030405060708090A0B0C0D0E0F1011121314");

        let handle = KeyHandle::Fingerprint(Fingerprint::Invalid(Box::new([10, 2, 3, 4])));
        assert_eq!(format!("{:X}", handle), "0A020304");

        let handle = KeyHandle::KeyID(KeyID::V4([10, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(format!("{:X}", handle), "0A02030405060708");

        let handle = KeyHandle::KeyID(KeyID::Invalid(Box::new([10, 2])));
        assert_eq!(format!("{:X}", handle), "0A02");
    }

    #[test]
    fn lower_hex_formatting() {
        let handle = KeyHandle::Fingerprint(Fingerprint::V4([1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]));
        assert_eq!(format!("{:x}", handle), "0102030405060708090a0b0c0d0e0f1011121314");

        let handle = KeyHandle::Fingerprint(Fingerprint::Invalid(Box::new([10, 2, 3, 4])));
        assert_eq!(format!("{:x}", handle), "0a020304");

        let handle = KeyHandle::KeyID(KeyID::V4([10, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(format!("{:x}", handle), "0a02030405060708");

        let handle = KeyHandle::KeyID(KeyID::Invalid(Box::new([10, 2])));
        assert_eq!(format!("{:x}", handle), "0a02");
    }

}
