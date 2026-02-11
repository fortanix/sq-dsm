use std::borrow::Borrow;
use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::Fingerprint;
use crate::KeyHandle;
use crate::Result;

/// A short identifier for certificates and keys.
///
/// A `KeyID` identifies a public key.  It was used in [RFC 4880]: for
/// example to reference the issuing key of a signature in its
/// [`Issuer`] subpacket.  You should prefer [`Fingerprint`] over
/// [`KeyID`] in data structures, interfaces, and wire formats, unless
/// space is of the utmost concern.
///
/// Currently, Sequoia supports *version 6* fingerprints and Key IDs,
/// and *version 4* fingerprints and Key IDs.  *Version 3*
/// fingerprints and Key IDs were deprecated by [RFC 4880] in 2007.
///
/// *Version 6* and *version 4* [`KeyID`]s are a truncated version of
/// the key's fingerprint, which in turn is hash of the public key
/// packet.  As a general rule of thumb, you should prefer the
/// fingerprint as it is possible to create keys with a colliding
/// KeyID using a [birthday attack].
///
/// For more details about how a `KeyID` is generated, see [Section
/// 5.5.4 of RFC 9580].
///
/// In previous versions of OpenPGP, the Key ID used to be called
/// "long Key ID", as there even was a "short Key ID". At only 4 bytes
/// length, short Key IDs vulnerable to preimage attacks. That is, an
/// attacker can create a key with any given short Key ID in short
/// amount of time.
///
/// See also [`Fingerprint`] and [`KeyHandle`].
///
///   [RFC 4880]: https://tools.ietf.org/html/rfc4880
///   [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
///   [birthday attack]: https://nullprogram.com/blog/2019/07/22/
///   [`Issuer`]: crate::packet::signature::subpacket::SubpacketValue::Issuer
///   [`Fingerprint`]: crate::Fingerprint
///   [`KeyHandle`]: crate::KeyHandle
///
/// # Examples
///
/// ```rust
/// # fn main() -> sequoia_openpgp::Result<()> {
/// # use sequoia_openpgp as openpgp;
/// use openpgp::KeyID;
///
/// let id: KeyID = "0123 4567 89AB CDEF".parse()?;
///
/// assert_eq!("0123456789ABCDEF", id.to_hex());
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum KeyID {
    /// A long (8 bytes) key ID.
    ///
    /// For v4, this is the right-most 8 bytes of the v4 fingerprint.
    /// For v6, this is the left-most 8 bytes of the v6 fingerprint.
    Long([u8; 8]),

    /// Used for holding invalid keyids encountered during parsing
    /// e.g. wrong number of bytes.
    Invalid(Box<[u8]>),
}
assert_send_and_sync!(KeyID);

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::Debug for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("KeyID")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::UpperHex for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_to_fmt(f, true)
    }
}

impl fmt::LowerHex for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_to_fmt(f, false)
    }
}

impl std::str::FromStr for KeyID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.chars().filter(|c| ! c.is_whitespace()).count() % 2 == 1 {
            return Err(Error::InvalidArgument(
                "Odd number of nibbles".into()).into());
        }

        let bytes = crate::fmt::hex::decode_pretty(s)?;

        // A KeyID is exactly 8 bytes long.
        if bytes.len() == 8 {
            Ok(KeyID::from_bytes(&bytes[..]))
        } else if bytes.len() == 4 {
            Err(Error::ShortKeyID(s.to_string()).into())
        } else {
            // Maybe a fingerprint was given.  Try to parse it and
            // convert it to a KeyID.
            Ok(s.parse::<Fingerprint>()?.into())
        }
    }
}

impl From<KeyID> for Vec<u8> {
    fn from(id: KeyID) -> Self {
        let mut r = Vec::with_capacity(8);
        match id {
            KeyID::Long(ref b) => r.extend_from_slice(b),
            KeyID::Invalid(ref b) => r.extend_from_slice(b),
        }
        r
    }
}

impl From<u64> for KeyID {
    fn from(id: u64) -> Self {
        Self::new(id)
    }
}

impl From<[u8; 8]> for KeyID {
    fn from(id: [u8; 8]) -> Self {
        KeyID::from_bytes(&id[..])
    }
}

impl From<&Fingerprint> for KeyID {
    fn from(fp: &Fingerprint) -> Self {
        match fp {
            Fingerprint::V4(fp) =>
                KeyID::from_bytes(&fp[fp.len() - 8..]),
            Fingerprint::V6(fp) =>
                KeyID::from_bytes(&fp[..8]),
            Fingerprint::Unknown { bytes, .. } => {
                KeyID::Invalid(bytes.clone())
            }
        }
    }
}

impl From<Fingerprint> for KeyID {
    fn from(fp: Fingerprint) -> Self {
        match fp {
            Fingerprint::V4(fp) =>
                KeyID::from_bytes(&fp[fp.len() - 8..]),
            Fingerprint::V6(fp) =>
                KeyID::from_bytes(&fp[..8]),
            Fingerprint::Unknown { bytes, .. } => {
                KeyID::Invalid(bytes)
            }
        }
    }
}

impl KeyID {
    /// Converts a `u64` to a `KeyID`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// let keyid = KeyID::new(0x0123456789ABCDEF);
    /// ```
    pub fn new(data: u64) -> KeyID {
        let bytes = data.to_be_bytes();
        Self::from_bytes(&bytes[..])
    }

    /// Converts the `KeyID` to a `u64` if possible.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// let keyid = KeyID::new(0x0123456789ABCDEF);
    ///
    /// assert_eq!(keyid.as_u64()?, 0x0123456789ABCDEF);
    /// # Ok(()) }
    /// ```
    pub fn as_u64(&self) -> Result<u64> {
        match &self {
            KeyID::Long(ref b) =>
                Ok(u64::from_be_bytes(*b)),
            KeyID::Invalid(_) =>
                Err(Error::InvalidArgument("Invalid KeyID".into()).into()),
        }
    }

    /// Creates a `KeyID` from a big endian byte slice.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// let keyid: KeyID = "0123 4567 89AB CDEF".parse()?;
    ///
    /// let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    /// assert_eq!(KeyID::from_bytes(&bytes), keyid);
    /// # Ok(()) }
    /// ```
    pub fn from_bytes(raw: &[u8]) -> KeyID {
        if raw.len() == 8 {
            let mut keyid : [u8; 8] = Default::default();
            keyid.copy_from_slice(raw);
            KeyID::Long(keyid)
        } else {
            KeyID::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Returns a reference to the raw `KeyID` as a byte slice in big
    /// endian representation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// let keyid: KeyID = "0123 4567 89AB CDEF".parse()?;
    ///
    /// assert_eq!(keyid.as_bytes(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    /// # Ok(()) }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyID::Long(ref id) => id,
            KeyID::Invalid(ref id) => id,
        }
    }

    /// Creates a wildcard `KeyID`.
    ///
    /// Refer to [Section 5.1 of RFC 9580] for details.
    ///
    ///   [Section 5.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// assert_eq!(KeyID::wildcard(), KeyID::new(0x0000000000000000));
    /// ```
    pub fn wildcard() -> Self {
        Self::from_bytes(&[0u8; 8][..])
    }

    /// Returns `true` if this is the wildcard `KeyID`.
    ///
    /// Refer to [Section 5.1 of RFC 9580] for details.
    ///
    ///   [Section 5.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// assert!(KeyID::new(0x0000000000000000).is_wildcard());
    /// ```
    pub fn is_wildcard(&self) -> bool {
        self.as_bytes().iter().all(|b| *b == 0)
    }

    /// Converts this `KeyID` to its canonical hexadecimal
    /// representation.
    ///
    /// This representation is always uppercase and without spaces and
    /// is suitable for stable key identifiers.
    ///
    /// The output of this function is exactly the same as formatting
    /// this object with the `:X` format specifier.
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// let keyid: KeyID = "fb3751f1587daef1".parse()?;
    ///
    /// assert_eq!("FB3751F1587DAEF1", keyid.to_hex());
    /// assert_eq!(format!("{:X}", keyid), keyid.to_hex());
    /// # Ok(()) }
    /// ```
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;

        let raw_len = self.as_bytes().len();
        let mut output = String::with_capacity(
            // Each byte results in two hex characters.
            raw_len * 2);

        // We write to String that never fails but the Write API
        // returns Results.
        write!(output, "{:X}", self).unwrap();

        output
    }

    /// Converts this `KeyID` to its hexadecimal representation with
    /// spaces.
    ///
    /// This representation is always uppercase and with spaces
    /// grouping the hexadecimal digits into groups of four.  It is
    /// suitable for manual comparison of Key IDs.
    ///
    /// Note: The spaces will hinder other kind of use cases.  For
    /// example, it is harder to select the whole Key ID for copying,
    /// and it has to be quoted when used as a command line argument.
    /// Only use this form for displaying a Key ID with the intent of
    /// manual comparisons.
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// let keyid: openpgp::KeyID = "fb3751f1587daef1".parse()?;
    ///
    /// assert_eq!("FB37 51F1 587D AEF1", keyid.to_spaced_hex());
    /// # Ok(()) }
    /// ```
    pub fn to_spaced_hex(&self) -> String {
        use std::fmt::Write;

        let raw_len = self.as_bytes().len();
        let mut output = String::with_capacity(
            // Each byte results in two hex characters.
            raw_len * 2
            +
            // Every 2 bytes of output, we insert a space.
            raw_len / 2);

        // We write to String that never fails but the Write API
        // returns Results.
        write!(output, "{:#X}", self).unwrap();

        output
    }

    /// Parses the hexadecimal representation of an OpenPGP `KeyID`.
    ///
    /// This function is the reverse of `to_hex`. It also accepts
    /// other variants of the `keyID` notation including lower-case
    /// letters, spaces and optional leading `0x`.
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    ///
    /// let keyid = KeyID::from_hex("0xfb3751f1587daef1")?;
    ///
    /// assert_eq!("FB3751F1587DAEF1", keyid.to_hex());
    /// # Ok(()) }
    /// ```
    pub fn from_hex(s: &str) -> std::result::Result<Self, anyhow::Error> {
        std::str::FromStr::from_str(s)
    }

    /// Common code for the above functions.
    fn write_to_fmt(&self, f: &mut fmt::Formatter, upper_case: bool) -> fmt::Result {
        use std::fmt::Write;

        let a_letter = if upper_case { b'A' } else { b'a' };
        let pretty = f.alternate();

        let raw = match self {
            KeyID::Long(ref fp) => &fp[..],
            KeyID::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle long Key IDs, which look like:
        //
        //   AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid Key ID, just
        // format it like a V4 fingerprint and hope for the best.

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                f.write_char(' ')?;
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                f.write_char((b'0' + top) as char)?;
            } else {
                f.write_char((a_letter + (top - 10u8)) as char)?;
            }

            if bottom < 10u8 {
                f.write_char((b'0' + bottom) as char)?;
            } else {
                f.write_char((a_letter + (bottom - 10u8)) as char)?;
            }
        }

        Ok(())
    }
    /// Returns whether `self` and `other` could be aliases of each
    /// other.
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
    /// [transitive]: std::cmp::PartialEq
    ///
    /// That is, if `fpr1` and `fpr2` are distinct fingerprints with the
    /// same key ID then:
    ///
    /// ```text
    /// fpr1 == keyid and fpr2 == keyid, but fpr1 != fpr2.
    /// ```
    ///
    /// This definition of equality makes searching for a given
    /// `KeyHandle` using `PartialEq` awkward.  This function fills
    /// that gap.  It answers the question: given a `KeyHandle` and a
    /// `KeyID`, could they be aliases?  That is, it implements the
    /// desired, non-transitive equality relation:
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::KeyID;
    /// # use openpgp::KeyHandle;
    /// #
    /// # let fpr1: Fingerprint
    /// #     = "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>()?;
    /// #
    /// # let fpr2: Fingerprint
    /// #     = "0123 4567 8901 2345 6789  0123 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>()?;
    /// #
    /// # let keyid: KeyID = "AACB 3243 6300 52D9".parse::<KeyID>()?;
    /// #
    /// // fpr1 and fpr2 are different fingerprints with the same KeyID.
    /// assert_ne!(fpr1, fpr2);
    /// assert_eq!(KeyID::from(&fpr1), KeyID::from(&fpr2));
    /// assert!(keyid.aliases(KeyHandle::from(&fpr1)));
    /// assert!(keyid.aliases(KeyHandle::from(&fpr2)));
    /// # Ok(()) }
    /// ```
    pub fn aliases<H>(&self, other: H) -> bool
        where H: Borrow<KeyHandle>
    {
        let other = other.borrow();

        match (self, other) {
            (k, KeyHandle::KeyID(o)) => {
                k == o
            },
            (KeyID::Long(k), KeyHandle::Fingerprint(Fingerprint::V4(o))) => {
                // Avoid a heap allocation by embedding our
                // knowledge of how a v4 key ID is derived from a
                // v4 fingerprint:
                //
                // A v4 key ID are the 8 right-most octets of a v4
                // fingerprint.
                &o[12..] == k
            },

            (KeyID::Long(k), KeyHandle::Fingerprint(Fingerprint::V6(f))) => {
                // A v6 key ID are the 8 left-most octets of a v6
                // fingerprint.
                k == &f[..8]
            },

            (k, o) => {
                k == &KeyID::from(o)
            },
        }
    }
}

#[cfg(test)]
impl Arbitrary for KeyID {
    fn arbitrary(g: &mut Gen) -> Self {
        KeyID::new(u64::arbitrary(g))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    quickcheck! {
        fn u64_roundtrip(id: u64) -> bool {
            KeyID::new(id).as_u64().unwrap() == id
        }
    }

    #[test]
    fn from_hex() {
        "FB3751F1587DAEF1".parse::<KeyID>().unwrap();
        "39D100AB67D5BD8C04010205FB3751F1587DAEF1".parse::<KeyID>()
            .unwrap();
        "0xFB3751F1587DAEF1".parse::<KeyID>().unwrap();
        "0x39D100AB67D5BD8C04010205FB3751F1587DAEF1".parse::<KeyID>()
            .unwrap();
        "FB37 51F1 587D AEF1".parse::<KeyID>().unwrap();
        "39D1 00AB 67D5 BD8C 0401  0205 FB37 51F1 587D AEF1".parse::<KeyID>()
            .unwrap();
        "GB3751F1587DAEF1".parse::<KeyID>().unwrap_err();
        "EFB3751F1587DAEF1".parse::<KeyID>().unwrap_err();
        "%FB3751F1587DAEF1".parse::<KeyID>().unwrap_err();
    }

    #[test]
    fn from_hex_short_keyid() {
        for s in &[ "FB3751F1", "0xFB3751F1", "fb3751f1",  "0xfb3751f1" ] {
            match s.parse::<KeyID>() {
                Ok(_) => panic!("Failed to reject short Key ID."),
                Err(err) => {
                    let err = err.downcast_ref::<Error>().unwrap();
                    assert!(matches!(err, Error::ShortKeyID(_)));
                }
            }
        }
    }

    #[test]
    fn hex_formatting() {
        let keyid = "FB3751F1587DAEF1".parse::<KeyID>().unwrap();
        assert_eq!(format!("{:X}", keyid), "FB3751F1587DAEF1");
        assert_eq!(format!("{:x}", keyid), "fb3751f1587daef1");
    }

    #[test]
    fn aliases() -> crate::Result<()> {
        // fp1 and fp15 have the same key ID, but are different
        // fingerprints.
        let fp1 = "280C0AB0B94D1302CAAEB71DA299CDCD3884EBEA"
            .parse::<Fingerprint>()?;
        let fp15 = "1234567890ABCDEF12345678A299CDCD3884EBEA"
            .parse::<Fingerprint>()?;
        let fp2 = "F8D921C01EE93B65D4C6FEB7B456A7DB5E4274D0"
            .parse::<Fingerprint>()?;

        let keyid1 = KeyID::from(&fp1);
        let keyid15 = KeyID::from(&fp15);
        let keyid2 = KeyID::from(&fp2);

        eprintln!("fp1: {:?}", fp1);
        eprintln!("keyid1: {:?}", keyid1);
        eprintln!("fp15: {:?}", fp15);
        eprintln!("keyid15: {:?}", keyid15);
        eprintln!("fp2: {:?}", fp2);
        eprintln!("keyid2: {:?}", keyid2);

        assert_ne!(fp1, fp15);
        assert_eq!(keyid1, keyid15);

        assert!(keyid1.aliases(KeyHandle::from(&fp1)));
        assert!(keyid1.aliases(KeyHandle::from(&fp15)));
        assert!(! keyid1.aliases(KeyHandle::from(&fp2)));

        assert!(keyid15.aliases(KeyHandle::from(&fp1)));
        assert!(keyid15.aliases(KeyHandle::from(&fp15)));
        assert!(! keyid15.aliases(KeyHandle::from(&fp2)));

        assert!(! keyid2.aliases(KeyHandle::from(&fp1)));
        assert!(! keyid2.aliases(KeyHandle::from(&fp15)));
        assert!(keyid2.aliases(KeyHandle::from(&fp2)));

        Ok(())
    }
}
