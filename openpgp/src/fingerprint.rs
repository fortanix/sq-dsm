use std::borrow::Borrow;
use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::KeyHandle;
use crate::KeyID;
use crate::Result;

/// A long identifier for certificates and keys.
///
/// A `Fingerprint` uniquely identifies a public key.
///
/// Currently, Sequoia supports *version 6* fingerprints and Key IDs,
/// and *version 4* fingerprints and Key IDs.  *Version 3*
/// fingerprints and Key IDs were deprecated by [RFC 4880] in 2007.
///
/// Essentially, a fingerprint is a hash over the key's public key
/// packet.  For details, see [Section 5.5.4 of RFC 9580].
///
/// Fingerprints are used, for example, to reference the issuing key
/// of a signature in its [`IssuerFingerprint`] subpacket.  As a
/// general rule of thumb, you should prefer using fingerprints over
/// KeyIDs because the latter are vulnerable to [birthday attack]s.
///
/// See also [`KeyID`] and [`KeyHandle`].
///
///   [RFC 4880]: https://tools.ietf.org/html/rfc4880
///   [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
///   [`IssuerFingerprint`]: crate::packet::signature::subpacket::SubpacketValue::IssuerFingerprint
///   [birthday attack]: https://nullprogram.com/blog/2019/07/22/
///   [`KeyID`]: crate::KeyID
///   [`KeyHandle`]: crate::KeyHandle
///
/// # Examples
///
/// ```rust
/// # fn main() -> sequoia_openpgp::Result<()> {
/// # use sequoia_openpgp as openpgp;
/// use openpgp::Fingerprint;
///
/// let fp: Fingerprint =
///     "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
///
/// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fp.to_hex());
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Fingerprint {
    /// Fingerprint of v6 certificates and keys.
    V6([u8; 32]),

    /// Fingerprint of v4 certificates and keys.
    V4([u8; 20]),

    /// Fingerprint of unknown version or shape.
    Unknown {
        /// Version of the fingerprint, if known.
        version: Option<u8>,

        /// Raw bytes of the fingerprint.
        bytes: Box<[u8]>,
    },
}
assert_send_and_sync!(Fingerprint);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Fingerprint::V4(_) =>
                write!(f, "Fingerprint::V4({})", self),
            Fingerprint::V6(_) =>
                write!(f, "Fingerprint::V6({})", self),
            Fingerprint::Unknown { version, .. } =>
                write!(f, "Fingerprint::Unknown {{ {:?}, {} }}", version, self),
        }
    }
}

impl fmt::UpperHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_to_fmt(f, true)
    }
}

impl fmt::LowerHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.write_to_fmt(f, false)
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.chars().filter(|c| ! c.is_whitespace()).count() % 2 == 1 {
            return Err(crate::Error::InvalidArgument(
                "Odd number of nibbles".into()).into());
        }

        Self::from_bytes_intern(None, &crate::fmt::hex::decode_pretty(s)?)
    }
}

impl Fingerprint {
    /// Creates a `Fingerprint` from a byte slice in big endian
    /// representation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fp: Fingerprint =
    ///     "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
    /// let bytes =
    ///     [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
    ///      0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67];
    ///
    /// assert_eq!(Fingerprint::from_bytes(4, &bytes)?, fp);
    /// # Ok(()) }
    /// ```
    pub fn from_bytes(version: u8, raw: &[u8]) -> Result<Fingerprint> {
        Self::from_bytes_intern(Some(version), raw)
    }

    /// Like [`Fingerprint::from_bytes`], but with optional version.
    pub(crate) fn from_bytes_intern(mut version: Option<u8>, raw: &[u8])
                                    -> Result<Fingerprint>
    {
        // Apply some heuristics if no explicit version is known.
        if version.is_none() && raw.len() == 32 {
            version = Some(6);
        } else if version.is_none() && raw.len() == 20 {
            version = Some(4);
        }

        match version {
            Some(6) => if raw.len() == 32 {
                let mut fp: [u8; 32] = Default::default();
                fp.copy_from_slice(raw);
                Ok(Fingerprint::V6(fp))
            } else {
                Err(Error::InvalidArgument(format!(
                    "a v6 fingerprint consists of 32 bytes, got {}",
                    raw.len())).into())
            },

            Some(4) => if raw.len() == 20 {
                let mut fp : [u8; 20] = Default::default();
                fp.copy_from_slice(raw);
                Ok(Fingerprint::V4(fp))
            } else {
                Err(Error::InvalidArgument(format!(
                    "a v4 fingerprint consists of 20 bytes, got {}",
                    raw.len())).into())
            },

            _ => Ok(Fingerprint::Unknown {
                version,
                bytes: raw.to_vec().into_boxed_slice(),
            }),
        }
    }

    /// Returns the raw fingerprint as a byte slice in big endian
    /// representation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fp: Fingerprint =
    ///     "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
    ///
    /// assert_eq!(fp.as_bytes(),
    ///            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
    ///             0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67]);
    /// # Ok(()) }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Fingerprint::V4(ref fp) => fp,
            Fingerprint::V6(fp) => fp,
            Fingerprint::Unknown { bytes, .. } => bytes,
        }
    }

    /// Converts this fingerprint to its canonical hexadecimal
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
    /// use openpgp::Fingerprint;
    ///
    /// let fp: Fingerprint =
    ///     "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fp.to_hex());
    /// assert_eq!(format!("{:X}", fp), fp.to_hex());
    /// # Ok(()) }
    /// ```
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;

        let mut output = String::with_capacity(
            // Each byte results in two hex characters.
            self.as_bytes().len() * 2);

        // We write to String that never fails but the Write API
        // returns Results.
        write!(output, "{:X}", self).unwrap();

        output
    }

    /// Converts this fingerprint to its hexadecimal representation
    /// with spaces.
    ///
    /// This representation is always uppercase and with spaces
    /// grouping the hexadecimal digits into groups of four with a
    /// double space in the middle.  It is only suitable for manual
    /// comparison of fingerprints.
    ///
    /// Note: The spaces will hinder other kind of use cases.  For
    /// example, it is harder to select the whole fingerprint for
    /// copying, and it has to be quoted when used as a command line
    /// argument.  Only use this form for displaying a fingerprint
    /// with the intent of manual comparisons.
    ///
    /// See also [`Fingerprint::to_icao`].
    ///
    ///   [`Fingerprint::to_icao`]: Fingerprint::to_icao()
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// let fp: openpgp::Fingerprint =
    ///     "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
    ///
    /// assert_eq!("0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567",
    ///            fp.to_spaced_hex());
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
            raw_len / 2
            // After half of the groups, there is another space.
            + 1);

        // We write to String that never fails but the Write API
        // returns Results.
        write!(output, "{:#X}", self).unwrap();

        output
    }

    /// Parses the hexadecimal representation of an OpenPGP
    /// fingerprint.
    ///
    /// This function is the reverse of `to_hex`. It also accepts
    /// other variants of the fingerprint notation including
    /// lower-case letters, spaces and optional leading `0x`.
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fp =
    ///     Fingerprint::from_hex("0123456789ABCDEF0123456789ABCDEF01234567")?;
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fp.to_hex());
    ///
    /// let fp =
    ///     Fingerprint::from_hex("0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567")?;
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fp.to_hex());
    /// # Ok(()) }
    /// ```
    pub fn from_hex(s: &str) -> std::result::Result<Self, anyhow::Error> {
        std::str::FromStr::from_str(s)
    }

    /// Common code for the above functions.
    fn write_to_fmt(&self, f: &mut fmt::Formatter, upper_case: bool) -> fmt::Result {
        use std::fmt::Write;

        let raw = self.as_bytes();

        // We currently only handle V4 fingerprints, which look like:
        //
        //   8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid fingerprint,
        // just format it like a V4 fingerprint and hope for the best.

        // XXX: v5 fingerprints have no human-readable formatting by
        // choice.
        let a_letter = if upper_case { b'A' } else { b'a' };
        let pretty = f.alternate();

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                f.write_char(' ')?;
            }

            if pretty && i > 0 && i * 2 == raw.len() {
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

    /// Converts the hex representation of the `Fingerprint` to a
    /// phrase in the [ICAO spelling alphabet].
    ///
    ///   [ICAO spelling alphabet]: https://en.wikipedia.org/wiki/ICAO_spelling_alphabet
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fp: Fingerprint =
    ///     "01AB 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
    ///
    /// assert!(fp.to_icao().starts_with("Zero One Alfa Bravo"));
    ///
    /// # let expected = "\
    /// # Zero One Alfa Bravo Four Five Six Seven Eight Niner Alfa Bravo \
    /// # Charlie Delta Echo Foxtrot Zero One Two Three Four Five Six Seven \
    /// # Eight Niner Alfa Bravo Charlie Delta Echo Foxtrot Zero One Two \
    /// # Three Four Five Six Seven";
    /// # assert_eq!(fp.to_icao(), expected);
    /// #
    /// # Ok(()) }
    /// ```
    pub fn to_icao(&self) -> String {
        let mut ret = String::default();

        for ch in self.to_hex().chars() {
            let word = match ch {
                '0' => "Zero",
                '1' => "One",
                '2' => "Two",
                '3' => "Three",
                '4' => "Four",
                '5' => "Five",
                '6' => "Six",
                '7' => "Seven",
                '8' => "Eight",
                '9' => "Niner",
                'A' => "Alfa",
                'B' => "Bravo",
                'C' => "Charlie",
                'D' => "Delta",
                'E' => "Echo",
                'F' => "Foxtrot",
                _ => { continue; }
            };

            if !ret.is_empty() {
                ret.push(' ');
            }
            ret.push_str(word);
        }

        ret
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
    /// `Fingerprint`, could they be aliases?  That is, it implements
    /// the desired, non-transitive equality relation:
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
    /// assert!(fpr1.aliases(KeyHandle::from(&keyid)));
    /// assert!(fpr2.aliases(KeyHandle::from(&keyid)));
    /// assert!(! fpr1.aliases(KeyHandle::from(&fpr2)));
    /// # Ok(()) }
    /// ```
    pub fn aliases<H>(&self, other: H) -> bool
        where H: Borrow<KeyHandle>
    {
        let other = other.borrow();

        match (self, other) {
            (f, KeyHandle::Fingerprint(o)) => {
                f == o
            },
            (Fingerprint::V4(f), KeyHandle::KeyID(KeyID::Long(o))) => {
                // Avoid a heap allocation by embedding our
                // knowledge of how a v4 key ID is derived from a
                // v4 fingerprint:
                //
                // A v4 key ID are the 8 right-most octets of a v4
                // fingerprint.
                &f[12..] == o
            },

            (Fingerprint::V6(f), KeyHandle::KeyID(KeyID::Long(o))) => {
                // A v6 key ID are the 8 left-most octets of a v6
                // fingerprint.
                &f[..8] == o
            },

            (f, KeyHandle::KeyID(o)) => {
                &KeyID::from(f) == o
            },
        }
    }
}

#[cfg(test)]
impl Fingerprint {
    pub(crate) fn arbitrary_v4(g: &mut Gen) -> Self {
        let mut fp = [0; 20];
        fp.iter_mut().for_each(|p| *p = Arbitrary::arbitrary(g));
        Fingerprint::V4(fp)
    }

    pub(crate) fn arbitrary_v6(g: &mut Gen) -> Self {
        let mut fp = [0; 32];
        fp.iter_mut().for_each(|p| *p = Arbitrary::arbitrary(g));
        Fingerprint::V6(fp)
    }
}

 #[cfg(test)]
impl Arbitrary for Fingerprint {
    fn arbitrary(g: &mut Gen) -> Self {
        if Arbitrary::arbitrary(g) {
            Self::arbitrary_v4(g)
        } else {
            Self::arbitrary_v6(g)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_hex_formatting() {
        let fp = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
            .parse::<Fingerprint>().unwrap();
        assert!(matches!(&fp, Fingerprint::V4(_)));
        assert_eq!(format!("{:X}", fp), "0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(format!("{:x}", fp), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn v5_hex_formatting() -> crate::Result<()> {
        let fp = "0123 4567 89AB CDEF 0123 4567 89AB CDEF \
                  0123 4567 89AB CDEF 0123 4567 89AB CDEF"
            .parse::<Fingerprint>()?;
        assert!(matches!(&fp, Fingerprint::V6(_)));
        assert_eq!(format!("{:X}", fp), "0123456789ABCDEF0123456789ABCDEF\
                                         0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(format!("{:x}", fp), "0123456789abcdef0123456789abcdef\
                                         0123456789abcdef0123456789abcdef");
        Ok(())
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

        // Compare fingerprints to fingerprints.
        assert!(fp1.aliases(KeyHandle::from(&fp1)));
        assert!(! fp1.aliases(KeyHandle::from(&fp15)));
        assert!(! fp1.aliases(KeyHandle::from(&fp2)));

        assert!(! fp15.aliases(KeyHandle::from(&fp1)));
        assert!(fp15.aliases(KeyHandle::from(&fp15)));
        assert!(! fp15.aliases(KeyHandle::from(&fp2)));

        assert!(! fp2.aliases(KeyHandle::from(&fp1)));
        assert!(! fp2.aliases(KeyHandle::from(&fp15)));
        assert!(fp2.aliases(KeyHandle::from(&fp2)));

        // Compare fingerprints to key IDs.
        assert!(fp1.aliases(KeyHandle::from(&keyid1)));
        assert!(fp1.aliases(KeyHandle::from(&keyid15)));
        assert!(! fp1.aliases(KeyHandle::from(&keyid2)));

        assert!(fp15.aliases(KeyHandle::from(&keyid1)));
        assert!(fp15.aliases(KeyHandle::from(&keyid15)));
        assert!(! fp15.aliases(KeyHandle::from(&keyid2)));

        assert!(! fp2.aliases(KeyHandle::from(&keyid1)));
        assert!(! fp2.aliases(KeyHandle::from(&keyid15)));
        assert!(fp2.aliases(KeyHandle::from(&keyid2)));

        Ok(())
    }
}
