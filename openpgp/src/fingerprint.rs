use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// A long identifier for certificates and keys.
///
/// A `Fingerprint` uniquely identifies a public key.
///
/// Currently, sequoia supports *version 4* fingerprints and Key IDs
/// only.  *Version 3* fingerprints and Key IDs were deprecated by
/// [RFC 4880] in 2007.
///
/// Essentially, a *v4* fingerprint is a SHA-1 hash over the key's
/// public key packet.  For details, see [Section 12.2 of RFC 4880].
///
/// Fingerprints are used, for example, to reference the issuing key
/// of a signature in its [`IssuerFingerprint`] subpacket.  As a
/// general rule of thumb, you should prefer using fingerprints over
/// KeyIDs because the latter are vulnerable to [birthday attack]s.
///
/// See also [`KeyID`] and [`KeyHandle`].
///
///   [RFC 4880]: https://tools.ietf.org/html/rfc4880
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
///   [`KeyID`]: ./enum.KeyID.html
///   [`KeyHandle`]: ./enum.KeyHandle.html
///   [`IssuerFingerprint`]: ./packet/signature/subpacket/enum.SubpacketValue.html#variant.IssuerFingerprint
///   [birthday attack]: https://nullprogram.com/blog/2019/07/22/
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
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
    /// A 20 byte SHA-1 hash of the public key packet as defined in the RFC.
    V4([u8;20]),
    /// Used for holding fingerprint data that is not a V4 fingerprint, e.g. a
    /// V3 fingerprint (deprecated) or otherwise wrong-length data.
    Invalid(Box<[u8]>),
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.convert_to_string(true))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::UpperHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.convert_to_string(false))
    }
}

impl fmt::LowerHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hex = self.convert_to_string(false);
        hex.make_ascii_lowercase();
        f.write_str(&hex)
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::from_bytes(&crate::fmt::hex::decode_pretty(s)?[..]))
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
    /// assert_eq!(Fingerprint::from_bytes(&bytes), fp);
    /// # Ok(()) }
    /// ```
    pub fn from_bytes(raw: &[u8]) -> Fingerprint {
        if raw.len() == 20 {
            let mut fp : [u8; 20] = Default::default();
            fp.copy_from_slice(raw);
            Fingerprint::V4(fp)
        } else {
            Fingerprint::Invalid(raw.to_vec().into_boxed_slice())
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
            &Fingerprint::V4(ref fp) => fp,
            &Fingerprint::Invalid(ref fp) => fp,
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
        format!("{:X}", self)
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
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &Fingerprint::V4(ref fp) => &fp[..],
            &Fingerprint::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 fingerprints, which look like:
        //
        //   8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid fingerprint,
        // just format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
                // After 5 groups, there is another space.
                + raw.len() / 10
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            if pretty && i > 0 && i % 10 == 0 {
                output.push(' ' as u8);
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
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

        for ch in self.convert_to_string(false).chars() {
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
                ret.push_str(" ");
            }
            ret.push_str(word);
        }

        ret
    }
}

#[cfg(test)]
impl Arbitrary for Fingerprint {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use rand::Rng;
        let mut fp = [0; 20];
        fp.iter_mut().for_each(|p| *p = g.gen());
        Fingerprint::V4(fp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_formatting() {
        let fp = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
            .parse::<Fingerprint>().unwrap();
        assert_eq!(format!("{:X}", fp), "0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(format!("{:x}", fp), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn fingerprint_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f("0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
          .parse::<Fingerprint>().unwrap());
    }
}
