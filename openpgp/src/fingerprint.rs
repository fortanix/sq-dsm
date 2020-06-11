use std::fmt;

#[cfg(any(test, feature = "quickcheck"))]
use quickcheck::{Arbitrary, Gen};

/// A long identifier for certificates and keys.
///
/// A fingerprint uniquely identifies a public key.  For more details
/// about how a fingerprint is generated, see [Section 12.2 of RFC
/// 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Fingerprint {
    /// 20 byte SHA-1 hash.
    V4([u8;20]),
    /// Used for holding fingerprints that we don't understand.  For
    /// instance, we don't grok v3 fingerprints.
    Invalid(Box<[u8]>),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
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
    /// Reads a binary fingerprint.
    pub fn from_bytes(raw: &[u8]) -> Fingerprint {
        if raw.len() == 20 {
            let mut fp : [u8; 20] = Default::default();
            fp.copy_from_slice(raw);
            Fingerprint::V4(fp)
        } else {
            Fingerprint::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Returns a reference to the raw Fingerprint.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            &Fingerprint::V4(ref fp) => fp,
            &Fingerprint::Invalid(ref fp) => fp,
            Fingerprint::__Nonexhaustive => unreachable!(),
        }
    }

    /// Converts this fingerprint to its canonical hexadecimal representation.
    ///
    /// This representation is always uppercase and without spaces and is
    /// suitable for stable key identifiers.
    ///
    /// The output of this function is exactly the same as formatting this
    /// object with the `:X` format specifier.
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fpr = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse::<Fingerprint>().unwrap();
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fpr.to_hex());
    /// assert_eq!(format!("{:X}", fpr), fpr.to_hex());
    /// ```
    pub fn to_hex(&self) -> String {
        format!("{:X}", self)
    }

    /// Parses the hexadecimal representation of an OpenPGP fingerprint.
    ///
    /// This function is the reverse of `to_hex`. It also accepts other variants
    /// of the fingerprint notation including lower-case letters, spaces and
    /// optional leading `0x`.
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::Fingerprint;
    ///
    /// let fpr = Fingerprint::from_hex("0123456789ABCDEF0123456789ABCDEF01234567").unwrap();
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fpr.to_hex());
    ///
    /// let fpr = Fingerprint::from_hex("0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567").unwrap();
    ///
    /// assert_eq!("0123456789ABCDEF0123456789ABCDEF01234567", fpr.to_hex());
    /// ```
    pub fn from_hex(s: &str) -> std::result::Result<Self, anyhow::Error> {
        std::str::FromStr::from_str(s)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &Fingerprint::V4(ref fp) => &fp[..],
            &Fingerprint::Invalid(ref fp) => &fp[..],
            Fingerprint::__Nonexhaustive => unreachable!(),
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

    /// Converts the hex representation of the fingerprint to a phrase in the
    /// ICAO alphabet.
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

#[cfg(any(test, feature = "quickcheck"))]
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
    fn icao() {
        let fpr = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
            .parse::<Fingerprint>().unwrap();
        let expected = "\
Zero One Two Three Four Five Six Seven Eight Niner Alfa Bravo Charlie Delta \
Echo Foxtrot Zero One Two Three Four Five Six Seven Eight Niner Alfa Bravo \
Charlie Delta Echo Foxtrot Zero One Two Three Four Five Six Seven";

        assert_eq!(fpr.to_icao(), expected);
    }

    #[test]
    fn hex_formatting() {
        let fpr = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
            .parse::<Fingerprint>().unwrap();
        assert_eq!(format!("{:X}", fpr), "0123456789ABCDEF0123456789ABCDEF01234567");
        assert_eq!(format!("{:x}", fpr), "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn fingerprint_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f("0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
          .parse::<Fingerprint>().unwrap());
    }
}
