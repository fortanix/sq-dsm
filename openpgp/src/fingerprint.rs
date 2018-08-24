use std::fmt;

use Fingerprint;
use KeyID;
use Result;

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
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

    /// Reads a hexadecimal fingerprint.
    ///
    /// This function ignores whitespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use openpgp::Fingerprint;
    /// let hex = "3E8877C877274692975189F5D03F6F865226FE8B";
    /// let fp = Fingerprint::from_hex(hex);
    /// assert!(fp.is_ok());
    /// assert_eq!(fp.unwrap().to_hex(), hex);
    /// ```
    pub fn from_hex(hex: &str) -> Result<Fingerprint> {
        Ok(Fingerprint::from_bytes(&::conversions::from_hex(hex, true)?[..]))
    }

    /// Returns a reference to the raw Fingerprint.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &Fingerprint::V4(ref fp) => fp,
            &Fingerprint::Invalid(ref fp) => fp,
        }
    }

    /// Converts the fingerprint to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the fingerprint to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
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

    /// Converts the fingerprint to a key ID.
    pub fn to_keyid(&self) -> KeyID {
        match self {
            &Fingerprint::V4(ref fp) =>
                KeyID::from_bytes(&fp[fp.len() - 8..]),
            &Fingerprint::Invalid(ref fp) => {
                if fp.len() < 8 {
                    KeyID::from_bytes(&[0; 8])
                } else {
                    KeyID::from_bytes(&fp[fp.len() - 8..])
                }
            }
        }
    }
}
