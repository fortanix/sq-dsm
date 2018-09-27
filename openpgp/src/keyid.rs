use std::fmt;

use Error;
use Fingerprint;
use KeyID;
use Result;

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Debug for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("KeyID")
            .field(&self.to_string())
            .finish()
    }
}

impl From<KeyID> for Vec<u8> {
    fn from(id: KeyID) -> Self {
        let mut r = Vec::with_capacity(8);
        match id {
            KeyID::V4(ref b) => r.extend_from_slice(b),
            KeyID::Invalid(ref b) => r.extend_from_slice(b),
        }
        r
    }
}

impl KeyID {
    /// Converts a u64 to a KeyID.
    pub fn new(data: u64) -> KeyID {
        let bytes = [
            (data >> (7 * 8)) as u8,
            (data >> (6 * 8)) as u8,
            (data >> (5 * 8)) as u8,
            (data >> (4 * 8)) as u8,
            (data >> (3 * 8)) as u8,
            (data >> (2 * 8)) as u8,
            (data >> (1 * 8)) as u8,
            (data >> (0 * 8)) as u8
        ];
        Self::from_bytes(&bytes[..])
    }

    /// Converts the KeyID to a u64 if possible.
    pub fn as_u64(&self) -> Result<u64> {
        match &self {
            KeyID::V4(ref b) =>
                Ok(0u64
                   | ((b[0] as u64) << (7 * 8))
                   | ((b[1] as u64) << (6 * 8))
                   | ((b[2] as u64) << (5 * 8))
                   | ((b[3] as u64) << (4 * 8))
                   | ((b[4] as u64) << (3 * 8))
                   | ((b[5] as u64) << (2 * 8))
                   | ((b[6] as u64) << (1 * 8))
                   | ((b[7] as u64) << (0 * 8))),
            KeyID::Invalid(_) =>
                Err(Error::InvalidArgument("Invalid KeyID".into()).into()),
        }
    }

    /// Reads a binary key ID.
    pub fn from_bytes(raw: &[u8]) -> KeyID {
        if raw.len() == 8 {
            let mut keyid : [u8; 8] = Default::default();
            keyid.copy_from_slice(raw);
            KeyID::V4(keyid)
        } else {
            KeyID::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Reads a hex-encoded Key ID.
    pub fn from_hex(hex: &str) -> Result<KeyID> {
        let bytes = ::conversions::from_hex(hex, true)?;

        // A KeyID is exactly 8 bytes long.
        if bytes.len() == 8 {
            Ok(KeyID::from_bytes(&bytes[..]))
        } else {
            // Maybe a fingerprint was given.  Try to parse it and
            // convert it to a KeyID.
            Ok(Fingerprint::from_hex(hex)?.to_keyid())
        }
    }

    /// Returns a reference to the raw KeyID.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &KeyID::V4(ref id) => id,
            &KeyID::Invalid(ref id) => id,
        }
    }

    /// Returns true if this is a wild card ID.
    pub fn is_wildcard(&self) -> bool {
        self.as_slice().iter().all(|b| *b == 0)
    }

    /// Converts the key ID to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the key ID to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &KeyID::V4(ref fp) => &fp[..],
            &KeyID::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 key IDs, which look like:
        //
        //   AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid key ID, just
        // format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
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
}

#[cfg(test)]
mod test {
    use super::*;
    quickcheck! {
        fn u64_roundtrip(id: u64) -> bool {
            KeyID::new(id).as_u64().unwrap() == id
        }
    }
}
