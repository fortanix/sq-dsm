use std::fmt;

use Fingerprint;
use KeyID;

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
    pub fn from_hex(hex: &str) -> Option<KeyID> {
        let bytes = ::conversions::from_hex(hex, true)?;

        // A KeyID is exactly 8 bytes long.
        if bytes.len() == 8 {
            Some(KeyID::from_bytes(&bytes[..]))
        } else {
            // Maybe a fingerprint was given.  Try to parse it and
            // convert it to a KeyID.
            Some(Fingerprint::from_hex(hex)?.to_keyid())
        }
    }

    /// Returns a reference to the raw KeyID.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &KeyID::V4(ref id) => id,
            &KeyID::Invalid(ref id) => id,
        }
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
