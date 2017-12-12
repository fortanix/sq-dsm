//! Types for working with OpenPGP.

/// Uniquely identifies OpenPGP keys.
pub struct KeyId(u64);

impl KeyId {
    /// Returns a KeyID with the given `id`.
    pub fn new(id: u64) -> KeyId {
        KeyId(id)
    }

    /// Returns a KeyID with the given `id` encoded as hexadecimal string.
    pub fn from_hex(id: &str) -> Option<KeyId> {
        u64::from_str_radix(id, 16).ok().map(|id| Self::new(id))
    }

    /// Returns a hexadecimal representation of the key id.
    pub fn as_hex(&self) -> String {
        format!("{:x}", self.0)
    }
}
