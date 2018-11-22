use std::fmt;

/// Describes how a key may be used, and stores additional
/// information.
#[derive(Clone)]
pub struct KeyFlags(pub Vec<u8>);

impl Default for KeyFlags {
    fn default() -> Self {
        KeyFlags(vec![0])
    }
}

impl PartialEq for KeyFlags {
    fn eq(&self, other: &KeyFlags) -> bool {
        // To deal with unknown flags, we do a bitwise comparison.
        // First, we need to bring both flag fields to the same
        // length.
        let len = ::std::cmp::max(self.0.len(), other.0.len());
        let mut mine = vec![0; len];
        let mut hers = vec![0; len];
        &mut mine[..self.0.len()].copy_from_slice(&self.0);
        &mut hers[..other.0.len()].copy_from_slice(&other.0);

        mine == hers
    }
}

impl fmt::Debug for KeyFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.can_certify() {
            f.write_str("C")?;
        }
        if self.can_sign() {
            f.write_str("S")?;
        }
        if self.can_encrypt_for_transport() {
            f.write_str("Et")?;
        }
        if self.can_encrypt_at_rest() {
            f.write_str("Er")?;
        }
        if self.can_authenticate() {
            f.write_str("A")?;
        }
        if self.is_split_key() {
            f.write_str("S")?;
        }
        if self.is_group_key() {
            f.write_str("G")?;
        }

        Ok(())
    }
}


impl KeyFlags {
    /// Grows the vector to the given length.
    fn grow(&mut self, target: usize) {
        while self.0.len() < target {
            self.0.push(0);
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// This key may be used to certify other keys.
    pub fn can_certify(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_CERTIFY > 0).unwrap_or(false)
    }


    /// Sets whether or not this key may be used to certify other keys.
    pub fn set_certify(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_CERTIFY;
        } else {
            self.0[0] &= !KEY_FLAG_CERTIFY;
        }
        self
    }

    /// This key may be used to sign data.
    pub fn can_sign(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_SIGN > 0).unwrap_or(false)
    }


    /// Sets whether or not this key may be used to sign data.
    pub fn set_sign(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_SIGN;
        } else {
            self.0[0] &= !KEY_FLAG_SIGN;
        }
        self
    }

    /// This key may be used to encrypt communications.
    pub fn can_encrypt_for_transport(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_ENCRYPT_FOR_TRANSPORT > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used to encrypt communications.
    pub fn set_encrypt_for_transport(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_ENCRYPT_FOR_TRANSPORT;
        } else {
            self.0[0] &= !KEY_FLAG_ENCRYPT_FOR_TRANSPORT;
        }
        self
    }

    /// This key may be used to encrypt storage.
    pub fn can_encrypt_at_rest(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_ENCRYPT_AT_REST > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used to encrypt storage.
    pub fn set_encrypt_at_rest(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_ENCRYPT_AT_REST;
        } else {
            self.0[0] &= !KEY_FLAG_ENCRYPT_AT_REST;
        }
        self
    }

    /// This key may be used for authentication.
    pub fn can_authenticate(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_AUTHENTICATE > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used for authentication.
    pub fn set_authenticate(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_AUTHENTICATE;
        } else {
            self.0[0] &= !KEY_FLAG_AUTHENTICATE;
        }
        self
    }

    /// The private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn is_split_key(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_SPLIT_KEY > 0).unwrap_or(false)
    }

    /// Sets whether or not the private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn set_split_key(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_SPLIT_KEY;
        } else {
            self.0[0] &= !KEY_FLAG_SPLIT_KEY;
        }
        self
    }

    /// The private component of this key may be in
    /// possession of more than one person.
    pub fn is_group_key(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_GROUP_KEY > 0).unwrap_or(false)
    }

    /// Sets whether or not the private component of this key may be in
    /// possession of more than one person.
    pub fn set_group_key(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_GROUP_KEY;
        } else {
            self.0[0] &= !KEY_FLAG_GROUP_KEY;
        }
        self
    }
}

// Numeric key capability flags.

/// This key may be used to certify other keys.
const KEY_FLAG_CERTIFY: u8 = 0x01;

/// This key may be used to sign data.
const KEY_FLAG_SIGN: u8 = 0x02;

/// This key may be used to encrypt communications.
const KEY_FLAG_ENCRYPT_FOR_TRANSPORT: u8 = 0x04;

/// This key may be used to encrypt storage.
const KEY_FLAG_ENCRYPT_AT_REST: u8 = 0x08;

/// The private component of this key may have been split by a
/// secret-sharing mechanism.
const KEY_FLAG_SPLIT_KEY: u8 = 0x10;

/// This key may be used for authentication.
const KEY_FLAG_AUTHENTICATE: u8 = 0x20;

/// The private component of this key may be in the possession of more
/// than one person.
const KEY_FLAG_GROUP_KEY: u8 = 0x80;
