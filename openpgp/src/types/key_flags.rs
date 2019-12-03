use std::fmt;
use std::cmp;
use std::ops::{BitAnd, BitOr};

/// Describes how a key may be used, and stores additional
/// information.
#[derive(Clone, Hash)]
pub struct KeyFlags{
    can_certify: bool,
    can_sign: bool,
    can_encrypt_for_transport: bool,
    can_encrypt_at_rest: bool,
    can_authenticate: bool,
    is_split_key: bool,
    is_group_key: bool,
    unknown: Box<[u8]>,
}

impl Default for KeyFlags {
    fn default() -> Self {
        KeyFlags::new(&vec![0])
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
            f.write_str("D")?;
        }
        if self.is_group_key() {
            f.write_str("G")?;
        }
        if self.unknown.len() > 0 {
            f.write_str("+0x")?;
            f.write_str(
                &crate::fmt::hex::encode_pretty(&self.unknown))?;
        }

        Ok(())
    }
}

impl PartialEq for KeyFlags {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(cmp::Ordering::Equal)
    }
}

impl Eq for KeyFlags {}

impl PartialOrd for KeyFlags {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        let mut a_bits = self.as_vec();
        let mut b_bits = other.as_vec();
        let len = cmp::max(a_bits.len(), b_bits.len());

        while a_bits.len() < len { a_bits.push(0); }
        while b_bits.len() < len { b_bits.push(0); }

        if a_bits == b_bits {
            Some(cmp::Ordering::Equal)
        } else if a_bits.iter().zip(b_bits.iter()).all(|(a,b)| a & b == *a) {
            Some(cmp::Ordering::Less)
        } else if a_bits.iter().zip(b_bits.iter()).all(|(a,b)| a & b == *b) {
            Some(cmp::Ordering::Greater)
        } else {
            None
        }
    }
}

impl BitAnd for &KeyFlags {
    type Output = KeyFlags;

    fn bitand(self, rhs: Self) -> KeyFlags {
        let l = self.as_vec();
        let r = rhs.as_vec();

        let mut c = Vec::with_capacity(cmp::min(l.len(), r.len()));
        for (l, r) in l.into_iter().zip(r.into_iter()) {
            c.push(l & r);
        }

        KeyFlags::new(&c[..])
    }
}

impl BitOr for &KeyFlags {
    type Output = KeyFlags;

    fn bitor(self, rhs: Self) -> KeyFlags {
        let l = self.as_vec();
        let r = rhs.as_vec();

        // Make l the longer one.
        let (mut l, r) = if l.len() > r.len() {
            (l, r)
        } else {
            (r, l)
        };

        for (i, r) in r.into_iter().enumerate() {
            l[i] = l[i] | r;
        }

        KeyFlags::new(&l[..])
    }
}

impl KeyFlags {
    /// Creates a new instance from `bits`.
    pub fn new(bits: &[u8]) -> Self {
        let can_certify = bits.get(0)
            .map(|x| x & KEY_FLAG_CERTIFY != 0).unwrap_or(false);
        let can_sign = bits.get(0)
            .map(|x| x & KEY_FLAG_SIGN != 0).unwrap_or(false);
        let can_encrypt_for_transport = bits.get(0)
            .map(|x| x & KEY_FLAG_ENCRYPT_FOR_TRANSPORT != 0).unwrap_or(false);
        let can_encrypt_at_rest = bits.get(0)
            .map(|x| x & KEY_FLAG_ENCRYPT_AT_REST != 0).unwrap_or(false);
        let can_authenticate = bits.get(0)
            .map(|x| x & KEY_FLAG_AUTHENTICATE != 0).unwrap_or(false);
        let is_split_key = bits.get(0)
            .map(|x| x & KEY_FLAG_SPLIT_KEY != 0).unwrap_or(false);
        let is_group_key = bits.get(0)
            .map(|x| x & KEY_FLAG_GROUP_KEY != 0).unwrap_or(false);
        let unk = if bits.is_empty() {
            Box::default()
        } else {
            let mut cpy = Vec::from(bits);

            cpy[0] &= (
                KEY_FLAG_ENCRYPT_AT_REST | KEY_FLAG_ENCRYPT_FOR_TRANSPORT |
                KEY_FLAG_SIGN | KEY_FLAG_CERTIFY | KEY_FLAG_AUTHENTICATE |
                KEY_FLAG_GROUP_KEY | KEY_FLAG_SPLIT_KEY
            ) ^ 0xff;

            while cpy.last().cloned() == Some(0) { cpy.pop(); }
            cpy.into_boxed_slice()
        };

        KeyFlags{
            can_certify, can_sign, can_encrypt_for_transport,
            can_encrypt_at_rest, can_authenticate, is_split_key,
            is_group_key, unknown: unk
        }
    }

    /// Returns a new `KeyFlags` with all capabilities disabled.
    pub fn empty() -> Self {
        KeyFlags::default()
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_vec(&self) -> Vec<u8> {
        let mut ret = if self.unknown.is_empty() {
            vec![0]
        } else {
            self.unknown.clone().into()
        };

        if self.can_certify { ret[0] |= KEY_FLAG_CERTIFY; }
        if self.can_sign { ret[0] |= KEY_FLAG_SIGN; }
        if self.can_encrypt_for_transport { ret[0] |= KEY_FLAG_ENCRYPT_FOR_TRANSPORT; }
        if self.can_encrypt_at_rest { ret[0] |= KEY_FLAG_ENCRYPT_AT_REST; }
        if self.can_authenticate { ret[0] |= KEY_FLAG_AUTHENTICATE; }
        if self.is_split_key { ret[0] |= KEY_FLAG_SPLIT_KEY; }
        if self.is_group_key { ret[0] |= KEY_FLAG_GROUP_KEY }

        ret
    }

    /// This key may be used to certify other keys.
    pub fn can_certify(&self) -> bool { self.can_certify }

    /// Sets whether or not this key may be used to certify other keys.
    pub fn set_certify(mut self, v: bool) -> Self {
        self.can_certify = v;
        self
    }

    /// This key may be used to sign data.
    pub fn can_sign(&self) -> bool { self.can_sign }

    /// Sets whether or not this key may be used to sign data.
    pub fn set_sign(mut self, v: bool) -> Self {
        self.can_sign = v;
        self
    }

    /// This key may be used to encrypt communications.
    pub fn can_encrypt_for_transport(&self) -> bool {
        self.can_encrypt_for_transport
    }

    /// Sets whether or not this key may be used to encrypt communications.
    pub fn set_encrypt_for_transport(mut self, v: bool) -> Self {
        self.can_encrypt_for_transport = v;
        self
    }

    /// This key may be used to encrypt storage.
    pub fn can_encrypt_at_rest(&self) -> bool { self.can_encrypt_at_rest }

    /// Sets whether or not this key may be used to encrypt storage.
    pub fn set_encrypt_at_rest(mut self, v: bool) -> Self {
        self.can_encrypt_at_rest = v;
        self
    }

    /// This key may be used for authentication.
    pub fn can_authenticate(&self) -> bool {
        self.can_authenticate
    }

    /// Sets whether or not this key may be used for authentication.
    pub fn set_authenticate(mut self, v: bool) -> Self {
        self.can_authenticate = v;
        self
    }

    /// The private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn is_split_key(&self) -> bool {
        self.is_split_key
    }

    /// Sets whether or not the private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn set_split_key(mut self, v: bool) -> Self {
        self.is_split_key = v;
        self
    }

    /// The private component of this key may be in
    /// possession of more than one person.
    pub fn is_group_key(&self) -> bool {
        self.is_group_key
    }

    /// Sets whether or not the private component of this key may be in
    /// possession of more than one person.
    pub fn set_group_key(mut self, v: bool) -> Self {
        self.is_group_key = v;
        self
    }

    /// Returns whether no flags are set.
    pub fn is_empty(&self) -> bool {
        self.as_vec().into_iter().all(|b| b == 0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        let nothing = KeyFlags::default();
        let enc = KeyFlags::default()
            .set_encrypt_for_transport(true)
            .set_encrypt_at_rest(true);
        let sig = KeyFlags::default()
            .set_sign(true);
        let enc_and_auth = KeyFlags::default()
            .set_encrypt_for_transport(true)
            .set_encrypt_at_rest(true)
            .set_authenticate(true);

        assert!(nothing < enc);
        assert!(sig >= nothing);
        assert!(nothing <= enc);
        assert!(enc < enc_and_auth);
        assert!(enc_and_auth >= enc_and_auth);
        assert!(enc <= enc_and_auth);
        assert!(enc_and_auth >= enc);
        assert!(!(enc < sig));
        assert!(!(enc > sig));
    }
}
