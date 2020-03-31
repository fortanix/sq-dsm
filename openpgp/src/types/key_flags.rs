use std::hash::{Hash, Hasher};
use std::fmt;
use std::cmp;
use std::ops::{BitAnd, BitOr};

/// Describes how a key may be used, and stores additional
/// information.
///
/// # A note on equality
///
/// `PartialEq` is implements semantic equality, i.e. it ignores
/// padding.
#[derive(Clone)]
pub struct KeyFlags{
    for_certification: bool,
    for_signing: bool,
    for_transport_encryption: bool,
    for_storage_encryption: bool,
    for_authentication: bool,
    is_split_key: bool,
    is_group_key: bool,
    unknown: Box<[u8]>,
    /// Original length, including trailing zeros.
    pad_to: usize,
}

impl Default for KeyFlags {
    fn default() -> Self {
        KeyFlags::new(&[])
    }
}

impl fmt::Debug for KeyFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.for_certification() {
            f.write_str("C")?;
        }
        if self.for_signing() {
            f.write_str("S")?;
        }
        if self.for_transport_encryption() {
            f.write_str("Et")?;
        }
        if self.for_storage_encryption() {
            f.write_str("Er")?;
        }
        if self.for_authentication() {
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
        if self.pad_to > KEY_FLAGS_N_KNOWN_BYTES + self.unknown.len() {
            write!(f, "+padding({} bytes)", self.pad_to - self.unknown.len())?;
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

impl Hash for KeyFlags {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.for_certification.hash(state);
        self.for_signing.hash(state);
        self.for_transport_encryption.hash(state);
        self.for_storage_encryption.hash(state);
        self.for_authentication.hash(state);
        self.is_split_key.hash(state);
        self.is_group_key.hash(state);
        self.unknown.hash(state);
    }
}

impl PartialOrd for KeyFlags {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        let mut a_bits = self.to_vec();
        crate::types::bitfield_remove_padding(&mut a_bits);
        let mut b_bits = other.to_vec();
        crate::types::bitfield_remove_padding(&mut b_bits);
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
        let l = self.to_vec();
        let r = rhs.to_vec();

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
        let l = self.to_vec();
        let r = rhs.to_vec();

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
    pub fn new<B: AsRef<[u8]>>(bits: B) -> Self {
        let bits = bits.as_ref();
        let mut pad_to = 0;

        let for_certification = bits.get(0)
            .map(|x| x & KEY_FLAG_CERTIFY != 0).unwrap_or(false);
        let for_signing = bits.get(0)
            .map(|x| x & KEY_FLAG_SIGN != 0).unwrap_or(false);
        let for_transport_encryption = bits.get(0)
            .map(|x| x & KEY_FLAG_ENCRYPT_FOR_TRANSPORT != 0).unwrap_or(false);
        let for_storage_encryption = bits.get(0)
            .map(|x| x & KEY_FLAG_ENCRYPT_AT_REST != 0).unwrap_or(false);
        let for_authentication = bits.get(0)
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

            pad_to = crate::types::bitfield_remove_padding(&mut cpy);
            cpy.into_boxed_slice()
        };

        KeyFlags{
            for_certification, for_signing, for_transport_encryption,
            for_storage_encryption, for_authentication, is_split_key,
            is_group_key, unknown: unk, pad_to,
        }
    }

    /// Returns a new `KeyFlags` with all capabilities disabled.
    pub fn empty() -> Self {
        KeyFlags::default()
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut ret = if self.unknown.is_empty() {
            vec![0]
        } else {
            self.unknown.clone().into()
        };

        if self.for_certification { ret[0] |= KEY_FLAG_CERTIFY; }
        if self.for_signing { ret[0] |= KEY_FLAG_SIGN; }
        if self.for_transport_encryption { ret[0] |= KEY_FLAG_ENCRYPT_FOR_TRANSPORT; }
        if self.for_storage_encryption { ret[0] |= KEY_FLAG_ENCRYPT_AT_REST; }
        if self.for_authentication { ret[0] |= KEY_FLAG_AUTHENTICATE; }
        if self.is_split_key { ret[0] |= KEY_FLAG_SPLIT_KEY; }
        if self.is_group_key { ret[0] |= KEY_FLAG_GROUP_KEY; }

        // Corner case: empty flag field.  We initialized ret to
        // vec![0] for easy setting of flags.  See if any of the above
        // was set.
        if ret.len() == 1 && ret[0] == 0 {
            // Nope.  Trim this byte.
            ret.pop();
        }

        for _ in ret.len()..self.pad_to {
            ret.push(0);
        }

        ret
    }

    /// This key may be used to certify other keys.
    pub fn for_certification(&self) -> bool { self.for_certification }

    /// Sets whether or not this key may be used to certify other keys.
    pub fn set_certification(mut self, v: bool) -> Self {
        self.for_certification = v;
        self
    }

    /// This key may be used to sign data.
    pub fn for_signing(&self) -> bool { self.for_signing }

    /// Sets whether or not this key may be used to sign data.
    pub fn set_signing(mut self, v: bool) -> Self {
        self.for_signing = v;
        self
    }

    /// This key may be used to encrypt communications.
    pub fn for_transport_encryption(&self) -> bool {
        self.for_transport_encryption
    }

    /// Sets whether or not this key may be used to encrypt communications.
    pub fn set_transport_encryption(mut self, v: bool) -> Self {
        self.for_transport_encryption = v;
        self
    }

    /// This key may be used to encrypt storage.
    pub fn for_storage_encryption(&self) -> bool { self.for_storage_encryption }

    /// Sets whether or not this key may be used to encrypt storage.
    pub fn set_storage_encryption(mut self, v: bool) -> Self {
        self.for_storage_encryption = v;
        self
    }

    /// This key may be used for authentication.
    pub fn for_authentication(&self) -> bool {
        self.for_authentication
    }

    /// Sets whether or not this key may be used for authentication.
    pub fn set_authentication(mut self, v: bool) -> Self {
        self.for_authentication = v;
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
        self.to_vec().into_iter().all(|b| b == 0)
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

/// Number of bytes with known flags.
const KEY_FLAGS_N_KNOWN_BYTES: usize = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        let nothing = KeyFlags::default();
        let enc = KeyFlags::default()
            .set_transport_encryption(true)
            .set_storage_encryption(true);
        let sig = KeyFlags::default()
            .set_signing(true);
        let enc_and_auth = KeyFlags::default()
            .set_transport_encryption(true)
            .set_storage_encryption(true)
            .set_authentication(true);

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

    quickcheck! {
        fn roundtrip(raw: Vec<u8>) -> bool {
            let val = KeyFlags::new(&raw);
            assert_eq!(raw, val.to_vec());

            // Check that equality ignores padding.
            let mut val_without_padding = val.clone();
            val_without_padding.pad_to = val.unknown.len();
            assert_eq!(val, val_without_padding);

            true
        }
    }
}
