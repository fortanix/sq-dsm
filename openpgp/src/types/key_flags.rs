use std::fmt;
use std::ops::{BitAnd, BitOr};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::types::Bitfield;

/// Describes how a key may be used, and stores additional information.
///
/// Key flags are described in [Section 5.2.3.29 of RFC 9580].
///
/// [Section 5.2.3.29 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.29
///
/// # A note on equality
///
/// `PartialEq` compares the serialized form of the key flag sets.  If
/// you prefer to compare two key flag sets for semantic equality, you
/// should use [`KeyFlags::normalized_eq`].  The difference between
/// semantic equality and serialized equality is that semantic
/// equality ignores differences in the amount of padding.
///
///   [`KeyFlags::normalized_eq`]: KeyFlags::normalized_eq()
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
///
/// # fn main() -> Result<()> {
/// let p = &StandardPolicy::new();
///
/// let (cert, _) =
///     CertBuilder::new()
///         .add_userid("Alice <alice@example.com>")
///         .add_transport_encryption_subkey()
///         .generate()?;
///
/// for subkey in cert.with_policy(p, None)?.keys().subkeys() {
///     // Key contains one Encryption subkey:
///     assert!(subkey.key_flags().unwrap().for_transport_encryption());
/// }
/// # Ok(()) }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyFlags(Bitfield);
assert_send_and_sync!(KeyFlags);

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

        let mut need_comma = false;
        for i in self.0.iter_set() {
            match i {
                KEY_FLAG_CERTIFY
                    | KEY_FLAG_SIGN
                    | KEY_FLAG_ENCRYPT_FOR_TRANSPORT
                    | KEY_FLAG_ENCRYPT_AT_REST
                    | KEY_FLAG_SPLIT_KEY
                    | KEY_FLAG_AUTHENTICATE
                    | KEY_FLAG_GROUP_KEY
                    => (),
                i => {
                    if need_comma { f.write_str(", ")?; }
                    write!(f, "#{}", i)?;
                    need_comma = true;
                },
            }
        }

        // Mention any padding, as equality is sensitive to this.
        if let Some(padding) = self.0.padding_bytes() {
            if need_comma { f.write_str(", ")?; }
            write!(f, "+padding({} bytes)", padding)?;
        }

        Ok(())
    }
}

impl BitAnd for &KeyFlags {
    type Output = KeyFlags;

    fn bitand(self, rhs: Self) -> KeyFlags {
        let l = self.as_bitfield().as_bytes();
        let r = rhs.as_bitfield().as_bytes();

        let mut c = Vec::with_capacity(std::cmp::min(l.len(), r.len()));
        for (l, r) in l.iter().zip(r.iter()) {
            c.push(l & r);
        }

        KeyFlags(c.into())
    }
}

impl BitOr for &KeyFlags {
    type Output = KeyFlags;

    fn bitor(self, rhs: Self) -> KeyFlags {
        let l = self.as_bitfield().as_bytes();
        let r = rhs.as_bitfield().as_bytes();

        // Make l the longer one.
        let (l, r) = if l.len() > r.len() {
            (l, r)
        } else {
            (r, l)
        };

        let mut l = l.to_vec();
        for (i, r) in r.iter().enumerate() {
            l[i] |= r;
        }

        KeyFlags(l.into())
    }
}

impl AsRef<KeyFlags> for KeyFlags {
    fn as_ref(&self) -> &KeyFlags {
        self
    }
}

impl KeyFlags {
    /// Creates a new instance from `bits`.
    pub fn new<B: AsRef<[u8]>>(bits: B) -> Self {
        Self(bits.as_ref().to_vec().into())
    }

    /// Returns a new `KeyFlags` with all capabilities disabled.
    pub fn empty() -> Self {
        KeyFlags::new(&[])
    }

    /// Returns a reference to the underlying [`Bitfield`].
    pub fn as_bitfield(&self) -> &Bitfield {
        &self.0
    }

    /// Returns a mutable reference to the underlying [`Bitfield`].
    pub fn as_bitfield_mut(&mut self) -> &mut Bitfield {
        &mut self.0
    }

    /// Compares two key flag sets for semantic equality.
    ///
    /// `KeyFlags` implementation of `PartialEq` compares two key
    /// flag sets for serialized equality.  That is, the `PartialEq`
    /// implementation considers two key flag sets to *not* be equal
    /// if they have different amounts of padding.  This comparison
    /// function ignores padding.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let a = KeyFlags::new(&[0x1]);
    /// let b = KeyFlags::new(&[0x1, 0x0]);
    ///
    /// assert!(a != b);
    /// assert!(a.normalized_eq(&b));
    /// # Ok(()) }
    /// ```
    pub fn normalized_eq(&self, other: &Self) -> bool {
        self.0.normalized_eq(&other.0)
    }

    /// Returns whether the specified key flag is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// // Key flags 0 and 2.
    /// let kf = KeyFlags::new(&[0x5]);
    ///
    /// assert!(kf.get(0));
    /// assert!(! kf.get(1));
    /// assert!(kf.get(2));
    /// assert!(! kf.get(3));
    /// assert!(! kf.get(8));
    /// assert!(! kf.get(80));
    /// # assert!(kf.for_certification());
    /// # Ok(()) }
    /// ```
    pub fn get(&self, bit: usize) -> bool {
        self.0.get(bit)
    }

    /// Sets the specified key flag.
    ///
    /// This also clears any padding (trailing NUL bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let kf = KeyFlags::empty().set(0).set(2);
    ///
    /// assert!(kf.get(0));
    /// assert!(! kf.get(1));
    /// assert!(kf.get(2));
    /// assert!(! kf.get(3));
    /// # assert!(kf.for_certification());
    /// # Ok(()) }
    /// ```
    pub fn set(mut self, bit: usize) -> Self {
        self.0.set(bit);
        self.0.canonicalize();
        self
    }

    /// Clears the specified key flag.
    ///
    /// This also clears any padding (trailing NUL bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let kf = KeyFlags::empty().set(0).set(2).clear(2);
    ///
    /// assert!(kf.get(0));
    /// assert!(! kf.get(1));
    /// assert!(! kf.get(2));
    /// assert!(! kf.get(3));
    /// # assert!(kf.for_certification());
    /// # Ok(()) }
    /// ```
    pub fn clear(mut self, bit: usize) -> Self {
        self.0.clear(bit);
        self.0.canonicalize();
        self
    }

    /// This key may be used to certify other keys.
    pub fn for_certification(&self) -> bool {
        self.get(KEY_FLAG_CERTIFY)
    }

    /// Returns a KeyFlags where the certificate flag is set.
    pub fn certification() -> Self {
        KeyFlags::empty().set_certification()
    }

    /// Declares that this key may be used to certify other keys.
    pub fn set_certification(self) -> Self {
        self.set(KEY_FLAG_CERTIFY)
    }

    /// Declares that this key may not be used to certify other keys.
    pub fn clear_certification(self) -> Self {
        self.clear(KEY_FLAG_CERTIFY)
    }

    /// Declares whether this key may be used to certify other keys.
    pub fn set_certification_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_CERTIFY)
        } else {
            self.clear(KEY_FLAG_CERTIFY)
        }
    }

    /// This key may be used to sign data.
    pub fn for_signing(&self) -> bool {
        self.get(KEY_FLAG_SIGN)
    }

    /// Returns a KeyFlags where the signing flag is set.
    pub fn signing() -> Self {
        KeyFlags::empty().set_signing()
    }

    /// Declares that this key may be used to sign data.
    pub fn set_signing(self) -> Self {
        self.set(KEY_FLAG_SIGN)
    }

    /// Declares that this key may not be used to sign data.
    pub fn clear_signing(self) -> Self {
        self.clear(KEY_FLAG_SIGN)
    }

    /// Declares whether this key may be used to sign data.
    pub fn set_signing_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_SIGN)
        } else {
            self.clear(KEY_FLAG_SIGN)
        }
    }

    /// This key may be used to encrypt communications.
    pub fn for_transport_encryption(&self) -> bool {
        self.get(KEY_FLAG_ENCRYPT_FOR_TRANSPORT)
    }

    /// Returns a KeyFlags where the transport encryption flag is set.
    pub fn transport_encryption() -> Self {
        KeyFlags::empty().set_transport_encryption()
    }

    /// Declares that this key may be used to encrypt communications.
    pub fn set_transport_encryption(self) -> Self {
        self.set(KEY_FLAG_ENCRYPT_FOR_TRANSPORT)
    }

    /// Declares that this key may not be used to encrypt communications.
    pub fn clear_transport_encryption(self) -> Self {
        self.clear(KEY_FLAG_ENCRYPT_FOR_TRANSPORT)
    }

    /// Declares whether this key may be used to encrypt communications.
    pub fn set_transport_encryption_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_ENCRYPT_FOR_TRANSPORT)
        } else {
            self.clear(KEY_FLAG_ENCRYPT_FOR_TRANSPORT)
        }
    }

    /// This key may be used to encrypt storage.
    pub fn for_storage_encryption(&self) -> bool {
        self.get(KEY_FLAG_ENCRYPT_AT_REST)
    }

    /// Returns a KeyFlags where the storage encryption flag is set.
    pub fn storage_encryption() -> Self {
        KeyFlags::empty().set_storage_encryption()
    }

    /// Declares that this key may be used to encrypt storage.
    pub fn set_storage_encryption(self) -> Self {
        self.set(KEY_FLAG_ENCRYPT_AT_REST)
    }

    /// Declares that this key may not be used to encrypt storage.
    pub fn clear_storage_encryption(self) -> Self {
        self.clear(KEY_FLAG_ENCRYPT_AT_REST)
    }

    /// Declares whether this key may be used to encrypt storage.
    pub fn set_storage_encryption_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_ENCRYPT_AT_REST)
        } else {
            self.clear(KEY_FLAG_ENCRYPT_AT_REST)
        }
    }

    /// This key may be used for authentication.
    pub fn for_authentication(&self) -> bool {
        self.get(KEY_FLAG_AUTHENTICATE)
    }

    /// Returns a KeyFlags where the authentication flag is set.
    pub fn authentication() -> Self {
        KeyFlags::empty().set_authentication()
    }

    /// Declares that this key may be used for authentication.
    pub fn set_authentication(self) -> Self {
        self.set(KEY_FLAG_AUTHENTICATE)
    }

    /// Declares that this key may not be used for authentication.
    pub fn clear_authentication(self) -> Self {
        self.clear(KEY_FLAG_AUTHENTICATE)
    }

    /// Declares whether this key may be used for authentication.
    pub fn set_authentication_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_AUTHENTICATE)
        } else {
            self.clear(KEY_FLAG_AUTHENTICATE)
        }
    }

    /// The private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn is_split_key(&self) -> bool {
        self.get(KEY_FLAG_SPLIT_KEY)
    }

    /// Returns a KeyFlags where the split key flag is set.
    pub fn split_key() -> Self {
        KeyFlags::empty().set_split_key()
    }

    /// Declares that the private component of this key may have been
    /// split using a secret-sharing mechanism.
    pub fn set_split_key(self) -> Self {
        self.set(KEY_FLAG_SPLIT_KEY)
    }

    /// Declares that the private component of this key has not been
    /// split using a secret-sharing mechanism.
    pub fn clear_split_key(self) -> Self {
        self.clear(KEY_FLAG_SPLIT_KEY)
    }

    /// Declares whether the private component of this key may have been
    /// split using a secret-sharing mechanism.
    pub fn set_split_key_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_SPLIT_KEY)
        } else {
            self.clear(KEY_FLAG_SPLIT_KEY)
        }
    }

    /// The private component of this key may be in possession of more
    /// than one person.
    pub fn is_group_key(&self) -> bool {
        self.get(KEY_FLAG_GROUP_KEY)
    }

    /// Returns a KeyFlags where the group flag is set.
    pub fn group_key() -> Self {
        KeyFlags::empty().set_group_key()
    }

    /// Declares that the private component of this key is in
    /// possession of more than one person.
    pub fn set_group_key(self) -> Self {
        self.set(KEY_FLAG_GROUP_KEY)
    }

    /// Declares that the private component of this key should not be
    /// in possession of more than one person.
    pub fn clear_group_key(self) -> Self {
        self.clear(KEY_FLAG_GROUP_KEY)
    }

    /// Declares whether the private component of this key is in
    /// possession of more than one person.
    pub fn set_group_key_to(self, value: bool) -> Self {
        if value {
            self.set(KEY_FLAG_GROUP_KEY)
        } else {
            self.clear(KEY_FLAG_GROUP_KEY)
        }
    }

    /// Returns whether no flags are set.
    pub fn is_empty(&self) -> bool {
        self.as_bitfield().as_bytes().iter().all(|b| *b == 0)
    }
}

/// This key may be used to certify other keys.
const KEY_FLAG_CERTIFY: usize = 0;

/// This key may be used to sign data.
const KEY_FLAG_SIGN: usize = 1;

/// This key may be used to encrypt communications.
const KEY_FLAG_ENCRYPT_FOR_TRANSPORT: usize = 2;

/// This key may be used to encrypt storage.
const KEY_FLAG_ENCRYPT_AT_REST: usize = 3;

/// The private component of this key may have been split by a
/// secret-sharing mechanism.
const KEY_FLAG_SPLIT_KEY: usize = 4;

/// This key may be used for authentication.
const KEY_FLAG_AUTHENTICATE: usize = 5;

/// The private component of this key may be in the possession of more
/// than one person.
const KEY_FLAG_GROUP_KEY: usize = 7;

#[cfg(test)]
impl Arbitrary for KeyFlags {
    fn arbitrary(g: &mut Gen) -> Self {
        Self::new(Vec::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn roundtrip(val: KeyFlags) -> bool {
            let mut q_bytes = val.as_bitfield().as_bytes().to_vec();
            let q = KeyFlags::new(&q_bytes);
            assert_eq!(val, q);
            assert!(val.normalized_eq(&q));

            // Add some padding to q.  Make sure they are still equal.
            q_bytes.push(0);
            let q = KeyFlags::new(&q_bytes);
            assert!(val != q);
            assert!(val.normalized_eq(&q));

            q_bytes.push(0);
            let q = KeyFlags::new(&q_bytes);
            assert!(val != q);
            assert!(val.normalized_eq(&q));

            true
        }
    }

    #[test]
    fn test_set_to() {
        macro_rules! t {
            ($set:ident, $set2:ident) => {
                // Set using set2.
                assert_eq!(KeyFlags::empty().$set(),
                           KeyFlags::empty().$set2(true));

                // Clear using set2.
                assert_eq!(KeyFlags::empty().$set2(false),
                           KeyFlags::empty());

                // Set using set, then clear using set2.
                assert_eq!(KeyFlags::empty().$set().$set2(false),
                           KeyFlags::empty());
            }
        }

        t!(set_certification, set_certification_to);
        t!(set_signing, set_signing_to);
        t!(set_transport_encryption, set_transport_encryption_to);
        t!(set_storage_encryption, set_storage_encryption_to);
        t!(set_split_key, set_split_key_to);
        t!(set_group_key, set_group_key_to);
    }
}
