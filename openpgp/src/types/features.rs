use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::types::Bitfield;

/// Describes the features supported by an OpenPGP implementation.
///
/// The feature flags are defined in [Section 5.2.3.32 of RFC 9580],
/// and [Section 5.2.3.32 of draft-ietf-openpgp-crypto-refresh].
///
/// [Section 5.2.3.32 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.32
/// [Section 5.2.3.32 of draft-ietf-openpgp-crypto-refresh]: https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-10.html#features-subpacket
///
/// The feature flags are set by the user's OpenPGP implementation to
/// signal to any senders what features the implementation supports.
///
/// # A note on equality
///
/// `PartialEq` compares the serialized form of the two feature sets.
/// If you prefer to compare two feature sets for semantic equality,
/// you should use [`Features::normalized_eq`].  The difference
/// between semantic equality and serialized equality is that semantic
/// equality ignores differences in the amount of padding.
///
///   [`Features::normalized_eq`]: Features::normalized_eq()
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
///     CertBuilder::general_purpose(Some("alice@example.org"))
///     .generate()?;
/// match cert.with_policy(p, None)?.primary_userid()?.features() {
///     Some(features) => {
///         println!("Certificate holder's supported features:");
///         assert!(features.supports_seipdv1());
///         assert!(features.supports_seipdv2());
///     }
///     None => {
///         println!("Certificate Holder did not specify any features.");
/// #       unreachable!();
///     }
/// }
/// # Ok(()) }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Features(Bitfield);
assert_send_and_sync!(Features);

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Print known features first.
        let mut need_comma = false;
        if self.supports_seipdv1() {
            f.write_str("SEIPDv1")?;
            need_comma = true;
        }
        if self.supports_seipdv2() {
            if need_comma { f.write_str(", ")?; }
            f.write_str("SEIPDv2")?;
            need_comma = true;
        }

        // Now print any unknown features.
        for i in self.0.iter_set() {
            match i {
                FEATURE_FLAG_SEIPDV1 => (),
                FEATURE_FLAG_SEIPDV2 => (),
                i => {
                    if need_comma { f.write_str(", ")?; }
                    write!(f, "#{}", i)?;
                    need_comma = true;
                }
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

impl Features {
    /// Creates a new instance from `bytes`.
    ///
    /// This does not remove any trailing padding from `bytes`.
    pub fn new<B>(bytes: B) -> Self
        where B: AsRef<[u8]>
    {
        Features(bytes.as_ref().to_vec().into())
    }

    /// Returns an empty feature set.
    pub fn empty() -> Self {
        Self::new(&[][..])
    }

    /// Returns a feature set describing Sequoia's capabilities.
    pub fn sequoia() -> Self {
        let v : [u8; 1] = [ 0 ];

        Self::new(&v[..])
            .set_seipdv1()
            .set_seipdv2()
    }

    /// Returns a reference to the underlying [`Bitfield`].
    pub fn as_bitfield(&self) -> &Bitfield {
        &self.0
    }

    /// Returns a mutable reference to the underlying [`Bitfield`].
    pub fn as_bitfield_mut(&mut self) -> &mut Bitfield {
        &mut self.0
    }

    /// Compares two feature sets for semantic equality.
    ///
    /// `Features` implementation of `PartialEq` compares two feature
    /// sets for serialized equality.  That is, the `PartialEq`
    /// implementation considers two feature sets to *not* be equal if
    /// they have different amounts of padding.  This comparison
    /// function ignores padding.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let a = Features::new(&[0x1]);
    /// let b = Features::new(&[0x1, 0x0]);
    ///
    /// assert!(a != b);
    /// assert!(a.normalized_eq(&b));
    /// # Ok(()) }
    /// ```
    pub fn normalized_eq(&self, other: &Self) -> bool {
        self.0.normalized_eq(&other.0)
    }

    /// Returns whether the specified feature flag is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// // Feature flags 0 and 3.
    /// let f = Features::new(&[0x9]);
    ///
    /// assert!(f.get(0));
    /// assert!(! f.get(1));
    /// assert!(! f.get(2));
    /// assert!(f.get(3));
    /// assert!(! f.get(4));
    /// assert!(! f.get(8));
    /// assert!(! f.get(80));
    /// # Ok(()) }
    /// ```
    pub fn get(&self, bit: usize) -> bool {
        self.0.get(bit)
    }

    /// Sets the specified feature flag.
    ///
    /// This also clears any padding (trailing NUL bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty().set(0).set(3);
    ///
    /// assert!(f.get(0));
    /// assert!(! f.get(1));
    /// assert!(! f.get(2));
    /// assert!(f.get(3));
    /// assert!(! f.get(4));
    /// assert!(! f.get(8));
    /// assert!(! f.get(80));
    /// # Ok(()) }
    /// ```
    pub fn set(mut self, bit: usize) -> Self {
        self.0.set(bit);
        self.0.canonicalize();
        self
    }

    /// Clears the specified feature flag.
    ///
    /// This also clears any padding (trailing NUL bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty().set(0).set(3).clear(3);
    ///
    /// assert!(f.get(0));
    /// assert!(! f.get(1));
    /// assert!(! f.get(2));
    /// assert!(! f.get(3));
    /// # Ok(()) }
    /// ```
    pub fn clear(mut self, bit: usize) -> Self {
        self.0.clear(bit);
        self.0.canonicalize();
        self
    }

    /// Returns whether the SEIPDv1 feature flag is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty();
    ///
    /// assert!(! f.supports_seipdv1());
    /// # Ok(()) }
    /// ```
    pub fn supports_seipdv1(&self) -> bool {
        self.get(FEATURE_FLAG_SEIPDV1)
    }

    /// Sets the SEIPDv1 feature flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty().set_seipdv1();
    ///
    /// assert!(f.supports_seipdv1());
    /// # assert!(f.get(0));
    /// # Ok(()) }
    /// ```
    pub fn set_seipdv1(self) -> Self {
        self.set(FEATURE_FLAG_SEIPDV1)
    }

    /// Clears the SEIPDv1 feature flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::new(&[0x1]);
    /// assert!(f.supports_seipdv1());
    ///
    /// let f = f.clear_seipdv1();
    /// assert!(! f.supports_seipdv1());
    /// # Ok(()) }
    /// ```
    pub fn clear_seipdv1(self) -> Self {
        self.clear(FEATURE_FLAG_SEIPDV1)
    }

    /// Returns whether the SEIPDv2 feature flag is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty();
    ///
    /// assert!(! f.supports_seipdv2());
    /// # Ok(()) }
    /// ```
    pub fn supports_seipdv2(&self) -> bool {
        self.get(FEATURE_FLAG_SEIPDV2)
    }

    /// Sets the SEIPDv2 feature flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::empty().set_seipdv2();
    ///
    /// assert!(f.supports_seipdv2());
    /// # assert!(f.get(3));
    /// # Ok(()) }
    /// ```
    pub fn set_seipdv2(self) -> Self {
        self.set(FEATURE_FLAG_SEIPDV2)
    }

    /// Clears the SEIPDv2 feature flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::Features;
    ///
    /// # fn main() -> Result<()> {
    /// let f = Features::new(&[0x8]);
    /// assert!(f.supports_seipdv2());
    ///
    /// let f = f.clear_seipdv2();
    /// assert!(! f.supports_seipdv2());
    /// # Ok(()) }
    /// ```
    pub fn clear_seipdv2(self) -> Self {
        self.clear(FEATURE_FLAG_SEIPDV2)
    }
}

/// Symmetrically Encrypted and Integrity Protected Data packet
/// version 1.
const FEATURE_FLAG_SEIPDV1: usize = 0;

/// Symmetrically Encrypted and Integrity Protected Data packet
/// version 2.
const FEATURE_FLAG_SEIPDV2: usize = 3;

#[cfg(test)]
impl Arbitrary for Features {
    fn arbitrary(g: &mut Gen) -> Self {
        Self::new(Vec::arbitrary(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn roundtrip(val: Features) -> bool {
            let mut q_bytes = val.as_bitfield().as_bytes().to_vec();
            let q = Features::new(&q_bytes);
            assert_eq!(val, q);
            assert!(val.normalized_eq(&q));

            // Add some padding to q.  Make sure they are still equal.
            q_bytes.push(0);
            let q = Features::new(&q_bytes);
            assert!(val != q);
            assert!(val.normalized_eq(&q));

            q_bytes.push(0);
            let q = Features::new(&q_bytes);
            assert!(val != q);
            assert!(val.normalized_eq(&q));

            true
        }
    }

    #[test]
    fn set_clear() {
        let a = Features::new(&[ 0x5, 0x1, 0x0, 0xff ]);
        let b = Features::new(&[])
            .set(0).set(2)
            .set(8)
            .set(24).set(25).set(26).set(27).set(28).set(29).set(30).set(31);
        assert_eq!(a, b);

        // Clear a bit and make sure they are not equal.
        let b = b.clear(0);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(0);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        let b = b.clear(8);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(8);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        let b = b.clear(31);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(31);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        // Add a bit.
        let a = a.set(10);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(10);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        let a = a.set(32);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(32);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        let a = a.set(1000);
        assert!(a != b);
        assert!(! a.normalized_eq(&b));
        let b = b.set(1000);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));
    }

    #[test]
    fn known() {
        let a = Features::empty().set_seipdv1();
        let b = Features::new(&[ 0x1 ]);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        let a = Features::empty().set_seipdv2();
        let b = Features::new(&[ 0x8 ]);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));

        #[allow(deprecated)]
        let a = Features::empty().set_seipdv1().set_seipdv2();
        let b = Features::new(&[ 0x1 | 0x8 ]);
        assert_eq!(a, b);
        assert!(a.normalized_eq(&b));
    }
}
