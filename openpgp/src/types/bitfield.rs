use serde::{Deserialize, Serialize};

/// A variable-sized set of boolean flags.
///
/// This encodes flags in signature subpackets such as [`Features`]
/// and [`KeyFlags`].  The `Bitfield` grows to accommodate all bits
/// that are set, and querying a bit outside the allocated space will
/// return `false`.  Note that it will not automatically shrink if
/// clearing a bit would leave trailing bytes to be zero.  To do that,
/// explicitly call [`Bitfield::canonicalize`].
///
///   [`Features`]: crate::types::Features
///   [`KeyFlags`]: crate::types::KeyFlags
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Bitfield {
    raw: Vec<u8>,
}

impl From<Vec<u8>> for Bitfield {
    fn from(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

impl AsRef<[u8]> for Bitfield {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for Bitfield {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

impl Bitfield {
    /// Returns all bits that are set starting from bit 0, the
    /// least-significant bit in the left-most byte.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let f = Bitfield::from(vec![0b0000_0001, 0b0000_0010]);
    /// let mut i = f.iter_set();
    /// assert_eq!(i.next(), Some(0));
    /// assert_eq!(i.next(), Some(9));
    /// assert_eq!(i.next(), None);
    /// ```
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + Send + Sync + '_
    {
        self.raw.iter()
            .flat_map(|b| {
                (0..8).into_iter().map(move |i| {
                    b & (1 << i) != 0
                })
            })
            .enumerate()
            .filter_map(|(i, v)| if v { Some(i) } else { None })
    }

    /// Returns the number of trailing zero bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::from(vec![0b0000_0001]);
    /// assert!(f.padding_bytes().is_none());
    /// f.clear(0);
    /// assert_eq!(f.padding_bytes().unwrap().get(), 1);
    /// f.canonicalize();
    /// assert!(f.padding_bytes().is_none());
    /// ```
    pub fn padding_bytes(&self) -> Option<std::num::NonZeroUsize> {
        std::num::NonZeroUsize::new(
            self.raw.iter().rev().take_while(|b| **b == 0).count())
    }

    /// Compares two feature sets for semantic equality.
    ///
    /// Returns true if both sets have the same flags set, i.e. this
    /// function ignores any trailing zero bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let f = Bitfield::from(vec![0b0000_0001]);
    /// let g = Bitfield::from(vec![0b0000_0001, 0b0000_0000]);
    /// assert!(f != g);
    /// assert!(f.normalized_eq(&g));
    /// ```
    pub fn normalized_eq(&self, other: &Self) -> bool {
        let (small, big) = if self.raw.len() < other.raw.len() {
            (self, other)
        } else {
            (other, self)
        };

        for (s, b) in small.raw.iter().zip(big.raw.iter()) {
            if s != b {
                return false;
            }
        }

        for &b in &big.raw[small.raw.len()..] {
            if b != 0 {
                return false;
            }
        }

        true
    }

    /// Returns a slice containing the raw values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::default();
    /// assert_eq!(f.as_bytes(), &[]);
    /// f.set(0);
    /// assert_eq!(f.as_bytes(), &[0b0000_0001]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns a mutable slice containing the raw values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::from(vec![0b0000_0000]);
    /// assert_eq!(f.get(0), false);
    /// f.as_bytes_mut()[0] = 0b0000_0001;
    /// assert_eq!(f.get(0), true);
    /// ```
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.raw
    }

    /// Returns whether the specified flag is set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let f = Bitfield::default();
    /// assert_eq!(f.get(0), false);
    /// assert_eq!(f.get(23), false);
    ///
    /// let f = Bitfield::from(vec![0b0000_0001]);
    /// assert_eq!(f.get(0), true);
    /// ```
    pub fn get(&self, bit: usize) -> bool {
        let byte = bit / 8;

        if byte >= self.raw.len() {
            // Unset bits are false.
            false
        } else {
            (self.raw[byte] & (1 << (bit % 8))) != 0
        }
    }

    /// Canonicalize by removing any trailing zero bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::from(vec![0b0000_0001]);
    /// assert!(f.padding_bytes().is_none());
    /// f.clear(0);
    /// assert_eq!(f.padding_bytes().unwrap().get(), 1);
    /// f.canonicalize();
    /// assert!(f.padding_bytes().is_none());
    /// ```
    pub fn canonicalize(&mut self) {
        while !self.raw.is_empty() && self.raw[self.raw.len() - 1] == 0 {
            self.raw.truncate(self.raw.len() - 1);
        }
    }

    /// Sets the specified flag.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::default();
    /// assert_eq!(f.get(0), false);
    /// f.set(0);
    /// assert_eq!(f.get(0), true);
    /// ```
    pub fn set(&mut self, bit: usize) {
        let byte = bit / 8;
        while self.raw.len() <= byte {
            self.raw.push(0);
        }
        self.raw[byte] |= 1 << (bit % 8);
    }

    /// Clears the specified flag.
    ///
    /// Note: This does not implicitly canonicalize the bit field.  To
    /// do that, invoke [`Bitfield::canonicalize`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp::types::Bitfield;
    /// let mut f = Bitfield::from(vec![0b0000_0001]);
    /// assert_eq!(f.get(0), true);
    /// f.clear(0);
    /// assert_eq!(f.get(0), false);
    /// assert_eq!(f.padding_bytes().unwrap().get(), 1);
    /// ```
    pub fn clear(&mut self, bit: usize) {
        let byte = bit / 8;
        if byte < self.raw.len() {
            self.raw[byte] &= !(1 << (bit % 8));
        }
    }
}
