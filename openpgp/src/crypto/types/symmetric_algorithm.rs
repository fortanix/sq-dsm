use std::{
    fmt,
};

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// The symmetric-key algorithms as defined in [Section 9.3 of RFC 9580].
///
///   [Section 9.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.3
///
/// The values can be converted into and from their corresponding values of the serialized format.
///
/// Use [`SymmetricAlgorithm::from`] to translate a numeric value to a
/// symbolic one.
///
///   [`SymmetricAlgorithm::from`]: std::convert::From
///
/// # Examples
///
/// Use `SymmetricAlgorithm` to set the preferred symmetric algorithms on a signature:
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::packet::signature::SignatureBuilder;
/// use openpgp::types::{HashAlgorithm, SymmetricAlgorithm, SignatureType};
///
/// # fn main() -> openpgp::Result<()> {
/// let mut builder = SignatureBuilder::new(SignatureType::DirectKey)
///     .set_hash_algo(HashAlgorithm::SHA512)
///     .set_preferred_symmetric_algorithms(vec![
///         SymmetricAlgorithm::AES256,
///     ])?;
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    /// Null encryption.
    Unencrypted,
    /// IDEA block cipher, deprecated in RFC 9580.
    #[deprecated(note = "Use a newer symmetric algorithm instead.")]
    IDEA,
    /// 3-DES in EDE configuration, deprecated in RFC 9580.
    #[deprecated(note = "Use a newer symmetric algorithm instead.")]
    TripleDES,
    /// CAST5/CAST128 block cipher, deprecated in RFC 9580.
    #[deprecated(note = "Use a newer symmetric algorithm instead.")]
    CAST5,
    /// Schneier et.al. Blowfish block cipher.
    Blowfish,
    /// 10-round AES.
    AES128,
    /// 12-round AES.
    AES192,
    /// 14-round AES.
    AES256,
    /// Twofish block cipher.
    Twofish,
    /// 18 rounds of NESSIEs Camellia.
    Camellia128,
    /// 24 rounds of NESSIEs Camellia w/192 bit keys.
    Camellia192,
    /// 24 rounds of NESSIEs Camellia w/256 bit keys.
    Camellia256,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),
}
assert_send_and_sync!(SymmetricAlgorithm);

#[allow(deprecated)]
const SYMMETRIC_ALGORITHM_VARIANTS: [ SymmetricAlgorithm; 11 ] = [
    SymmetricAlgorithm::IDEA,
    SymmetricAlgorithm::TripleDES,
    SymmetricAlgorithm::CAST5,
    SymmetricAlgorithm::Blowfish,
    SymmetricAlgorithm::AES128,
    SymmetricAlgorithm::AES192,
    SymmetricAlgorithm::AES256,
    SymmetricAlgorithm::Twofish,
    SymmetricAlgorithm::Camellia128,
    SymmetricAlgorithm::Camellia192,
    SymmetricAlgorithm::Camellia256,
];

impl Default for SymmetricAlgorithm {
    fn default() -> Self {
        SymmetricAlgorithm::AES256
    }
}

impl From<u8> for SymmetricAlgorithm {
    fn from(u: u8) -> Self {
        #[allow(deprecated)]
        match u {
            0 => SymmetricAlgorithm::Unencrypted,
            1 => SymmetricAlgorithm::IDEA,
            2 => SymmetricAlgorithm::TripleDES,
            3 => SymmetricAlgorithm::CAST5,
            4 => SymmetricAlgorithm::Blowfish,
            7 => SymmetricAlgorithm::AES128,
            8 => SymmetricAlgorithm::AES192,
            9 => SymmetricAlgorithm::AES256,
            10 => SymmetricAlgorithm::Twofish,
            11 => SymmetricAlgorithm::Camellia128,
            12 => SymmetricAlgorithm::Camellia192,
            13 => SymmetricAlgorithm::Camellia256,
            100..=110 => SymmetricAlgorithm::Private(u),
            u => SymmetricAlgorithm::Unknown(u),
        }
    }
}

impl From<SymmetricAlgorithm> for u8 {
    fn from(s: SymmetricAlgorithm) -> u8 {
        #[allow(deprecated)]
        match s {
            SymmetricAlgorithm::Unencrypted => 0,
            SymmetricAlgorithm::IDEA => 1,
            SymmetricAlgorithm::TripleDES => 2,
            SymmetricAlgorithm::CAST5 => 3,
            SymmetricAlgorithm::Blowfish => 4,
            SymmetricAlgorithm::AES128 => 7,
            SymmetricAlgorithm::AES192 => 8,
            SymmetricAlgorithm::AES256 => 9,
            SymmetricAlgorithm::Twofish => 10,
            SymmetricAlgorithm::Camellia128 => 11,
            SymmetricAlgorithm::Camellia192 => 12,
            SymmetricAlgorithm::Camellia256 => 13,
            SymmetricAlgorithm::Private(u) => u,
            SymmetricAlgorithm::Unknown(u) => u,
        }
    }
}


/// Formats the symmetric algorithm name.
///
/// There are two ways the symmetric algorithm name can be formatted.
/// By default the short name is used.  The alternate format uses the
/// full algorithm name.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::SymmetricAlgorithm;
///
/// // default, short format
/// assert_eq!("AES-128", format!("{}", SymmetricAlgorithm::AES128));
///
/// // alternate, long format
/// assert_eq!("AES with 128-bit key", format!("{:#}", SymmetricAlgorithm::AES128));
/// ```
impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[allow(deprecated)]
        if f.alternate() {
            match *self {
                SymmetricAlgorithm::Unencrypted =>
                    f.write_str("Unencrypted"),
                SymmetricAlgorithm::IDEA =>
                    f.write_str("IDEA"),
                SymmetricAlgorithm::TripleDES =>
                    f.write_str("TripleDES (EDE-DES, 168 bit key derived from 192))"),
                SymmetricAlgorithm::CAST5 =>
                    f.write_str("CAST5 (128 bit key, 16 rounds)"),
                SymmetricAlgorithm::Blowfish =>
                    f.write_str("Blowfish (128 bit key, 16 rounds)"),
                SymmetricAlgorithm::AES128 =>
                    f.write_str("AES with 128-bit key"),
                SymmetricAlgorithm::AES192 =>
                    f.write_str("AES with 192-bit key"),
                SymmetricAlgorithm::AES256 =>
                    f.write_str("AES with 256-bit key"),
                SymmetricAlgorithm::Twofish =>
                    f.write_str("Twofish with 256-bit key"),
                SymmetricAlgorithm::Camellia128 =>
                    f.write_str("Camellia with 128-bit key"),
                SymmetricAlgorithm::Camellia192 =>
                    f.write_str("Camellia with 192-bit key"),
                SymmetricAlgorithm::Camellia256 =>
                    f.write_str("Camellia with 256-bit key"),
                SymmetricAlgorithm::Private(u) =>
                    f.write_fmt(format_args!("Private/Experimental symmetric key algorithm {}", u)),
                SymmetricAlgorithm::Unknown(u) =>
                    f.write_fmt(format_args!("Unknown symmetric key algorithm {}", u)),
            }
        } else {
            match *self {
                SymmetricAlgorithm::Unencrypted =>
                    f.write_str("Unencrypted"),
                SymmetricAlgorithm::IDEA =>
                    f.write_str("IDEA"),
                SymmetricAlgorithm::TripleDES =>
                    f.write_str("3DES"),
                SymmetricAlgorithm::CAST5 =>
                    f.write_str("CAST5"),
                SymmetricAlgorithm::Blowfish =>
                    f.write_str("Blowfish"),
                SymmetricAlgorithm::AES128 =>
                    f.write_str("AES-128"),
                SymmetricAlgorithm::AES192 =>
                    f.write_str("AES-192"),
                SymmetricAlgorithm::AES256 =>
                    f.write_str("AES-256"),
                SymmetricAlgorithm::Twofish =>
                    f.write_str("Twofish"),
                SymmetricAlgorithm::Camellia128 =>
                    f.write_str("Camellia-128"),
                SymmetricAlgorithm::Camellia192 =>
                    f.write_str("Camellia-192"),
                SymmetricAlgorithm::Camellia256 =>
                    f.write_str("Camellia-256"),
                SymmetricAlgorithm::Private(u) =>
                    f.write_fmt(format_args!("Private symmetric key algo {}", u)),
                SymmetricAlgorithm::Unknown(u) =>
                    f.write_fmt(format_args!("Unknown symmetric key algo {}", u)),
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for SymmetricAlgorithm {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

impl SymmetricAlgorithm {
    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`SymmetricAlgorithm::Unencrypted`],
    /// [`SymmetricAlgorithm::Private`], or
    /// [`SymmetricAlgorithm::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        SYMMETRIC_ALGORITHM_VARIANTS.iter().cloned()
    }

    /// Returns whether this algorithm is supported by the crypto backend.
    ///
    /// All backends support all the AES variants.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    ///
    /// assert!(SymmetricAlgorithm::AES128.is_supported());
    /// assert!(SymmetricAlgorithm::AES192.is_supported());
    /// assert!(SymmetricAlgorithm::AES256.is_supported());
    ///
    /// assert!(!SymmetricAlgorithm::Unencrypted.is_supported());
    /// assert!(!SymmetricAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use crate::crypto::backend::{Backend, interface::Symmetric};
        Backend::supports_algo(*self)
    }

    /// Length of a key for this algorithm in bytes.
    ///
    /// Fails if the algorithm isn't known to Sequoia.
    pub fn key_size(self) -> Result<usize> {
        #[allow(deprecated)]
        match self {
            SymmetricAlgorithm::IDEA => Ok(16),
            SymmetricAlgorithm::TripleDES => Ok(24),
            SymmetricAlgorithm::CAST5 => Ok(16),
            // RFC4880, Section 9.2: Blowfish (128 bit key, 16 rounds)
            SymmetricAlgorithm::Blowfish => Ok(16),
            SymmetricAlgorithm::AES128 => Ok(16),
            SymmetricAlgorithm::AES192 => Ok(24),
            SymmetricAlgorithm::AES256 => Ok(32),
            SymmetricAlgorithm::Twofish => Ok(32),
            SymmetricAlgorithm::Camellia128 => Ok(16),
            SymmetricAlgorithm::Camellia192 => Ok(24),
            SymmetricAlgorithm::Camellia256 => Ok(32),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }

    /// Length of a block for this algorithm in bytes.
    ///
    /// Fails if the algorithm isn't known to Sequoia.
    pub fn block_size(self) -> Result<usize> {
        #[allow(deprecated)]
        match self {
            SymmetricAlgorithm::IDEA => Ok(8),
            SymmetricAlgorithm::TripleDES => Ok(8),
            SymmetricAlgorithm::CAST5 => Ok(8),
            SymmetricAlgorithm::Blowfish => Ok(8),
            SymmetricAlgorithm::AES128 => Ok(16),
            SymmetricAlgorithm::AES192 => Ok(16),
            SymmetricAlgorithm::AES256 => Ok(16),
            SymmetricAlgorithm::Twofish => Ok(16),
            SymmetricAlgorithm::Camellia128 => Ok(16),
            SymmetricAlgorithm::Camellia192 => Ok(16),
            SymmetricAlgorithm::Camellia256 => Ok(16),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn sym_roundtrip(sym: SymmetricAlgorithm) -> bool {
            let val: u8 = sym.into();
            sym == SymmetricAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn sym_display(sym: SymmetricAlgorithm) -> bool {
            let s = format!("{}", sym);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn sym_parse(sym: SymmetricAlgorithm) -> bool {
            match sym {
                SymmetricAlgorithm::Unknown(u) =>
                    u == 5 || u == 6 || u > 110 || (u > 10 && u < 100),
                SymmetricAlgorithm::Private(u) =>
                    (100..=110).contains(&u),
                _ => true
            }
        }
    }

    #[test]
    fn symmetric_algorithms_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // SYMMETRIC_ALGORITHM_VARIANTS is a list.  Derive it in a
        // different way to double-check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(SymmetricAlgorithm::from)
            .filter(|t| {
                match t {
                    SymmetricAlgorithm::Unencrypted => false,
                    SymmetricAlgorithm::Private(_) => false,
                    SymmetricAlgorithm::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(SYMMETRIC_ALGORITHM_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
