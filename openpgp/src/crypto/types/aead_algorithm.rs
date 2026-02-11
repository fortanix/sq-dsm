use std::{
    fmt,
};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// AEAD modes.
///
/// See [AEAD Algorithms] for details.
///
///   [AEAD Algorithms]: https://www.rfc-editor.org/rfc/rfc9580.html#name-aead-algorithms
///
/// The values can be converted into and from their corresponding values of the serialized format.
///
/// Use [`AEADAlgorithm::from`] to translate a numeric value to a
/// symbolic one.
///
///   [`AEADAlgorithm::from`]: std::convert::From
///
/// # Examples
///
/// Use `AEADAlgorithm` to set the preferred AEAD algorithms on a signature:
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::packet::signature::SignatureBuilder;
/// use openpgp::types::{AEADAlgorithm, Features, SignatureType, SymmetricAlgorithm};
///
/// # fn main() -> openpgp::Result<()> {
/// let features = Features::empty().set_seipdv2();
/// let mut builder = SignatureBuilder::new(SignatureType::DirectKey)
///     .set_features(features)?
///     .set_preferred_aead_ciphersuites(vec![
///         (SymmetricAlgorithm::Camellia128, AEADAlgorithm::EAX),
///     ])?;
/// # Ok(()) }
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum AEADAlgorithm {
    /// EAX mode.
    EAX,
    /// OCB mode.
    OCB,
    /// Galois/Counter mode.
    GCM,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),
}
assert_send_and_sync!(AEADAlgorithm);

const AEAD_ALGORITHM_VARIANTS: [AEADAlgorithm; 3] = [
    AEADAlgorithm::EAX,
    AEADAlgorithm::OCB,
    AEADAlgorithm::GCM,
];

impl Default for AEADAlgorithm {
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm, but fall back to any supported algorithm.
    fn default() -> Self {
        [
            AEADAlgorithm::OCB, // Prefer OCB.
            AEADAlgorithm::GCM,
            AEADAlgorithm::EAX, // EAX is the slowest.
        ]
            .into_iter()
            .filter(Self::is_supported)
            .next()
        // One is better be supported, else just return OCB and hope
        // for the best.
            .unwrap_or(AEADAlgorithm::OCB)
    }
}

impl AEADAlgorithm {
    /// Returns whether this algorithm is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::AEADAlgorithm;
    ///
    /// assert!(! AEADAlgorithm::Private(100).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use crate::crypto::backend::{Backend, interface::Aead};
        Backend::supports_algo(*self)
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`AEADAlgorithm::Private`], or
    /// [`AEADAlgorithm::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        AEAD_ALGORITHM_VARIANTS.iter().cloned()
    }
}

impl From<u8> for AEADAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            1 => AEADAlgorithm::EAX,
            2 => AEADAlgorithm::OCB,
            3 => AEADAlgorithm::GCM,
            100..=110 => AEADAlgorithm::Private(u),
            u => AEADAlgorithm::Unknown(u),
        }
    }
}

impl From<AEADAlgorithm> for u8 {
    fn from(s: AEADAlgorithm) -> u8 {
        match s {
            AEADAlgorithm::EAX => 1,
            AEADAlgorithm::OCB => 2,
            AEADAlgorithm::GCM => 3,
            AEADAlgorithm::Private(u) => u,
            AEADAlgorithm::Unknown(u) => u,
        }
    }
}

/// Formats the AEAD algorithm name.
///
/// There are two ways the AEAD algorithm name can be formatted.  By
/// default the short name is used.  The alternate format uses the
/// full algorithm name.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::AEADAlgorithm;
///
/// // default, short format
/// assert_eq!("EAX", format!("{}", AEADAlgorithm::EAX));
///
/// // alternate, long format
/// assert_eq!("EAX mode", format!("{:#}", AEADAlgorithm::EAX));
/// ```
impl fmt::Display for AEADAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            match *self {
                AEADAlgorithm::EAX =>
                    f.write_str("EAX mode"),
                AEADAlgorithm::OCB =>
                    f.write_str("OCB mode"),
                AEADAlgorithm::GCM =>
                    f.write_str("GCM mode"),
                AEADAlgorithm::Private(u) =>
                    f.write_fmt(format_args!("Private/Experimental AEAD algorithm {}", u)),
                AEADAlgorithm::Unknown(u) =>
                    f.write_fmt(format_args!("Unknown AEAD algorithm {}", u)),
            }
        } else {
            match *self {
                AEADAlgorithm::EAX =>
                    f.write_str("EAX"),
                AEADAlgorithm::OCB =>
                    f.write_str("OCB"),
                AEADAlgorithm::GCM =>
                    f.write_str("GCM"),
                AEADAlgorithm::Private(u) =>
                    f.write_fmt(format_args!("Private AEAD algo {}", u)),
                AEADAlgorithm::Unknown(u) =>
                    f.write_fmt(format_args!("Unknown AEAD algo {}", u)),
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for AEADAlgorithm {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn aead_roundtrip(aead: AEADAlgorithm) -> bool {
            let val: u8 = aead.into();
            aead == AEADAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn aead_display(aead: AEADAlgorithm) -> bool {
            let s = format!("{}", aead);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn aead_parse(aead: AEADAlgorithm) -> bool {
            match aead {
                AEADAlgorithm::Unknown(u) =>
                    u == 0 || u > 110 || (u > 2 && u < 100),
                AEADAlgorithm::Private(u) =>
                    (100..=110).contains(&u),
                _ => true
            }
        }
    }

    #[test]
    fn aead_algorithms_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // AEAD_ALGORITHM_VARIANTS is a list.  Derive it in a
        // different way to double-check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(AEADAlgorithm::from)
            .filter(|t| {
                match t {
                    AEADAlgorithm::Private(_) => false,
                    AEADAlgorithm::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(AEAD_ALGORITHM_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
