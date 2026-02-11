use std::{
    fmt,
};

use crate::{Error, Result};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// Elliptic curves used in OpenPGP.
///
/// `PublicKeyAlgorithm` does not differentiate between elliptic
/// curves.  Instead, the curve is specified using an OID prepended to
/// the key material.  We provide this type to be able to match on the
/// curves.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Curve {
    /// NIST curve P-256.
    NistP256,
    /// NIST curve P-384.
    NistP384,
    /// NIST curve P-521.
    NistP521,
    /// brainpoolP256r1.
    BrainpoolP256,
    /// brainpoolP384r1.
    BrainpoolP384,
    /// brainpoolP512r1.
    BrainpoolP512,
    /// D.J. Bernstein's "Twisted" Edwards curve Ed25519.
    Ed25519,
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519.
    Cv25519,
    /// Unknown curve.
    Unknown(Box<[u8]>),
}

assert_send_and_sync!(Curve);

const CURVE_VARIANTS: [Curve; 8] = [
    Curve::NistP256,
    Curve::NistP384,
    Curve::NistP521,
    Curve::BrainpoolP256,
    Curve::BrainpoolP384,
    Curve::BrainpoolP512,
    Curve::Ed25519,
    Curve::Cv25519,
];

impl Curve {
    /// Returns the length of public keys over this curve in bits.
    ///
    /// For the Kobliz curves this is the size of the underlying
    /// finite field.  For X25519 it is 256.
    ///
    /// This value is also equal to the length of a coordinate in bits.
    ///
    /// Note: This information is useless and should not be used to
    /// gauge the security of a particular curve. This function exists
    /// only because some legacy PGP application like HKP need it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Curve;
    ///
    /// assert_eq!(Curve::NistP256.bits()?, 256);
    /// assert_eq!(Curve::NistP384.bits()?, 384);
    /// assert_eq!(Curve::Ed25519.bits()?, 256);
    /// assert!(Curve::Unknown(Box::new([0x2B, 0x11])).bits().is_err());
    /// # Ok(()) }
    /// ```
    pub fn bits(&self) -> Result<usize> {
        use self::Curve::*;

        match self {
            NistP256 => Ok(256),
            NistP384 => Ok(384),
            NistP521 => Ok(521),
            BrainpoolP256 => Ok(256),
            BrainpoolP384 => Ok(384),
            BrainpoolP512 => Ok(512),
            Ed25519 => Ok(256),
            Cv25519 => Ok(256),
            Unknown(_) =>
                Err(Error::UnsupportedEllipticCurve(self.clone()).into()),
        }
    }

    /// Returns the curve's field size in bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Curve;
    ///
    /// assert_eq!(Curve::NistP256.field_size()?, 32);
    /// assert_eq!(Curve::NistP384.field_size()?, 48);
    /// assert_eq!(Curve::NistP521.field_size()?, 66);
    /// assert_eq!(Curve::Ed25519.field_size()?, 32);
    /// assert!(Curve::Unknown(Box::new([0x2B, 0x11])).field_size().is_err());
    /// # Ok(()) }
    /// ```
    pub fn field_size(&self) -> Result<usize> {
        self.bits()
            .map(|bits| (bits + 7) / 8)
    }
}

/// Formats the elliptic curve name.
///
/// There are two ways the elliptic curve name can be formatted.  By
/// default the short name is used.  The alternate format uses the
/// full curve name.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::Curve;
///
/// // default, short format
/// assert_eq!("NIST P-256", format!("{}", Curve::NistP256));
///
/// // alternate, long format
/// assert_eq!("NIST curve P-256", format!("{:#}", Curve::NistP256));
/// ```
impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Curve::*;

        struct DotEncoded<'o>(&'o [u8]);
        impl fmt::Display for DotEncoded<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut oid = self.0;
                if oid.is_empty() {
                    write!(f, "[invalid]")?;
                    return Ok(());
                }

                // The first octet encodes two values.
                let first = oid[0] / 40;
                let second = oid[0] % 40;
                oid = &oid[1..];
                write!(f, "{}.{}", first, second)?;

                let mut acc: usize = 0;
                for b in oid {
                    if b & 0x80 > 0 {
                        acc *= 0x80;
                        acc += (b & 0x7f) as usize;
                    } else {
                        acc *= 0x80;
                        acc += (b & 0x7f) as usize;
                        write!(f, ".{}", acc)?;
                        acc = 0;
                    }
                }

                Ok(())
            }
        }


        if f.alternate() {
            match *self {
                NistP256 => f.write_str("NIST curve P-256"),
                NistP384 => f.write_str("NIST curve P-384"),
                NistP521 => f.write_str("NIST curve P-521"),
                BrainpoolP256 => f.write_str("brainpoolP256r1"),
                BrainpoolP384 => f.write_str("brainpoolP384r1"),
                BrainpoolP512 => f.write_str("brainpoolP512r1"),
                Ed25519
                    => f.write_str("D.J. Bernstein's \"Twisted\" Edwards curve Ed25519"),
                Cv25519
                    => f.write_str("Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519"),
                Unknown(ref oid)
                    => write!(f, "Unknown curve (OID: {})", DotEncoded(oid)),
            }
        } else {
            match *self {
                NistP256 => f.write_str("NIST P-256"),
                NistP384 => f.write_str("NIST P-384"),
                NistP521 => f.write_str("NIST P-521"),
                BrainpoolP256 => f.write_str("brainpoolP256r1"),
                BrainpoolP384 => f.write_str("brainpoolP384r1"),
                BrainpoolP512 => f.write_str("brainpoolP512r1"),
                Ed25519
                    => f.write_str("Ed25519"),
                Cv25519
                    => f.write_str("Curve25519"),
                Unknown(ref oid)
                    => write!(f, "Unknown curve {}", DotEncoded(oid)),
            }
        }
    }
}

const NIST_P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const NIST_P384_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const NIST_P521_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const BRAINPOOL_P256_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const BRAINPOOL_P384_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const BRAINPOOL_P512_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
const ED25519_OID: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const CV25519_OID: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

impl Curve {
    /// Parses the given OID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Curve;
    ///
    /// assert_eq!(Curve::from_oid(&[0x2B, 0x81, 0x04, 0x00, 0x22]), Curve::NistP384);
    /// assert_eq!(Curve::from_oid(&[0x2B, 0x11]), Curve::Unknown(Box::new([0x2B, 0x11])));
    /// ```
    pub fn from_oid(oid: &[u8]) -> Curve {
        // Match on OIDs, see section 11 of RFC6637.
        match oid {
            NIST_P256_OID => Curve::NistP256,
            NIST_P384_OID => Curve::NistP384,
            NIST_P521_OID => Curve::NistP521,
            BRAINPOOL_P256_OID => Curve::BrainpoolP256,
            BRAINPOOL_P384_OID => Curve::BrainpoolP384,
            BRAINPOOL_P512_OID => Curve::BrainpoolP512,
            ED25519_OID => Curve::Ed25519,
            CV25519_OID => Curve::Cv25519,
            oid => Curve::Unknown(Vec::from(oid).into_boxed_slice()),
        }
    }

    /// Returns this curve's OID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Curve;
    ///
    /// assert_eq!(Curve::NistP384.oid(), &[0x2B, 0x81, 0x04, 0x00, 0x22]);
    /// assert_eq!(Curve::Unknown(Box::new([0x2B, 0x11])).oid(), &[0x2B, 0x11]);
    /// ```
    pub fn oid(&self) -> &[u8] {
        match self {
            Curve::NistP256 => NIST_P256_OID,
            Curve::NistP384 => NIST_P384_OID,
            Curve::NistP521 => NIST_P521_OID,
            Curve::BrainpoolP256 => BRAINPOOL_P256_OID,
            Curve::BrainpoolP384 => BRAINPOOL_P384_OID,
            Curve::BrainpoolP512 => BRAINPOOL_P512_OID,
            Curve::Ed25519 => ED25519_OID,
            Curve::Cv25519 => CV25519_OID,
            Curve::Unknown(ref oid) => oid,
        }
    }

    /// Returns whether this algorithm is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Curve;
    ///
    /// assert!(Curve::Ed25519.is_supported());
    /// assert!(!Curve::Unknown(Box::new([0x2B, 0x11])).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use crate::crypto::backend::{Backend, interface::Asymmetric};
        Backend::supports_curve(self)
    }

    /// Returns an iterator over all valid variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        CURVE_VARIANTS.iter().cloned()
    }
}

#[cfg(test)]
impl Arbitrary for Curve {
    fn arbitrary(g: &mut Gen) -> Self {
        match u8::arbitrary(g) % 9 {
            0 => Curve::NistP256,
            1 => Curve::NistP384,
            2 => Curve::NistP521,
            3 => Curve::BrainpoolP256,
            4 => Curve::BrainpoolP384,
            5 => Curve::BrainpoolP512,
            6 => Curve::Ed25519,
            7 => Curve::Cv25519,
            8 => Curve::Unknown({
                let mut k = <Vec<u8>>::arbitrary(g);
                k.truncate(255);
                k.into_boxed_slice()
            }),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn curve_roundtrip(curve: Curve) -> bool {
            curve == Curve::from_oid(curve.oid())
        }
    }
}
