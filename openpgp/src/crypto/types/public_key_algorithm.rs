use std::{
    fmt,
};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// The OpenPGP public key algorithms as defined in [Section 9.1 of
/// RFC 9580].
///
/// # Examples
///
/// ```rust
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::types::PublicKeyAlgorithm;
///
/// let (cert, _) = CertBuilder::new()
///     .set_cipher_suite(CipherSuite::Cv25519)
///     .generate()?;
///
/// assert_eq!(cert.primary_key().key().pk_algo(), PublicKeyAlgorithm::EdDSA);
/// # Ok(()) }
/// ```
///
///   [Section 9.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt or Sign)
    RSAEncryptSign,
    /// RSA Encrypt-Only, deprecated in RFC 4880.
    #[deprecated(note = "Use `PublicKeyAlgorithm::RSAEncryptSign`.")]
    RSAEncrypt,
    /// RSA Sign-Only, deprecated in RFC 4880.
    #[deprecated(note = "Use `PublicKeyAlgorithm::RSAEncryptSign`.")]
    RSASign,
    /// ElGamal (Encrypt-Only), deprecated in RFC 9580.
    #[deprecated(note = "Use a newer public key algorithm instead.")]
    ElGamalEncrypt,
    /// DSA (Digital Signature Algorithm)
    #[deprecated(note = "Use a newer public key algorithm instead.")]
    DSA,
    /// Elliptic curve DH
    ECDH,
    /// Elliptic curve DSA
    ECDSA,
    /// ElGamal (Encrypt or Sign), deprecated in RFC 4880.
    #[deprecated(note = "Use a newer public key algorithm instead.")]
    ElGamalEncryptSign,
    /// "Twisted" Edwards curve DSA
    EdDSA,
    /// X25519 (RFC 7748).
    X25519,
    /// X448 (RFC 7748).
    X448,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// Ed448 (RFC 8032).
    Ed448,
    /// Private algorithm identifier.
    Private(u8),
    /// Unknown algorithm identifier.
    Unknown(u8),
}
assert_send_and_sync!(PublicKeyAlgorithm);

#[allow(deprecated)]
pub(crate) const PUBLIC_KEY_ALGORITHM_VARIANTS: [PublicKeyAlgorithm; 13] = [
    PublicKeyAlgorithm::RSAEncryptSign,
    PublicKeyAlgorithm::RSAEncrypt,
    PublicKeyAlgorithm::RSASign,
    PublicKeyAlgorithm::ElGamalEncrypt,
    PublicKeyAlgorithm::DSA,
    PublicKeyAlgorithm::ECDH,
    PublicKeyAlgorithm::ECDSA,
    PublicKeyAlgorithm::ElGamalEncryptSign,
    PublicKeyAlgorithm::EdDSA,
    PublicKeyAlgorithm::X25519,
    PublicKeyAlgorithm::X448,
    PublicKeyAlgorithm::Ed25519,
    PublicKeyAlgorithm::Ed448,
];

impl PublicKeyAlgorithm {
    /// Returns true if the algorithm can sign data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::PublicKeyAlgorithm;
    ///
    /// assert!(PublicKeyAlgorithm::EdDSA.for_signing());
    /// assert!(PublicKeyAlgorithm::RSAEncryptSign.for_signing());
    /// assert!(!PublicKeyAlgorithm::ElGamalEncrypt.for_signing());
    /// ```
    pub fn for_signing(&self) -> bool {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)] {
            matches!(self, RSAEncryptSign
                     | RSASign
                     | DSA
                     | ECDSA
                     | ElGamalEncryptSign
                     | EdDSA
                     | Ed25519
                     | Ed448
                     | Private(_)
                     | Unknown(_)
            )
        }
    }

    /// Returns true if the algorithm can encrypt data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::PublicKeyAlgorithm;
    ///
    /// assert!(!PublicKeyAlgorithm::EdDSA.for_encryption());
    /// assert!(PublicKeyAlgorithm::RSAEncryptSign.for_encryption());
    /// assert!(PublicKeyAlgorithm::ElGamalEncrypt.for_encryption());
    /// ```
    pub fn for_encryption(&self) -> bool {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)] {
            matches!(self, RSAEncryptSign
                     | RSAEncrypt
                     | ElGamalEncrypt
                     | ECDH
                     | ElGamalEncryptSign
                     | X25519
                     | X448
                     | Private(_)
                     | Unknown(_)
            )
        }
    }

    /// Returns whether this algorithm is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::PublicKeyAlgorithm;
    ///
    /// assert!(PublicKeyAlgorithm::EdDSA.is_supported());
    /// assert!(PublicKeyAlgorithm::RSAEncryptSign.is_supported());
    /// assert!(!PublicKeyAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use crate::crypto::backend::{Backend, interface::Asymmetric};
        Backend::supports_algo(*self)
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`PublicKeyAlgorithm::Private`], or
    /// [`PublicKeyAlgorithm::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        PUBLIC_KEY_ALGORITHM_VARIANTS.iter().cloned()
    }
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(u: u8) -> Self {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match u {
            1 => RSAEncryptSign,
            2 => RSAEncrypt,
            3 => RSASign,
            16 => ElGamalEncrypt,
            17 => DSA,
            18 => ECDH,
            19 => ECDSA,
            20 => ElGamalEncryptSign,
            22 => EdDSA,
            25 => X25519,
            26 => X448,
            27 => Ed25519,
            28 => Ed448,
            100..=110 => Private(u),
            u => Unknown(u),
        }
    }
}

impl From<PublicKeyAlgorithm> for u8 {
    fn from(p: PublicKeyAlgorithm) -> u8 {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match p {
            RSAEncryptSign => 1,
            RSAEncrypt => 2,
            RSASign => 3,
            ElGamalEncrypt => 16,
            DSA => 17,
            ECDH => 18,
            ECDSA => 19,
            ElGamalEncryptSign => 20,
            EdDSA => 22,
            X25519 => 25,
            X448 => 26,
            Ed25519 => 27,
            Ed448 => 28,
            Private(u) => u,
            Unknown(u) => u,
        }
    }
}

/// Formats the public key algorithm name.
///
/// There are two ways the public key algorithm name can be formatted.
/// By default the short name is used.  The alternate format uses the
/// full public key algorithm name.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::PublicKeyAlgorithm;
///
/// // default, short format
/// assert_eq!("ECDH", format!("{}", PublicKeyAlgorithm::ECDH));
///
/// // alternate, long format
/// assert_eq!("ECDH public key algorithm", format!("{:#}", PublicKeyAlgorithm::ECDH));
/// ```
impl fmt::Display for PublicKeyAlgorithm {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::PublicKeyAlgorithm::*;
        if f.alternate() {
            match *self {
                RSAEncryptSign => f.write_str("RSA (Encrypt or Sign)"),
                RSAEncrypt => f.write_str("RSA Encrypt-Only"),
                RSASign => f.write_str("RSA Sign-Only"),
                ElGamalEncrypt => f.write_str("ElGamal (Encrypt-Only)"),
                DSA => f.write_str("DSA (Digital Signature Algorithm)"),
                ECDSA => f.write_str("ECDSA public key algorithm"),
                ElGamalEncryptSign => f.write_str("ElGamal (Encrypt or Sign)"),
                ECDH => f.write_str("ECDH public key algorithm"),
                EdDSA => f.write_str("EdDSA Edwards-curve Digital Signature Algorithm"),
                X25519 => f.write_str("X25519"),
                X448 => f.write_str("X448"),
                Ed25519 => f.write_str("Ed25519"),
                Ed448 => f.write_str("Ed448"),
                Private(u) =>
                    f.write_fmt(format_args!("Private/Experimental public key algorithm {}", u)),
                Unknown(u) =>
                    f.write_fmt(format_args!("Unknown public key algorithm {}", u)),
            }
        } else {
            match *self {
                RSAEncryptSign => f.write_str("RSA"),
                RSAEncrypt => f.write_str("RSA"),
                RSASign => f.write_str("RSA"),
                ElGamalEncrypt => f.write_str("ElGamal"),
                DSA => f.write_str("DSA"),
                ECDSA => f.write_str("ECDSA"),
                ElGamalEncryptSign => f.write_str("ElGamal"),
                ECDH => f.write_str("ECDH"),
                EdDSA => f.write_str("EdDSA"),
                X25519 => f.write_str("X25519"),
                X448 => f.write_str("X448"),
                Ed25519 => f.write_str("Ed25519"),
                Ed448 => f.write_str("Ed448"),
                Private(u) =>
                    f.write_fmt(format_args!("Private algo {}", u)),
                Unknown(u) =>
                    f.write_fmt(format_args!("Unknown algo {}", u)),
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for PublicKeyAlgorithm {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

#[cfg(test)]
impl PublicKeyAlgorithm {
    pub(crate) fn arbitrary_for_signing(g: &mut Gen) -> Self {
        use self::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        let a = g.choose(&[
            RSAEncryptSign, RSASign, DSA, ECDSA, EdDSA,
            Ed25519, Ed448,
        ]).unwrap();
        assert!(a.for_signing());
        *a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn pk_roundtrip(pk: PublicKeyAlgorithm) -> bool {
            let val: u8 = pk.into();
            pk == PublicKeyAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn pk_display(pk: PublicKeyAlgorithm) -> bool {
            let s = format!("{}", pk);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn pk_parse(pk: PublicKeyAlgorithm) -> bool {
            match pk {
                PublicKeyAlgorithm::Unknown(u) =>
                    u == 0 || u > 110 || (4..=15).contains(&u)
                    || (18..100).contains(&u),
                PublicKeyAlgorithm::Private(u) => (100..=110).contains(&u),
                _ => true
            }
        }
    }

    #[test]
    fn public_key_algorithms_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // PUBLIC_KEY_ALGORITHM_VARIANTS is a list.  Derive it in a
        // different way to double-check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(PublicKeyAlgorithm::from)
            .filter(|t| {
                match t {
                    PublicKeyAlgorithm::Private(_) => false,
                    PublicKeyAlgorithm::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(PUBLIC_KEY_ALGORITHM_VARIANTS.iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
