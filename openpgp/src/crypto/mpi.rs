//! Multiprecision Integers.
//!
//! Cryptographic objects like [public keys], [secret keys],
//! [ciphertexts], and [signatures] are scalar numbers of arbitrary
//! precision.  OpenPGP specifies that these are stored encoded as
//! big-endian integers with leading zeros stripped (See [Section 3.2
//! of RFC 9580]).  Multiprecision integers in OpenPGP are extended by
//! [Section 3.2.1 of RFC 9580] to store curves and coordinates used
//! in elliptic curve cryptography (ECC).
//!
//!   [public keys]: PublicKey
//!   [secret keys]: SecretKeyMaterial
//!   [ciphertexts]: Ciphertext
//!   [signatures]: Signature
//!   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
//!   [Section 3.2.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2.1
use std::fmt;
use std::cmp::Ordering;
use std::io::Write;
use std::borrow::Cow;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::fmt::hex;
use crate::types::{
    Curve,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};
use crate::crypto::hash::{self, Hash};
use crate::crypto::mem::{secure_cmp, Protected};
use crate::serialize::Marshal;

use crate::Error;
use crate::Result;

/// A Multiprecision Integer.
#[derive(Clone)]
pub struct MPI {
    /// Integer value as big-endian with leading zeros stripped.
    value: Box<[u8]>,
}
assert_send_and_sync!(MPI);

impl From<Vec<u8>> for MPI {
    fn from(v: Vec<u8>) -> Self {
        // XXX: This will leak secrets in v into the heap.  But,
        // eagerly clearing the memory may have a very high overhead,
        // after all, most MPIs that we encounter will not contain
        // secrets.  I think it is better to avoid creating MPIs that
        // contain secrets in the first place.  In 2.0, we can remove
        // the impl From<MPI> for ProtectedMPI.
        Self::new(&v)
    }
}

impl From<Box<[u8]>> for MPI {
    fn from(v: Box<[u8]>) -> Self {
        // XXX: This will leak secrets in v into the heap.  But,
        // eagerly clearing the memory may have a very high overhead,
        // after all, most MPIs that we encounter will not contain
        // secrets.  I think it is better to avoid creating MPIs that
        // contain secrets in the first place.  In 2.0, we can remove
        // the impl From<MPI> for ProtectedMPI.
        Self::new(&v)
    }
}

impl MPI {
    /// Trims leading zero octets.
    fn trim_leading_zeros(v: &[u8]) -> &[u8] {
        let offset = v.iter().take_while(|&&o| o == 0).count();
        &v[offset..]
    }

    /// Creates a new MPI.
    ///
    /// This function takes care of removing leading zeros.
    pub fn new(value: &[u8]) -> Self {
        let value = Self::trim_leading_zeros(value).to_vec().into_boxed_slice();

        MPI {
            value,
        }
    }

    /// Creates new MPI encoding an uncompressed EC point.
    ///
    /// Encodes the given point on an elliptic curve (see [Section 6 of
    /// RFC 6637] for details).  This is used to encode public keys
    /// and ciphertexts for the NIST curves (`NistP256`, `NistP384`,
    /// and `NistP521`).
    ///
    ///   [Section 6 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-6
    pub fn new_point(x: &[u8], y: &[u8], field_bits: usize) -> Self {
        Self::new_point_common(x, y, field_bits).into()
    }

    /// Common implementation shared between MPI and ProtectedMPI.
    fn new_point_common(x: &[u8], y: &[u8], field_bits: usize) -> Vec<u8> {
        let field_sz = if field_bits % 8 > 0 { 1 } else { 0 } + field_bits / 8;
        let mut val = vec![0x0u8; 1 + 2 * field_sz];
        let x_missing = field_sz - x.len();
        let y_missing = field_sz - y.len();

        val[0] = 0x4;
        val[1 + x_missing..1 + field_sz].copy_from_slice(x);
        val[1 + field_sz + y_missing..].copy_from_slice(y);
        val
    }

    /// Creates new MPI encoding a compressed EC point using native
    /// encoding.
    ///
    /// Encodes the given point on an elliptic curve (see [Section 13.2
    /// of RFC4880bis] for details).  This is used to encode public
    /// keys and ciphertexts for the Bernstein curves (currently
    /// `X25519`).
    ///
    ///   [Section 13.2 of RFC4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-13.2
    pub fn new_compressed_point(x: &[u8]) -> Self {
        Self::new_compressed_point_common(x).into()
    }

    /// Common implementation shared between MPI and ProtectedMPI.
    fn new_compressed_point_common(x: &[u8]) -> Vec<u8> {
        let mut val = vec![0; 1 + x.len()];
        val[0] = 0x40;
        val[1..].copy_from_slice(x);
        val
    }

    /// Creates a new MPI representing zero.
    pub fn zero() -> Self {
        Self::new(&[])
    }

    /// Tests whether the MPI represents zero.
    pub fn is_zero(&self) -> bool {
        self.value().is_empty()
    }

    /// Returns the length of the MPI in bits.
    ///
    /// Leading zero-bits are not included in the returned size.
    pub fn bits(&self) -> usize {
        self.value.len() * 8
            - self.value.get(0).map(|&b| b.leading_zeros() as usize)
                  .unwrap_or(0)
    }

    /// Returns the value of this MPI.
    ///
    /// Note that due to stripping of zero-bytes, the returned value
    /// may be shorter than expected.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the value of this MPI zero-padded to the given length.
    ///
    /// MPI-encoding strips leading zero-bytes.  This function adds
    /// them back, if necessary.  If the size exceeds `to`, an error
    /// is returned.
    pub fn value_padded(&self, to: usize) -> Result<Cow<[u8]>> {
        crate::crypto::pad(self.value(), to)
    }

    /// Decodes an EC point encoded as MPI.
    ///
    /// Decodes the MPI into a point on an elliptic curve (see
    /// [Section 6 of RFC 6637] and [Section 13.2 of RFC4880bis] for
    /// details).  If the point is not compressed, the function
    /// returns `(x, y)`.  If it is compressed, `y` will be empty.
    ///
    ///   [Section 6 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-6
    ///   [Section 13.2 of RFC4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-13.2
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedEllipticCurve` if the curve is not
    /// supported, `Error::MalformedMPI` if the point is formatted
    /// incorrectly, `Error::InvalidOperation` if the given curve is
    /// operating on native octet strings.
    pub fn decode_point(&self, curve: &Curve) -> Result<(&[u8], &[u8])> {
        Self::decode_point_common(self.value(), curve)
    }

    /// Common implementation shared between MPI and ProtectedMPI.
    fn decode_point_common<'a>(value: &'a [u8], curve: &Curve)
                               -> Result<(&'a [u8], &'a [u8])> {
        const ED25519_KEY_SIZE: usize = 32;
        const CURVE25519_SIZE: usize = 32;
        use self::Curve::*;
        match &curve {
            Ed25519 | Cv25519 => {
                assert_eq!(CURVE25519_SIZE, ED25519_KEY_SIZE);
                // This curve uses a custom compression format which
                // only contains the X coordinate.
                if value.len() != 1 + CURVE25519_SIZE {
                    return Err(Error::MalformedMPI(
                        format!("Bad size of Curve25519 key: {} expected: {}",
                                value.len(),
                                1 + CURVE25519_SIZE
                        )
                    ).into());
                }

                if value.get(0).map(|&b| b != 0x40).unwrap_or(true) {
                    return Err(Error::MalformedMPI(
                        "Bad encoding of Curve25519 key".into()).into());
                }

                Ok((&value[1..], &[]))
            },

            NistP256
                | NistP384
                | NistP521
                | BrainpoolP256
                | BrainpoolP384
                | BrainpoolP512
                =>
            {
                // Length of one coordinate in bytes, rounded up.
                let coordinate_length = curve.field_size()?;

                // Check length of Q.
                let expected_length =
                    1 // 0x04.
                    + (2 // (x, y)
                       * coordinate_length);

                if value.len() != expected_length {
                    return Err(Error::MalformedMPI(
                        format!("Invalid length of MPI: {} (expected {})",
                                value.len(), expected_length)).into());
                }

                if value.get(0).map(|&b| b != 0x04).unwrap_or(true) {
                    return Err(Error::MalformedMPI(
                        format!("Bad prefix: {:?} (expected Some(0x04))",
                                value.get(0))).into());
                }

                Ok((&value[1..1 + coordinate_length],
                    &value[1 + coordinate_length..]))
            },

            Unknown(_) =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
        }
    }

    /// Securely compares two MPIs in constant time.
    fn secure_memcmp(&self, other: &Self) -> Ordering {
        let cmp = unsafe {
            if self.value.len() == other.value.len() {
                ::memsec::memcmp(self.value.as_ptr(), other.value.as_ptr(),
                                 other.value.len())
            } else {
                self.value.len() as i32 - other.value.len() as i32
            }
        };

        match cmp {
            0 => Ordering::Equal,
            x if x < 0 => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{} bits: {}", self.bits(),
            crate::fmt::to_hex(&*self.value, true)))
    }
}

impl Hash for MPI {
    fn hash(&self, hash: &mut hash::Context) -> Result<()> {
        let len = self.bits() as u16;

        hash.update(&len.to_be_bytes());
        hash.update(&self.value);
        Ok(())
    }
}

#[cfg(test)]
impl Arbitrary for MPI {
    fn arbitrary(g: &mut Gen) -> Self {
        loop {
            let buf = <Vec<u8>>::arbitrary(g);

            if !buf.is_empty() && buf[0] != 0 {
                break MPI::new(&buf);
            }
        }
    }
}

impl PartialOrd for MPI {
    fn partial_cmp(&self, other: &MPI) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MPI {
    fn cmp(&self, other: &MPI) -> Ordering {
        self.secure_memcmp(other)
    }
}

impl PartialEq for MPI {
    fn eq(&self, other: &MPI) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MPI {}

impl std::hash::Hash for MPI {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

/// Holds a single MPI containing secrets.
///
/// The memory will be cleared when the object is dropped.  Used by
/// [`SecretKeyMaterial`] to protect secret keys.
///
#[derive(Clone)]
pub struct ProtectedMPI {
    /// Integer value as big-endian.
    value: Protected,
}
assert_send_and_sync!(ProtectedMPI);

impl From<&[u8]> for ProtectedMPI {
    fn from(m: &[u8]) -> Self {
        let value = Protected::from(MPI::trim_leading_zeros(m));
        ProtectedMPI {
            value,
        }
    }
}

impl From<Vec<u8>> for ProtectedMPI {
    fn from(m: Vec<u8>) -> Self {
        let value = Protected::from(MPI::trim_leading_zeros(&m));
        drop(Protected::from(m)); // Erase source.
        ProtectedMPI {
            value,
        }
    }
}

impl From<Box<[u8]>> for ProtectedMPI {
    fn from(m: Box<[u8]>) -> Self {
        let value = Protected::from(MPI::trim_leading_zeros(&m));
        drop(Protected::from(m)); // Erase source.
        ProtectedMPI {
            value,
        }
    }
}

impl From<Protected> for ProtectedMPI {
    fn from(m: Protected) -> Self {
        let value = Protected::from(MPI::trim_leading_zeros(&m));
        drop(m); // Erase source.
        ProtectedMPI {
            value,
        }
    }
}

impl PartialOrd for ProtectedMPI {
    fn partial_cmp(&self, other: &ProtectedMPI) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtectedMPI {
    fn cmp(&self, other: &ProtectedMPI) -> Ordering {
        self.secure_memcmp(other)
    }
}

impl PartialEq for ProtectedMPI {
    fn eq(&self, other: &ProtectedMPI) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ProtectedMPI {}

impl std::hash::Hash for ProtectedMPI {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

#[cfg(test)]
impl Arbitrary for ProtectedMPI {
    fn arbitrary(g: &mut Gen) -> Self {
        loop {
            let buf = <Vec<u8>>::arbitrary(g);

            if ! buf.is_empty() && buf[0] != 0 {
                break ProtectedMPI::from(buf);
            }
        }
    }
}

impl ProtectedMPI {
    /// Creates new MPI encoding an uncompressed EC point.
    ///
    /// Encodes the given point on an elliptic curve (see [Section 6 of
    /// RFC 6637] for details).  This is used to encode public keys
    /// and ciphertexts for the NIST curves (`NistP256`, `NistP384`,
    /// and `NistP521`).
    ///
    ///   [Section 6 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-6
    pub fn new_point(x: &[u8], y: &[u8], field_bits: usize) -> Self {
        MPI::new_point_common(x, y, field_bits).into()
    }

    /// Creates new MPI encoding a compressed EC point using native
    /// encoding.
    ///
    /// Encodes the given point on an elliptic curve (see [Section 13.2
    /// of RFC4880bis] for details).  This is used to encode public
    /// keys and ciphertexts for the Bernstein curves (currently
    /// `X25519`).
    ///
    ///   [Section 13.2 of RFC4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-13.2
    pub fn new_compressed_point(x: &[u8]) -> Self {
        MPI::new_compressed_point_common(x).into()
    }

    /// Returns the length of the MPI in bits.
    ///
    /// Leading zero-bits are not included in the returned size.
    pub fn bits(&self) -> usize {
        self.value.len() * 8
            - self.value.get(0).map(|&b| b.leading_zeros() as usize)
                  .unwrap_or(0)
    }

    /// Returns the value of this MPI.
    ///
    /// Note that due to stripping of zero-bytes, the returned value
    /// may be shorter than expected.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the value of this MPI zero-padded to the given length.
    ///
    /// MPI-encoding strips leading zero-bytes.  This function adds
    /// them back.  This operation is done unconditionally to avoid
    /// timing differences.  If the size exceeds `to`, the result is
    /// silently truncated to avoid timing differences.
    pub fn value_padded(&self, to: usize) -> Protected {
        let missing = to.saturating_sub(self.value.len());
        let limit = self.value.len().min(to);
        let mut v: Protected = vec![0; to].into();
        v[missing..].copy_from_slice(&self.value()[..limit]);
        v
    }

    /// Decodes an EC point encoded as MPI.
    ///
    /// Decodes the MPI into a point on an elliptic curve (see
    /// [Section 6 of RFC 6637] and [Section 13.2 of RFC4880bis] for
    /// details).  If the point is not compressed, the function
    /// returns `(x, y)`.  If it is compressed, `y` will be empty.
    ///
    ///   [Section 6 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-6
    ///   [Section 13.2 of RFC4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-13.2
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedEllipticCurve` if the curve is not
    /// supported, `Error::MalformedMPI` if the point is formatted
    /// incorrectly, `Error::InvalidOperation` if the given curve is
    /// operating on native octet strings.
    pub fn decode_point(&self, curve: &Curve) -> Result<(&[u8], &[u8])> {
        MPI::decode_point_common(self.value(), curve)
    }

    /// Securely compares two MPIs in constant time.
    fn secure_memcmp(&self, other: &Self) -> Ordering {
        (self.value.len() as i32).cmp(&(other.value.len() as i32))
            .then(
                // Protected compares in constant time.
                self.value.cmp(&other.value))
    }
}

impl fmt::Debug for ProtectedMPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            f.write_fmt(format_args!(
                "{} bits: {}", self.bits(),
                crate::fmt::to_hex(&*self.value, true)))
        } else {
            f.write_str("<Redacted>")
        }
    }
}

/// A public key.
///
/// Provides a typed and structured way of storing multiple MPIs (and
/// the occasional elliptic curve) in [`Key`] packets.
///
///   [`Key`]: crate::packet::Key
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PublicKey {
    /// RSA public key.
    RSA {
        /// Public exponent
        e: MPI,
        /// Public modulo N = pq.
        n: MPI,
    },

    /// NIST DSA public key.
    DSA {
        /// Prime of the ring Zp.
        p: MPI,
        /// Order of `g` in Zp.
        q: MPI,
        /// Public generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI,
    },

    /// ElGamal public key.
    ElGamal {
        /// Prime of the ring Zp.
        p: MPI,
        /// Generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI,
    },

    /// DJB's "Twisted" Edwards curve DSA public key.
    EdDSA {
        /// Curve we're using. Must be curve 25519.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// NIST's Elliptic Curve DSA public key.
    ECDSA {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// Elliptic Curve Diffie-Hellman public key.
    ECDH {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
        /// Algorithm used to derive the Key Encapsulation Key.
        hash: HashAlgorithm,
        /// Algorithm used to encapsulate the session key.
        sym: SymmetricAlgorithm,
    },

    /// X25519 public key.
    X25519 {
        /// The public key, an opaque string.
        u: [u8; 32],
    },

    /// X448 public key.
    X448 {
        /// The public key, an opaque string.
        u: Box<[u8; 56]>,
    },

    /// Ed25519 public key.
    Ed25519 {
        /// The public key, an opaque string.
        a: [u8; 32],
    },

    /// Ed448 public key.
    Ed448 {
        /// The public key, an opaque string.
        a: Box<[u8; 57]>,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}
assert_send_and_sync!(PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicKey::RSA { e, n } =>
                f.debug_struct("RSA")
                .field("e", e)
                .field("n", n)
                .finish(),

            PublicKey::DSA { p, q, g, y } =>
                f.debug_struct("DSA")
                .field("p", p)
                .field("q", q)
                .field("g", g)
                .field("y", y)
                .finish(),

            PublicKey::ElGamal { p, g, y } =>
                f.debug_struct("ElGamal")
                .field("p", p)
                .field("g", g)
                .field("y", y)
                .finish(),

            PublicKey::EdDSA { curve, q } =>
                f.debug_struct("EdDSA")
                .field("curve", curve)
                .field("q", q)
                .finish(),

            PublicKey::ECDSA { curve, q } =>
                f.debug_struct("ECDSA")
                .field("curve", curve)
                .field("q", q)
                .finish(),

            PublicKey::ECDH { curve, q, hash, sym } =>
                f.debug_struct("ECDH")
                .field("curve", curve)
                .field("q", q)
                .field("hash", hash)
                .field("sym", sym)
                .finish(),

            PublicKey::X25519 { u } =>
                f.debug_struct("X25519")
                .field("u", &hex::encode(u))
                .finish(),

            PublicKey::X448 { u } =>
                f.debug_struct("X448")
                .field("u", &hex::encode(u.as_ref()))
                .finish(),

            PublicKey::Ed25519 { a } =>
                f.debug_struct("Ed25519")
                .field("a", &hex::encode(a))
                .finish(),

            PublicKey::Ed448 { a } =>
                f.debug_struct("Ed448")
                .field("a", &hex::encode(a.as_ref()))
                .finish(),

            PublicKey::Unknown { mpis, rest } =>
                f.debug_struct("Unknown")
                .field("mpis", mpis)
                .field("rest", &hex::encode(rest))
                .finish(),
        }
    }
}

impl PublicKey {
    /// Returns the length of the public key in bits.
    ///
    /// For finite field crypto this returns the size of the field we
    /// operate in, for ECC it returns `Curve::bits()`.
    ///
    /// Note: This information is useless and should not be used to
    /// gauge the security of a particular key. This function exists
    /// only because some legacy PGP application like HKP need it.
    ///
    /// Returns `None` for unknown keys and curves.
    pub fn bits(&self) -> Option<usize> {
        use self::PublicKey::*;
        match self {
            RSA { ref n,.. } => Some(n.bits()),
            DSA { ref p,.. } => Some(p.bits()),
            ElGamal { ref p,.. } => Some(p.bits()),
            EdDSA { ref curve,.. } => curve.bits().ok(),
            ECDSA { ref curve,.. } => curve.bits().ok(),
            ECDH { ref curve,.. } => curve.bits().ok(),
            X25519 { .. } => Some(256),
            X448 { .. } => Some(448),
            Ed25519 { .. } => Some(256),
            Ed448 { .. } => Some(456),
            Unknown { .. } => None,
        }
    }

    /// Returns, if known, the public-key algorithm for this public
    /// key.
    pub fn algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::PublicKey::*;
        #[allow(deprecated)]
        match self {
            RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            DSA { .. } => Some(PublicKeyAlgorithm::DSA),
            ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            EdDSA { .. } => Some(PublicKeyAlgorithm::EdDSA),
            ECDSA { .. } => Some(PublicKeyAlgorithm::ECDSA),
            ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            X25519 { .. } => Some(PublicKeyAlgorithm::X25519),
            X448 { .. } => Some(PublicKeyAlgorithm::X448),
            Ed25519 { .. } => Some(PublicKeyAlgorithm::Ed25519),
            Ed448 { .. } => Some(PublicKeyAlgorithm::Ed448),
            Unknown { .. } => None,
        }
    }
}

impl Hash for PublicKey {
    fn hash(&self, mut hash: &mut hash::Context) -> Result<()> {
        self.serialize(&mut hash as &mut dyn Write)
    }
}

#[cfg(test)]
impl Arbitrary for PublicKey {
    fn arbitrary(g: &mut Gen) -> Self {
        use self::PublicKey::*;
        use crate::arbitrary_helper::gen_arbitrary_from_range;

        match gen_arbitrary_from_range(0..10, g) {
            0 => RSA {
                e: MPI::arbitrary(g),
                n: MPI::arbitrary(g),
            },

            1 => DSA {
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g),
            },

            2 => ElGamal {
                p: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g),
            },

            3 => EdDSA {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
            },

            4 => ECDSA {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
            },

            5 => ECDH {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
                hash: HashAlgorithm::arbitrary(g),
                sym: SymmetricAlgorithm::arbitrary(g),
            },

            6 => X25519 { u: arbitrary(g) },
            7 => X448 { u: Box::new(arbitrarize(g, [0; 56])) },
            8 => Ed25519 { a: arbitrary(g) },
            9 => Ed448 { a: Box::new(arbitrarize(g, [0; 57])) },

            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
pub(crate) fn arbitrarize<T: AsMut<[u8]>>(g: &mut Gen, mut a: T) -> T
{
    a.as_mut().iter_mut().for_each(|p| *p = Arbitrary::arbitrary(g));
    a
}

#[cfg(test)]
pub(crate) fn arbitrary<T: Default + AsMut<[u8]>>(g: &mut Gen) -> T
{
    arbitrarize(g, Default::default())
}


/// A secret key.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// [`Key`] packets.  Secret key components are protected by storing
/// them using [`ProtectedMPI`].
///
///   [`Key`]: crate::packet::Key
// Deriving Hash here is okay: PartialEq is manually implemented to
// ensure that secrets are compared in constant-time.
#[non_exhaustive]
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Hash)]
pub enum SecretKeyMaterial {
    /// RSA secret key.
    RSA {
        /// Secret exponent, inverse of e in Phi(N).
        d: ProtectedMPI,
        /// Smaller secret prime.
        p: ProtectedMPI,
        /// Larger secret prime.
        q: ProtectedMPI,
        /// Inverse of p mod q.
        u: ProtectedMPI,
    },

    /// NIST DSA secret key.
    DSA {
        /// Secret key log_g(y) in Zp.
        x: ProtectedMPI,
    },

    /// ElGamal secret key.
    ElGamal {
        /// Secret key log_g(y) in Zp.
        x: ProtectedMPI,
    },

    /// DJB's "Twisted" Edwards curve DSA secret key.
    EdDSA {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// NIST's Elliptic Curve DSA secret key.
    ECDSA {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// Elliptic Curve Diffie-Hellman secret key.
    ECDH {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// X25519 secret key.
    X25519 {
        /// The secret key, an opaque string.
        x: Protected,
    },

    /// X448 secret key.
    X448 {
        /// The secret key, an opaque string.
        x: Protected,
    },

    /// Ed25519 secret key.
    Ed25519 {
        /// The secret key, an opaque string.
        x: Protected,
    },

    /// Ed448 secret key.
    Ed448 {
        /// The secret key, an opaque string.
        x: Protected,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[ProtectedMPI]>,
        /// Any data that failed to parse.
        rest: Protected,
    },
}
assert_send_and_sync!(SecretKeyMaterial);

impl fmt::Debug for SecretKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            match self {
                SecretKeyMaterial::RSA { d, p, q, u } =>
                    f.debug_struct("RSA")
                    .field("d", d)
                    .field("p", p)
                    .field("q", q)
                    .field("u", u)
                    .finish(),

                SecretKeyMaterial::DSA { x } =>
                    f.debug_struct("DSA")
                    .field("x", x)
                    .finish(),

                SecretKeyMaterial::ElGamal { x } =>
                    f.debug_struct("ElGamal")
                    .field("x", x)
                    .finish(),

                SecretKeyMaterial::EdDSA { scalar } =>
                    f.debug_struct("EdDSA")
                    .field("scalar", scalar)
                    .finish(),

                SecretKeyMaterial::ECDSA { scalar } =>
                    f.debug_struct("ECDSA")
                    .field("scalar", scalar)
                    .finish(),

                SecretKeyMaterial::ECDH { scalar } =>
                    f.debug_struct("ECDH")
                    .field("scalar", scalar)
                    .finish(),

                SecretKeyMaterial::X25519 { x } =>
                    f.debug_struct("X25519")
                    .field("x", &hex::encode(x))
                    .finish(),

                SecretKeyMaterial::X448 { x } =>
                    f.debug_struct("X448")
                    .field("x", &hex::encode(x))
                    .finish(),

                SecretKeyMaterial::Ed25519 { x } =>
                    f.debug_struct("Ed25519")
                    .field("x", &hex::encode(x))
                    .finish(),

                SecretKeyMaterial::Ed448 { x } =>
                    f.debug_struct("Ed448")
                    .field("x", &hex::encode(x))
                    .finish(),

                SecretKeyMaterial::Unknown{ mpis, rest } =>
                    f.debug_struct("Unknown")
                    .field("mpis", mpis)
                    .field("rest", &hex::encode(rest))
                    .finish(),
            }
        } else {
            match self {
                SecretKeyMaterial::RSA{ .. } =>
                    f.write_str("RSA { <Redacted> }"),
                SecretKeyMaterial::DSA{ .. } =>
                    f.write_str("DSA { <Redacted> }"),
                SecretKeyMaterial::ElGamal{ .. } =>
                    f.write_str("ElGamal { <Redacted> }"),
                SecretKeyMaterial::EdDSA{ .. } =>
                    f.write_str("EdDSA { <Redacted> }"),
                SecretKeyMaterial::ECDSA{ .. } =>
                    f.write_str("ECDSA { <Redacted> }"),
                SecretKeyMaterial::ECDH{ .. } =>
                    f.write_str("ECDH { <Redacted> }"),
                SecretKeyMaterial::X25519 { .. } =>
                    f.write_str("X25519 { <Redacted> }"),
                SecretKeyMaterial::X448 { .. } =>
                    f.write_str("X448 { <Redacted> }"),
                SecretKeyMaterial::Ed25519 { .. } =>
                    f.write_str("Ed25519 { <Redacted> }"),
                SecretKeyMaterial::Ed448 { .. } =>
                    f.write_str("Ed448 { <Redacted> }"),
                SecretKeyMaterial::Unknown{ .. } =>
                    f.write_str("Unknown { <Redacted> }"),
            }
        }
    }
}

impl PartialOrd for SecretKeyMaterial {
    fn partial_cmp(&self, other: &SecretKeyMaterial) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecretKeyMaterial {
    fn cmp(&self, other: &Self) -> Ordering {
        use std::iter;

        fn discriminant(sk: &SecretKeyMaterial) -> usize {
            match sk {
                SecretKeyMaterial::RSA{ .. } => 0,
                SecretKeyMaterial::DSA{ .. } => 1,
                SecretKeyMaterial::ElGamal{ .. } => 2,
                SecretKeyMaterial::EdDSA{ .. } => 3,
                SecretKeyMaterial::ECDSA{ .. } => 4,
                SecretKeyMaterial::ECDH{ .. } => 5,
                SecretKeyMaterial::X25519 { .. } => 6,
                SecretKeyMaterial::X448 { .. } => 7,
                SecretKeyMaterial::Ed25519 { .. } => 8,
                SecretKeyMaterial::Ed448 { .. } => 9,
                SecretKeyMaterial::Unknown { .. } => 10,
            }
        }

        let ret = match (self, other) {
            (&SecretKeyMaterial::RSA{ d: ref d1, p: ref p1, q: ref q1, u: ref u1 }
            ,&SecretKeyMaterial::RSA{ d: ref d2, p: ref p2, q: ref q2, u: ref u2 }) => {
                let o1 = d1.cmp(d2);
                let o2 = p1.cmp(p2);
                let o3 = q1.cmp(q2);
                let o4 = u1.cmp(u2);

                if o1 != Ordering::Equal { return o1; }
                if o2 != Ordering::Equal { return o2; }
                if o3 != Ordering::Equal { return o3; }
                o4
            }
            (&SecretKeyMaterial::DSA{ x: ref x1 }
            ,&SecretKeyMaterial::DSA{ x: ref x2 }) => {
                x1.cmp(x2)
            }
            (&SecretKeyMaterial::ElGamal{ x: ref x1 }
            ,&SecretKeyMaterial::ElGamal{ x: ref x2 }) => {
                x1.cmp(x2)
            }
            (&SecretKeyMaterial::EdDSA{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::EdDSA{ scalar: ref scalar2 }) => {
                scalar1.cmp(scalar2)
            }
            (&SecretKeyMaterial::ECDSA{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::ECDSA{ scalar: ref scalar2 }) => {
                scalar1.cmp(scalar2)
            }
            (&SecretKeyMaterial::ECDH{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::ECDH{ scalar: ref scalar2 }) => {
                scalar1.cmp(scalar2)
            }
            (SecretKeyMaterial::X25519 { x: x0 },
             SecretKeyMaterial::X25519 { x: x1 }) => x0.cmp(x1),
            (SecretKeyMaterial::X448 { x: x0 },
             SecretKeyMaterial::X448 { x: x1 }) => x0.cmp(x1),
            (SecretKeyMaterial::Ed25519 { x: x0 },
             SecretKeyMaterial::Ed25519 { x: x1 }) => x0.cmp(x1),
            (SecretKeyMaterial::Ed448 { x: x0 },
             SecretKeyMaterial::Ed448 { x: x1 }) => x0.cmp(x1),

            (&SecretKeyMaterial::Unknown{ mpis: ref mpis1, rest: ref rest1 }
            ,&SecretKeyMaterial::Unknown{ mpis: ref mpis2, rest: ref rest2 }) => {
                let o1 = secure_cmp(rest1, rest2);
                let o2 = mpis1.len().cmp(&mpis2.len());
                let on = mpis1.iter().zip(mpis2.iter()).map(|(a,b)| {
                    a.cmp(b)
                }).collect::<Vec<_>>();

                iter::once(o1)
                    .chain(iter::once(o2))
                    .chain(on.iter().cloned())
                    .fold(Ordering::Equal, |acc, x| acc.then(x))
            }

            (a, b) => {
                let ret = discriminant(a).cmp(&discriminant(b));

                assert!(ret != Ordering::Equal);
                ret
            }
        };

        ret
    }
}

impl PartialEq for SecretKeyMaterial {
    fn eq(&self, other: &Self) -> bool { self.cmp(other) == Ordering::Equal }
}

impl Eq for SecretKeyMaterial {}

impl SecretKeyMaterial {
    /// Returns, if known, the public-key algorithm for this secret
    /// key.
    pub fn algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::SecretKeyMaterial::*;
        #[allow(deprecated)]
        match self {
            RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            DSA { .. } => Some(PublicKeyAlgorithm::DSA),
            ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            EdDSA { .. } => Some(PublicKeyAlgorithm::EdDSA),
            ECDSA { .. } => Some(PublicKeyAlgorithm::ECDSA),
            ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            X25519 { .. } => Some(PublicKeyAlgorithm::X25519),
            X448 { .. } => Some(PublicKeyAlgorithm::X448),
            Ed25519 { .. } => Some(PublicKeyAlgorithm::Ed25519),
            Ed448 { .. } => Some(PublicKeyAlgorithm::Ed448),
            Unknown { .. } => None,
        }
    }
}

impl Hash for SecretKeyMaterial {
    fn hash(&self, mut hash: &mut hash::Context) -> Result<()> {
        self.serialize(&mut hash as &mut dyn Write)
    }
}

#[cfg(test)]
impl SecretKeyMaterial {
    pub(crate) fn arbitrary_for(g: &mut Gen, pk: PublicKeyAlgorithm) -> Result<Self> {
        use self::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match pk {
            RSAEncryptSign | RSASign | RSAEncrypt => Ok(SecretKeyMaterial::RSA {
                d: ProtectedMPI::arbitrary(g),
                p: ProtectedMPI::arbitrary(g),
                q: ProtectedMPI::arbitrary(g),
                u: ProtectedMPI::arbitrary(g),
            }),

            DSA => Ok(SecretKeyMaterial::DSA {
                x: ProtectedMPI::arbitrary(g),
            }),

            ElGamalEncryptSign | ElGamalEncrypt => Ok(SecretKeyMaterial::ElGamal {
                x: ProtectedMPI::arbitrary(g),
            }),

            EdDSA => Ok(SecretKeyMaterial::EdDSA {
                scalar: ProtectedMPI::arbitrary(g),
            }),

            ECDSA => Ok(SecretKeyMaterial::ECDSA {
                scalar: ProtectedMPI::arbitrary(g),
            }),

            ECDH => Ok(SecretKeyMaterial::ECDH {
                scalar: ProtectedMPI::arbitrary(g),
            }),

            X25519 => Ok(SecretKeyMaterial::X25519 {
                x: arbitrarize(g, vec![0; 32]).into(),
            }),
            X448 => Ok(SecretKeyMaterial::X448 {
                x: arbitrarize(g, vec![0; 56]).into(),
            }),
            Ed25519 => Ok(SecretKeyMaterial::Ed25519 {
                x: arbitrarize(g, vec![0; 32]).into(),
            }),
            Ed448 => Ok(SecretKeyMaterial::Ed448 {
                x: arbitrarize(g, vec![0; 57]).into(),
            }),

            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(pk).into()),
        }
    }
}
#[cfg(test)]
impl Arbitrary for SecretKeyMaterial {
    fn arbitrary(g: &mut Gen) -> Self {
        let pk = *g.choose(
            &crate::crypto::types::public_key_algorithm::PUBLIC_KEY_ALGORITHM_VARIANTS)
            .expect("not empty");
        Self::arbitrary_for(g, pk).expect("only known variants")
    }
}

/// Checksum method for secret key material.
///
/// Secret key material may be protected by a checksum.  See [Section
/// 5.5.3 of RFC 9580] for details.
///
///   [Section 5.5.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum SecretKeyChecksum {
    /// SHA1 over the decrypted secret key.
    SHA1,

    /// Sum of the decrypted secret key octets modulo 65536.
    Sum16,
}
assert_send_and_sync!(SecretKeyChecksum);

impl Default for SecretKeyChecksum {
    fn default() -> Self {
        SecretKeyChecksum::SHA1
    }
}

impl SecretKeyChecksum {
    /// Returns the on-wire length of the checksum.
    pub(crate) fn len(&self) -> usize {
        match self {
            SecretKeyChecksum::SHA1 => 20,
            SecretKeyChecksum::Sum16 => 2,
        }
    }
}

/// An encrypted session key.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// [`PKESK`] packets.
///
///   [`PKESK`]: crate::packet::PKESK
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ciphertext {
    /// RSA ciphertext.
    RSA {
        ///  m^e mod N.
        c: MPI,
    },

    /// ElGamal ciphertext.
    ElGamal {
        /// Ephemeral key.
        e: MPI,
        /// Ciphertext.
        c: MPI,
    },

    /// Elliptic curve ElGamal public key.
    ECDH {
        /// Ephemeral key.
        e: MPI,
        /// Symmetrically encrypted session key.
        key: Box<[u8]>,
    },

    /// X25519 ciphertext.
    X25519 {
        /// Ephermeral key.
        e: Box<[u8; 32]>,
        /// Symmetrically encrypted session key.
        key: Box<[u8]>,
    },

    /// X448 ciphertext.
    X448 {
        /// Ephermeral key.
        e: Box<[u8; 56]>,
        /// Symmetrically encrypted session key.
        key: Box<[u8]>,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}
assert_send_and_sync!(Ciphertext);

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Ciphertext::RSA { c } =>
                f.debug_struct("RSA")
                .field("c", c)
                .finish(),

            Ciphertext::ElGamal { e, c } =>
                f.debug_struct("ElGamal")
                .field("e", e)
                .field("c", c)
                .finish(),

            Ciphertext::ECDH { e, key } =>
                f.debug_struct("ECDH")
                .field("e", e)
                .field("key", &hex::encode(key))
                .finish(),

            Ciphertext::X25519 { e, key } =>
                f.debug_struct("X25519")
                .field("e", &hex::encode(&e[..]))
                .field("key", &hex::encode(key))
                .finish(),

            Ciphertext::X448 { e, key } =>
                f.debug_struct("X448")
                .field("e", &hex::encode(&e[..]))
                .field("key", &hex::encode(key))
                .finish(),

            Ciphertext::Unknown { mpis, rest } =>
                f.debug_struct("Unknown")
                .field("mpis", mpis)
                .field("rest", &hex::encode(rest))
                .finish(),
        }
    }
}

impl Ciphertext {
    /// Returns, if known, the public-key algorithm for this
    /// ciphertext.
    pub fn pk_algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::Ciphertext::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        #[allow(deprecated)]
        match self {
            RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            X25519 { .. } => Some(PublicKeyAlgorithm::X25519),
            X448 { .. } => Some(PublicKeyAlgorithm::X448),
            Unknown { .. } => None,
        }
    }
}

impl Hash for Ciphertext {
    fn hash(&self, mut hash: &mut hash::Context) -> Result<()> {
        self.serialize(&mut hash as &mut dyn Write)
    }
}

#[cfg(test)]
impl Arbitrary for Ciphertext {
    fn arbitrary(g: &mut Gen) -> Self {
        use crate::arbitrary_helper::gen_arbitrary_from_range;

        match gen_arbitrary_from_range(0..5, g) {
            0 => Ciphertext::RSA {
                c: MPI::arbitrary(g),
            },

            1 => Ciphertext::ElGamal {
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            2 => Ciphertext::ECDH {
                e: MPI::arbitrary(g),
                key: {
                    let mut k = <Vec<u8>>::arbitrary(g);
                    k.truncate(255);
                    k.into_boxed_slice()
                },
            },

            3 => Ciphertext::X25519 {
                e: Box::new(arbitrary(g)),
                key: {
                    let mut k = <Vec<u8>>::arbitrary(g);
                    k.truncate(255);
                    k.into_boxed_slice()
                },
            },

            4 => Ciphertext::X448 {
                e: Box::new(arbitrarize(g, [0; 56])),
                key: {
                    let mut k = <Vec<u8>>::arbitrary(g);
                    k.truncate(255);
                    k.into_boxed_slice()
                },
            },
            _ => unreachable!(),
        }
    }
}

/// A cryptographic signature.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// [`Signature`] packets.
///
///   [`Signature`]: crate::packet::Signature
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Signature {
    /// RSA signature.
    RSA {
        /// Signature m^d mod N.
        s: MPI,
    },

    /// NIST's DSA signature.
    DSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// ElGamal signature.
    ElGamal {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// DJB's "Twisted" Edwards curve DSA signature.
    EdDSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// NIST's Elliptic curve DSA signature.
    ECDSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// Ed25519 signature.
    Ed25519 {
        /// The signature.
        s: Box<[u8; 64]>,
    },

    /// Ed448 signature.
    Ed448 {
        /// The signature.
        s: Box<[u8; 114]>,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}
assert_send_and_sync!(Signature);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Signature::RSA { s } =>
                f.debug_struct("RSA")
                .field("s", s)
                .finish(),

            Signature::DSA { r, s } =>
                f.debug_struct("DSA")
                .field("r", r)
                .field("s", s)
                .finish(),

            Signature::ElGamal { r, s } =>
                f.debug_struct("ElGamal")
                .field("r", r)
                .field("s", s)
                .finish(),

            Signature::EdDSA { r, s } =>
                f.debug_struct("EdDSA")
                .field("r", r)
                .field("s", s)
                .finish(),

            Signature::ECDSA { r, s } =>
                f.debug_struct("ECDSA")
                .field("r", r)
                .field("s", s)
                .finish(),

            Signature::Ed25519 { s } =>
                f.debug_struct("Ed25519")
                .field("s", &hex::encode(&s[..]))
                .finish(),

            Signature::Ed448 { s } =>
                f.debug_struct("Ed448")
                .field("s", &hex::encode(&s[..]))
                .finish(),

            Signature::Unknown { mpis, rest } =>
                f.debug_struct("Unknown")
                .field("mpis", mpis)
                .field("rest", &hex::encode(rest))
                .finish(),
        }
    }
}

impl Hash for Signature {
    fn hash(&self, mut hash: &mut hash::Context) -> Result<()> {
        self.serialize(&mut hash as &mut dyn Write)
    }
}

#[cfg(test)]
impl Arbitrary for Signature {
    fn arbitrary(g: &mut Gen) -> Self {
        use crate::arbitrary_helper::gen_arbitrary_from_range;

        match gen_arbitrary_from_range(0..6, g) {
            0 => Signature::RSA  {
                s: MPI::arbitrary(g),
            },

            1 => Signature::DSA {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            2 => Signature::EdDSA  {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            3 => Signature::ECDSA  {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            4 => Signature::Ed25519  {
                s: Box::new(arbitrarize(g, [0; 64])),
            },

            5 => Signature::Ed448  {
                s: Box::new(arbitrarize(g, [0; 114])),
            },

            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;

    quickcheck! {
        fn mpi_roundtrip(mpi: MPI) -> bool {
            let mut buf = Vec::new();
            mpi.serialize(&mut buf).unwrap();
            MPI::from_bytes(&buf).unwrap() == mpi
        }
    }

    quickcheck! {
        fn pk_roundtrip(pk: PublicKey) -> bool {
            use std::io::Cursor;

            let mut buf = Vec::new();
            pk.serialize(&mut buf).unwrap();
            let cur = Cursor::new(buf);
            let pk_ = PublicKey::parse(pk.algo().unwrap(), cur).unwrap();

            pk == pk_
        }
    }

    #[test]
    fn pk_bits() {
        for (name, key_no, bits) in &[
            ("testy.pgp", 0, 2048),
            ("testy-new.pgp", 1, 256),
            ("dennis-simon-anton.pgp", 0, 2048),
            ("dsa2048-elgamal3072.pgp", 1, 3072),
            ("emmelie-dorothea-dina-samantha-awina-ed25519.pgp", 0, 256),
            ("erika-corinna-daniela-simone-antonia-nistp256.pgp", 0, 256),
            ("erika-corinna-daniela-simone-antonia-nistp384.pgp", 0, 384),
            ("erika-corinna-daniela-simone-antonia-nistp521.pgp", 0, 521),
        ] {
            let cert = crate::Cert::from_bytes(crate::tests::key(name)).unwrap();
            let ka = cert.keys().nth(*key_no).unwrap();
            assert_eq!(ka.key().mpis().bits().unwrap(), *bits,
                       "Cert {}, key no {}", name, *key_no);
        }
    }

    quickcheck! {
        fn sk_roundtrip(sk: SecretKeyMaterial) -> bool {
            let mut buf = Vec::new();
            sk.serialize(&mut buf).unwrap();
            let sk_ =
                SecretKeyMaterial::from_bytes(sk.algo().unwrap(),
                                              &buf).unwrap();

            sk == sk_
        }
    }

    quickcheck! {
        fn ct_roundtrip(ct: Ciphertext) -> bool {
            use std::io::Cursor;

            let mut buf = Vec::new();
            ct.serialize(&mut buf).unwrap();
            let cur = Cursor::new(buf);
            let ct_ = Ciphertext::parse(ct.pk_algo().unwrap(), cur).unwrap();

            ct == ct_
        }
    }

    quickcheck! {
        fn signature_roundtrip(sig: Signature) -> bool {
            use std::io::Cursor;
            use crate::PublicKeyAlgorithm::*;

            let mut buf = Vec::new();
            sig.serialize(&mut buf).unwrap();
            let cur = Cursor::new(buf);

            #[allow(deprecated)]
            let sig_ = match &sig {
                Signature::RSA { .. } =>
                    Signature::parse(RSAEncryptSign, cur).unwrap(),
                Signature::DSA { .. } =>
                    Signature::parse(DSA, cur).unwrap(),
                Signature::ElGamal { .. } =>
                    Signature::parse(ElGamalEncryptSign, cur).unwrap(),
                Signature::EdDSA { .. } =>
                    Signature::parse(EdDSA, cur).unwrap(),
                Signature::ECDSA { .. } =>
                    Signature::parse(ECDSA, cur).unwrap(),
                Signature::Ed25519 { .. } =>
                    Signature::parse(Ed25519, cur).unwrap(),
                Signature::Ed448 { .. } =>
                    Signature::parse(Ed448, cur).unwrap(),

                Signature::Unknown { .. } => unreachable!(),
            };

            sig == sig_
        }
    }
}
