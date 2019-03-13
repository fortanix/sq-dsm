//! Multi Precision Integers.

use std::fmt;
use std::io::Write;
use std::cmp::Ordering;

use quickcheck::{Arbitrary, Gen};
use rand::Rng;

use constants::{
    Curve,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};
use crypto::Hash;
use serialize::Serialize;

use nettle;

/// Holds a single MPI.
#[derive(Clone, Hash)]
pub struct MPI {
    /// Length of the integer in bits.
    pub bits: usize,
    /// Integer value as big-endian.
    pub value: Box<[u8]>,
}

impl From<Vec<u8>> for MPI {
    fn from(v: Vec<u8>) -> Self {
        Self::new(&v)
    }
}

impl MPI {
    /// Creates a new MPI.
    ///
    /// This function takes care of leading zeros.
    pub fn new(value: &[u8]) -> Self {
        let mut leading_zeros = 0;
        for b in value {
            leading_zeros += b.leading_zeros() as usize;
            if *b != 0 {
                break;
            }
        }

        let offset = leading_zeros / 8;
        let value = Vec::from(&value[offset..]).into_boxed_slice();

        MPI {
            bits: value.len() * 8 - leading_zeros % 8,
            value: value,
        }
    }

    /// Creates new MPI for EC point.
    pub fn new_weierstrass(x: &[u8], y: &[u8], field_bits: usize) -> Self {
        let field_sz = if field_bits % 8 > 0 { 1 } else { 0 } + field_bits / 8;
        let mut val = vec![0x0u8; 1 + 2 * field_sz];
        let x_missing = field_sz - x.len();
        let y_missing = field_sz - y.len();

        val[0] = 0x4;
        val[1 + x_missing..1 + field_sz].copy_from_slice(x);
        val[1 + field_sz + y_missing..].copy_from_slice(y);

        MPI{
            value: val.into_boxed_slice(),
            bits: 3 + 16 * field_sz,
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: nettle::Hash>(&self, hash: &mut H) {
        let len = &[(self.bits >> 8) as u8 & 0xFF, self.bits as u8];

        hash.update(len);
        hash.update(&self.value);
    }

    fn secure_memzero(&mut self) {
        unsafe {
            ::memsec::memzero(self.value.as_mut_ptr(), self.value.len());
        }
    }

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
                "{} bits: {}", self.bits, ::conversions::to_hex(&*self.value, true)))
    }
}

impl Hash for MPI {
    /// Update the Hash with a hash of the MPIs.
    fn hash<H: nettle::Hash + Write>(&self, hash: &mut H) {
        let len = &[(self.bits >> 8) as u8 & 0xFF, self.bits as u8];

        hash.update(len);
        hash.update(&self.value);
    }
}

impl Arbitrary for MPI {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
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
        Some(self.secure_memcmp(other))
    }
}

impl Ord for MPI {
    fn cmp(&self, other: &MPI) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for MPI {
    fn eq(&self, other: &MPI) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MPI {}

/// Holds a public key.
///
/// Provides a typed and structured way of storing multiple MPIs (and
/// the occasional elliptic curve) in packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
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

    /// Elgamal public key.
    Elgamal {
        /// Prime of the ring Zp.
        p: MPI,
        /// Generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI,
    },

    /// DJBs "Twisted" Edwards curve DSA public key.
    EdDSA {
        /// Curve we're using. Must be curve 25519.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// NISTs Elliptic curve DSA public key.
    ECDSA {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// Elliptic curve Elgamal public key.
    ECDH {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
        /// Hash algorithm used for key derivation.
        hash: HashAlgorithm,
        /// Algorithm used w/the derived key.
        sym: SymmetricAlgorithm,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl PublicKey {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::PublicKey::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref e, ref n } =>
                2 + e.value.len() + 2 + n.value.len(),

            &DSA { ref p, ref q, ref g, ref y } =>
                2 + p.value.len() + 2 + q.value.len() +
                2 + g.value.len() + 2 + y.value.len(),

            &Elgamal { ref p, ref g, ref y } =>
                2 + p.value.len() +
                2 + g.value.len() + 2 + y.value.len(),

            &EdDSA { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),

            &ECDSA { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),

            &ECDH { ref curve, ref q, .. } =>
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len() +
                2 + q.value.len() +
                // one octet length, one reserved and two algorithm identifier.
                4,

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Returns the 'bits' of the public key.
    ///
    /// For finite field crypto this returns the size of the field we operate
    /// in, for ECC it returns `Curve::bits()`. This information is useless and
    /// should not be used to gauge the security of a particular key. This
    /// function exists only because some legacy PGP application
    /// like HKP need it.
    pub fn bits(&self) -> usize {
        use self::PublicKey::*;
        match self {
            &RSA { ref n,.. } => n.bits,
            &DSA { ref q,.. } => q.bits,
            &Elgamal { ref p,.. } => p.bits,
            &EdDSA { ref curve,.. } => curve.bits(),
            &ECDSA { ref curve,.. } => curve.bits(),
            &ECDH { ref curve,.. } => curve.bits(),
            &Unknown { .. } => 0,
        }
    }
}

impl Hash for PublicKey {
    /// Update the Hash with a hash of the MPIs.
    fn hash<H: nettle::Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for PublicKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use self::PublicKey::*;
        match g.gen_range(0, 6) {
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

            2 => Elgamal {
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

            _ => unreachable!(),
        }
    }
}

/// Holds a secret key.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, Hash)]
pub enum SecretKey {
    /// RSA secret key.
    RSA {
        /// Secret exponent, inverse of e in Phi(N).
        d: MPI,
        /// Larger secret prime.
        p: MPI,
        /// Smaller secret prime.
        q: MPI,
        /// Inverse of p mod q.
        u: MPI,
    },

    /// NIST DSA secret key.
    DSA {
        /// Secret key log_g(y) in Zp.
        x: MPI,
    },

    /// Elgamal secret key.
    Elgamal {
        /// Secret key log_g(y) in Zp.
        x: MPI,
    },

    /// DJBs "Twisted" Edwards curve DSA secret key.
    EdDSA {
        /// Secret scalar.
        scalar: MPI,
    },

    /// NISTs Elliptic curve DSA secret key.
    ECDSA {
        /// Secret scalar.
        scalar: MPI,
    },

    /// Elliptic curve Elgamal secret key.
    ECDH {
        /// Secret scalar.
        scalar: MPI,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            match self {
                &SecretKey::RSA{ ref d, ref p, ref q, ref u } =>
                    write!(f, "RSA {{ d: {:?}, p: {:?}, q: {:?}, u: {:?} }}", d, p, q, u),
                &SecretKey::DSA{ ref x } =>
                    write!(f, "DSA {{ x: {:?} }}", x),
                &SecretKey::Elgamal{ ref x } =>
                    write!(f, "Elgamal {{ x: {:?} }}", x),
                &SecretKey::EdDSA{ ref scalar } =>
                    write!(f, "EdDSA {{ scalar: {:?} }}", scalar),
                &SecretKey::ECDSA{ ref scalar } =>
                    write!(f, "ECDSA {{ scalar: {:?} }}", scalar),
                &SecretKey::ECDH{ ref scalar } =>
                    write!(f, "ECDH {{ scalar: {:?} }}", scalar),
                &SecretKey::Unknown{ ref mpis, ref rest } =>
                    write!(f, "Unknown {{ mips: {:?}, rest: {:?} }}", mpis, rest),
            }
        } else {
            match self {
                &SecretKey::RSA{ .. } =>
                    f.write_str("RSA { <Redacted> }"),
                &SecretKey::DSA{ .. } =>
                    f.write_str("DSA { <Redacted> }"),
                &SecretKey::Elgamal{ .. } =>
                    f.write_str("Elgamal { <Redacted> }"),
                &SecretKey::EdDSA{ .. } =>
                    f.write_str("EdDSA { <Redacted> }"),
                &SecretKey::ECDSA{ .. } =>
                    f.write_str("ECDSA { <Redacted> }"),
                &SecretKey::ECDH{ .. } =>
                    f.write_str("ECDH { <Redacted> }"),
                &SecretKey::Unknown{ .. } =>
                    f.write_str("Unknown { <Redacted> }"),
            }
        }
    }
}

fn secure_mpi_cmp(a: &MPI, b: &MPI) -> Ordering {
    let ord1 = a.bits.cmp(&b.bits);
    let ord2 = super::secure_cmp(&a.value, &b.value);

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}

impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &SecretKey) -> Option<Ordering> {
        use std::iter;

        fn discriminant(sk: &SecretKey) -> usize {
            match sk {
                &SecretKey::RSA{ .. } => 0,
                &SecretKey::DSA{ .. } => 1,
                &SecretKey::Elgamal{ .. } => 2,
                &SecretKey::EdDSA{ .. } => 3,
                &SecretKey::ECDSA{ .. } => 4,
                &SecretKey::ECDH{ .. } => 5,
                &SecretKey::Unknown{ .. } => 6,
            }
        }

        let ret = match (self, other) {
            (&SecretKey::RSA{ d: ref d1, p: ref p1, q: ref q1, u: ref u1 }
            ,&SecretKey::RSA{ d: ref d2, p: ref p2, q: ref q2, u: ref u2 }) => {
                let o1 = secure_mpi_cmp(d1, d2);
                let o2 = secure_mpi_cmp(p1, p2);
                let o3 = secure_mpi_cmp(q1, q2);
                let o4 = secure_mpi_cmp(u1, u2);

                if o1 != Ordering::Equal { return Some(o1); }
                if o2 != Ordering::Equal { return Some(o2); }
                if o3 != Ordering::Equal { return Some(o3); }
                o4
            }
            (&SecretKey::DSA{ x: ref x1 }
            ,&SecretKey::DSA{ x: ref x2 }) => {
                secure_mpi_cmp(x1, x2)
            }
            (&SecretKey::Elgamal{ x: ref x1 }
            ,&SecretKey::Elgamal{ x: ref x2 }) => {
                secure_mpi_cmp(x1, x2)
            }
            (&SecretKey::EdDSA{ scalar: ref scalar1 }
            ,&SecretKey::EdDSA{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKey::ECDSA{ scalar: ref scalar1 }
            ,&SecretKey::ECDSA{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKey::ECDH{ scalar: ref scalar1 }
            ,&SecretKey::ECDH{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKey::Unknown{ mpis: ref mpis1, rest: ref rest1 }
            ,&SecretKey::Unknown{ mpis: ref mpis2, rest: ref rest2 }) => {
                let o1 = super::secure_cmp(rest1, rest2);
                let on = mpis1.iter().zip(mpis2.iter()).map(|(a,b)| {
                    secure_mpi_cmp(a, b)
                }).collect::<Vec<_>>();

                iter::once(&o1)
                    .chain(on.iter())
                    .find(|&&x| x != Ordering::Equal)
                    .cloned()
                    .unwrap_or(Ordering::Equal)
            }

            (a, b) => {
                let ret = discriminant(a).cmp(&discriminant(b));

                assert!(ret != Ordering::Equal);
                ret
            }
        };

        Some(ret)
    }
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool { self.cmp(other) == Ordering::Equal }
}

impl Eq for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        use self::SecretKey::*;
        match self {
            RSA { ref mut d, ref mut p, ref mut q, ref mut u } => {
                d.secure_memzero();
                p.secure_memzero();
                q.secure_memzero();
                u.secure_memzero();
            },
            DSA { ref mut x } =>
                x.secure_memzero(),
            Elgamal { ref mut x } =>
                x.secure_memzero(),
            EdDSA { ref mut scalar } =>
                scalar.secure_memzero(),
            ECDSA { ref mut scalar } =>
                scalar.secure_memzero(),
            ECDH { ref mut scalar } =>
                scalar.secure_memzero(),
            Unknown { ref mut mpis, ref mut rest } => {
                mpis.iter_mut().for_each(|m| m.secure_memzero());
                unsafe {
                    ::memsec::memzero(rest.as_mut_ptr(), rest.len());
                }
            },
        }
    }
}

impl SecretKey {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::SecretKey::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref d, ref p, ref q, ref u } =>
                2 + d.value.len() + 2 + q.value.len() +
                2 + p.value.len() + 2 + u.value.len(),

            &DSA { ref x } => 2 + x.value.len(),

            &Elgamal { ref x } => 2 + x.value.len(),

            &EdDSA { ref scalar } => 2 + scalar.value.len(),

            &ECDSA { ref scalar } => 2 + scalar.value.len(),

            &ECDH { ref scalar } => 2 + scalar.value.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }
}

impl Hash for SecretKey {
    /// Update the Hash with a hash of the MPIs.
    fn hash<H: nettle::Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for SecretKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 6) {
            0 => SecretKey::RSA {
                d: MPI::arbitrary(g),
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                u: MPI::arbitrary(g),
            },

            1 => SecretKey::DSA {
                x: MPI::arbitrary(g),
            },

            2 => SecretKey::Elgamal {
                x: MPI::arbitrary(g),
            },

            3 => SecretKey::EdDSA {
                scalar: MPI::arbitrary(g),
            },

            4 => SecretKey::ECDSA {
                scalar: MPI::arbitrary(g),
            },

            5 => SecretKey::ECDH {
                scalar: MPI::arbitrary(g),
            },

            _ => unreachable!(),
        }
    }
}

/// Holds a ciphertext.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Ciphertext {
    /// RSA ciphertext.
    RSA {
        ///  m^e mod N.
        c: MPI,
    },

    /// Elgamal ciphertext
    Elgamal {
        /// Ephemeral key.
        e: MPI,
        /// .
        c: MPI,
    },

    /// Elliptic curve Elgamal public key.
    ECDH {
        /// Ephemeral key.
        e: MPI,
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

impl Ciphertext {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::Ciphertext::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref c } =>
                2 + c.value.len(),

            &Elgamal { ref e, ref c } =>
                2 + e.value.len() + 2 + c.value.len(),

            &ECDH { ref e, ref key } =>
                2 + e.value.len() +
                // one length octet plus ephemeral key
                1 + key.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Returns, if known, the public-key algorithm for this
    /// ciphertext.
    pub fn pk_algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::Ciphertext::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            &Elgamal { .. } => Some(PublicKeyAlgorithm::ElgamalEncrypt),
            &ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            &Unknown { .. } => None,
        }
    }
}

impl Hash for Ciphertext {
    /// Update the Hash with a hash of the MPIs.
    fn hash<H: nettle::Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for Ciphertext {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 3) {
            0 => Ciphertext::RSA {
                c: MPI::arbitrary(g),
            },

            1 => Ciphertext::Elgamal {
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            2 => Ciphertext::ECDH {
                e: MPI::arbitrary(g),
                key: <Vec<u8>>::arbitrary(g).into_boxed_slice()
            },
            _ => unreachable!(),
        }
    }
}

/// Holds a signature.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
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

    /// Elgamal signature.
    Elgamal {
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

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl Signature {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::Signature::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref s } =>
                2 + s.value.len(),

            &DSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &Elgamal { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &EdDSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ECDSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }
}

impl Hash for Signature {
    /// Update the Hash with a hash of the MPIs.
    fn hash<H: nettle::Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for Signature {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 4) {
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

            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::Parse;
    use serialize::Serialize;

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
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            pk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let pk_ = match &pk {
                PublicKey::RSA { .. } =>
                    PublicKey::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                PublicKey::DSA { .. } =>
                    PublicKey::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                PublicKey::Elgamal { .. } =>
                    PublicKey::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                PublicKey::EdDSA { .. } =>
                    PublicKey::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDSA { .. } =>
                    PublicKey::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDH { .. } =>
                    PublicKey::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),

                PublicKey::Unknown { .. } => unreachable!(),
            };

            pk == pk_
        }
    }

    quickcheck! {
        fn sk_roundtrip(sk: SecretKey) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sk_ = match &sk {
                SecretKey::RSA { .. } =>
                    SecretKey::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                SecretKey::DSA { .. } =>
                    SecretKey::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                SecretKey::EdDSA { .. } =>
                    SecretKey::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                SecretKey::ECDSA { .. } =>
                    SecretKey::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                SecretKey::ECDH { .. } =>
                    SecretKey::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),
                SecretKey::Elgamal { .. } =>
                    SecretKey::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),

                SecretKey::Unknown { .. } => unreachable!(),
            };

            sk == sk_
        }
    }

    quickcheck! {
        fn ct_roundtrip(ct: Ciphertext) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            ct.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let ct_ = match &ct {
                Ciphertext::RSA { .. } =>
                    Ciphertext::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Ciphertext::Elgamal { .. } =>
                    Ciphertext::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                Ciphertext::ECDH { .. } =>
                    Ciphertext::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),

                Ciphertext::Unknown { .. } => unreachable!(),
            };

            ct == ct_
        }
    }

    quickcheck! {
        fn signature_roundtrip(sig: Signature) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sig.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sig_ = match &sig {
                Signature::RSA { .. } =>
                    Signature::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Signature::DSA { .. } =>
                    Signature::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                Signature::Elgamal { .. } =>
                    Signature::parse_naked(
                        ElgamalEncryptSign, cur.into_inner()).unwrap(),
                Signature::EdDSA { .. } =>
                    Signature::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                Signature::ECDSA { .. } =>
                    Signature::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),

                Signature::Unknown { .. } => unreachable!(),
            };

            sig == sig_
        }
    }
}
