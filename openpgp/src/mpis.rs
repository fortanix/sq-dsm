//! Multi Precision Integers.

use std::fmt;
use quickcheck::{Arbitrary, Gen};

use constants::{
    SymmetricAlgorithm,
    HashAlgorithm,
    Curve,
};

use nettle::Hash;

/// Holds a single MPI.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MPI {
    /// Length of the integer in bits.
    pub bits: usize,
    /// Integer value as big-endian.
    pub value: Box<[u8]>,
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

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let len = &[(self.bits >> 8) as u8 & 0xFF, self.bits as u8];

        hash.update(len);
        hash.update(&self.value);
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
                "{} bits: {}", self.bits, ::conversions::to_hex(&*self.value, true)))
    }
}

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

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        use self::PublicKey::*;

        match self {
            &RSA { ref e, ref n } => {
                n.hash(hash);
                e.hash(hash);
            }

            &DSA { ref p, ref q, ref g, ref y } => {
                p.hash(hash);
                q.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &Elgamal { ref p, ref g, ref y } => {
                p.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &EdDSA { ref curve, ref q } => {
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());
                q.hash(hash);
            }

            &ECDSA { ref curve, ref q } => {
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());
                q.hash(hash);
            }

            &ECDH { ref curve, ref q, hash: h, sym } => {
                // curve
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());

                // point MPI
                q.hash(hash);

                // KDF
                hash.update(&[3u8, 1u8, u8::from(h), u8::from(sym)]);
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.hash(hash);
                }
                hash.update(rest);
            }
        }
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
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
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

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        use self::SecretKey::*;

        match self {
            &RSA { ref d, ref p, ref q, ref u } => {
                d.hash(hash);
                p.hash(hash);
                q.hash(hash);
                u.hash(hash);
            }

            &DSA { ref x } => {
                x.hash(hash);
            }

            &Elgamal { ref x } => {
                x.hash(hash);
            }

            &EdDSA { ref scalar } => {
                scalar.hash(hash);
            }

            &ECDSA { ref scalar } => {
                scalar.hash(hash);
            }

            &ECDH { ref scalar } => {
                scalar.hash(hash);
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.hash(hash);
                }
                hash.update(rest);
            }
        }
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

/// Holds one or more MPIs.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum MPIs {
    /// Invalid, empty value.
    None,

    /// RSA ciphertext.
    RSACiphertext {
        /// Ciphertext m^e mod N.
        c: MPI
    },
    /// RSA signature.
    RSASignature {
        /// Signature m^d mod N.
        s: MPI
    },

    /// NIST DSA signature
    DSASignature {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// Elgamal ciphertext
    ElgamalCiphertext {
        /// Ephemeral key.
        e: MPI,
        /// Ciphertext.
        c: MPI
    },
    /// Elgamal signature
    ElgamalSignature {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// DJBs "Twisted" Edwards curve DSA signature.
    EdDSASignature {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// NISTs Elliptic curve DSA signature.
    ECDSASignature{
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// Elliptic curve Elgamal public key.
    ECDHCiphertext {
        /// Ephemeral key.
        e: MPI,
        /// Symmetrically encrypted poition.
        key: Box<[u8]>
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl MPIs {
    /// Create a `None` MPIs instance.
    pub fn empty() -> Self {
        MPIs::None
    }

    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::MPIs::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &None => 0,

            &RSACiphertext { ref c } => 2 + c.value.len(),
            &RSASignature { ref s } => 2 + s.value.len(),

            &DSASignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ElgamalCiphertext { ref e, ref c } =>
                2 + e.value.len() + 2 + c.value.len(),
            &ElgamalSignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &EdDSASignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ECDSASignature { ref r, ref s } => 2 + r.value.len() + 2 + s.value.len(),

            &ECDHCiphertext { ref e, ref key } =>
                2 + e.value.len() +
                // one length octet plus ephemeral key
                1 + key.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        use self::MPIs::*;

        match self {
            &None => {}

            &RSACiphertext { ref c } => {
                c.hash(hash);
            }

            &RSASignature { ref s } => {
                s.hash(hash);
            }

            &DSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ElgamalCiphertext { ref e, ref c } => {
                e.hash(hash);
                c.hash(hash);
            }

            &ElgamalSignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &EdDSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
             }

            &ECDSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ECDHCiphertext { ref e, ref key } => {
                e.hash(hash);

                // key
                hash.update(&[key.len() as u8]);
                hash.update(&key);
            }

            &Unknown { ref mpis, ref rest } => {
                for mpi in mpis.iter() {
                    mpi.hash(hash);
                }
                hash.update(rest);
            }
        }
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

impl Arbitrary for MPIs {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 7) {
           // None,

            0 => MPIs::RSACiphertext { c: MPI::arbitrary(g) },
            1 => MPIs::RSASignature { s: MPI::arbitrary(g) },

            2 => MPIs::DSASignature{
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            3 => MPIs::ElgamalCiphertext {
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            4 => MPIs::EdDSASignature {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            5 => MPIs::ECDSASignature {
                r: MPI::arbitrary(g), s: MPI::arbitrary(g)
            },

            6 => MPIs::ECDHCiphertext {
                e: MPI::arbitrary(g),
                key: <Vec<u8>>::arbitrary(g).into_boxed_slice()
            },
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn mpi_roundtrip(mpi: MPI) -> bool {
            use std::io::Cursor;
            use serialize::Serialize;

            let mut buf = Vec::new();
            mpi.serialize(&mut buf).unwrap();
            MPI::parse_naked(Cursor::new(buf)).unwrap() == mpi
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
        fn round_trip(mpis: MPIs) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            mpis.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let mpis2 = match &mpis {
                MPIs::None => unreachable!(),

                MPIs::RSASignature { .. } =>
                    MPIs::parse_signature_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSASignature { .. } =>
                    MPIs::parse_signature_naked(
                        DSA, cur.into_inner()).unwrap(),
                MPIs::ElgamalSignature { .. } =>
                    MPIs::parse_signature_naked(
                        ElgamalEncryptSign, cur.into_inner()).unwrap(),
                MPIs::EdDSASignature { .. } =>
                    MPIs::parse_signature_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSASignature { .. } =>
                    MPIs::parse_signature_naked(
                        ECDSA, cur.into_inner()).unwrap(),

                MPIs::RSACiphertext { .. } =>
                    MPIs::parse_ciphertext_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::ElgamalCiphertext { .. } =>
                    MPIs::parse_ciphertext_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                MPIs::ECDHCiphertext { .. } =>
                    MPIs::parse_ciphertext_naked(ECDH, cur.into_inner()).unwrap(),

                MPIs::Unknown { .. } => unreachable!(),
            };

            mpis == mpis2
        }
    }
}
