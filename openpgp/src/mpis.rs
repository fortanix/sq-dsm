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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
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
                "{} bits: {}", self.bits, ::to_hex(&*self.value, true)))
    }
}

/// Holds one or more MPIs.
///
/// Provides a typed and structured way of storing multiple MPIs (and
/// the occasional elliptic curve) in packets.
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum MPIs {
    /// Invalid, empty value.
    None,

    /// RSA public key.
    RSAPublicKey {
        /// Public exponent
        e: MPI,
        /// Public modulo N = pq.
        n: MPI
    },
    /// RSA secret key.
    RSASecretKey {
        /// Secret exponent, inverse of e in Phi(N).
        d: MPI,
        /// Larger secret prime.
        p: MPI,
        /// Smaller secret prime.
        q: MPI,
        /// Inverse of p mod q.
        u: MPI
    },
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

    /// NIST DSA public key.
    DSAPublicKey {
        /// Prime of the ring Zp.
        p: MPI,
        /// Order of `g` in Zp.
        q: MPI,
        /// Public generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI
    },
    /// NIST DSA secret key.
    DSASecretKey {
        /// Secret key log_g(y) in Zp.
        x: MPI
    },
    /// NIST DSA signature
    DSASignature {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// Elgamal public key.
    ElgamalPublicKey {
        /// Prime of the ring Zp.
        p: MPI,
        /// Generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI
    },
    /// Elgamal secret key.
    ElgamalSecretKey {
        /// Secret key log_g(y) in Zp.
        x: MPI
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

    /// DJBs "Twisted" Edwards curve DSA public key.
    EdDSAPublicKey {
        /// Curve we're using. Must be curve 25519.
        curve: Curve,
        /// Public point.
        q: MPI
    },
    /// DJBs "Twisted" Edwards curve DSA secret key.
    EdDSASecretKey {
        /// Secret scalar.
        scalar: MPI
    },
    /// DJBs "Twisted" Edwards curve DSA signature.
    EdDSASignature {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// NISTs Elliptic curve DSA public key.
    ECDSAPublicKey {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI
    },
    /// NISTs Elliptic curve DSA secret key.
    ECDSASecretKey {
        /// Secret scalar.
        scalar: MPI
    },
    /// NISTs Elliptic curve DSA signature.
    ECDSASignature{
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI
    },

    /// Elliptic curve Elgamal public key.
    ECDHPublicKey {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
        /// Hash algorithm used for key derivation.
        hash: HashAlgorithm,
        /// Algorithm used w/the derived key.
        sym: SymmetricAlgorithm
    },
    /// Elliptic curve Elgamal public key.
    ECDHSecretKey {
        /// Secret scalar.
        scalar: MPI
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

            &RSAPublicKey { ref e, ref n } =>
                2 + e.value.len() + 2 + n.value.len(),
            &RSASecretKey { ref d, ref p, ref q, ref u } =>
                2 + d.value.len() + 2 + q.value.len() +
                2 + p.value.len() + 2 + u.value.len(),
            &RSACiphertext { ref c } => 2 + c.value.len(),
            &RSASignature { ref s } => 2 + s.value.len(),

            &DSAPublicKey { ref p, ref q, ref g, ref y } =>
                2 + p.value.len() + 2 + q.value.len() +
                2 + g.value.len() + 2 + y.value.len(),
            &DSASecretKey { ref x } => 2 + x.value.len(),
            &DSASignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ElgamalPublicKey { ref p, ref g, ref y } =>
                2 + p.value.len() +
                2 + g.value.len() + 2 + y.value.len(),
            &ElgamalSecretKey { ref x } => 2 + x.value.len(),
            &ElgamalCiphertext { ref e, ref c } =>
                2 + e.value.len() + 2 + c.value.len(),
            &ElgamalSignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &EdDSAPublicKey { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),
            &EdDSASecretKey { ref scalar } => 2 + scalar.value.len(),
            &EdDSASignature { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ECDSAPublicKey { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),
            &ECDSASecretKey { ref scalar } => 2 + scalar.value.len(),
            &ECDSASignature { ref r, ref s } => 2 + r.value.len() + 2 + s.value.len(),

            &ECDHPublicKey { ref curve, ref q, .. } =>
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len() +
                2 + q.value.len() +
                // one octet length, one reserved and two algorithm identifier.
                4,
            &ECDHSecretKey { ref scalar } => 2 + scalar.value.len(),
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

            &RSAPublicKey { ref e, ref n } => {
                n.hash(hash);
                e.hash(hash);
            }

            &RSASecretKey { ref d, ref p, ref q, ref u } => {
                d.hash(hash);
                p.hash(hash);
                q.hash(hash);
                u.hash(hash);
            }

            &RSACiphertext { ref c } => {
                c.hash(hash);
            }

            &RSASignature { ref s } => {
                s.hash(hash);
            }

            &DSAPublicKey { ref p, ref q, ref g, ref y } => {
                p.hash(hash);
                q.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &DSASecretKey { ref x } => {
                x.hash(hash);
            }

            &DSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ElgamalPublicKey { ref p, ref g, ref y } => {
                p.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &ElgamalSecretKey { ref x } => {
                x.hash(hash);
            }

            &ElgamalCiphertext { ref e, ref c } => {
                e.hash(hash);
                c.hash(hash);
            }

            &ElgamalSignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &EdDSAPublicKey { ref curve, ref q } => {
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());
                q.hash(hash);
            }

            &EdDSASecretKey { ref scalar } => {
                scalar.hash(hash);
            }

            &EdDSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
             }

            &ECDSAPublicKey { ref curve, ref q } => {
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());
                q.hash(hash);
             }

            &ECDSASecretKey { ref scalar } => {
                scalar.hash(hash);
            }

            &ECDSASignature { ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ECDHPublicKey { ref curve, ref q, hash: h, sym } => {
                // curve
                hash.update(&[curve.oid().len() as u8]);
                hash.update(curve.oid());

                // point MPI
                q.hash(hash);

                // KDF
                hash.update(&[3u8, 1u8, u8::from(h), u8::from(sym)]);
             }

            &ECDHSecretKey { ref scalar } => {
                scalar.hash(hash);
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
        match g.gen_range(0, 19) {
           // None,

            0 => MPIs::RSAPublicKey {
                e: MPI::arbitrary(g),
                n: MPI::arbitrary(g)
            },
            1 => MPIs::RSASecretKey {
                d: MPI::arbitrary(g),
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                u: MPI::arbitrary(g)
            },
            2 => MPIs::RSACiphertext { c: MPI::arbitrary(g) },
            3 => MPIs::RSASignature { s: MPI::arbitrary(g) },

            4 => MPIs::DSAPublicKey {
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g)
            },
            5 => MPIs::DSASecretKey { x: MPI::arbitrary(g) },
            6 => MPIs::DSASignature{
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            7 => MPIs::ElgamalPublicKey {
                p: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g) },
            8 => MPIs::ElgamalSecretKey { x: MPI::arbitrary(g) },
            9 => MPIs::ElgamalCiphertext {
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            10 => MPIs::EdDSAPublicKey {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g)
            },
            11 => MPIs::EdDSASecretKey { scalar: MPI::arbitrary(g) },
            12 => MPIs::EdDSASignature {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            13 => MPIs::ECDSAPublicKey {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
            },
            14 => MPIs::ECDSASecretKey { scalar: MPI::arbitrary(g) },
            15 => MPIs::ECDSASignature {
                r: MPI::arbitrary(g), s: MPI::arbitrary(g)
            },

            16 => MPIs::ECDHPublicKey {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
                hash: HashAlgorithm::arbitrary(g),
                sym: SymmetricAlgorithm::arbitrary(g)
            },
            17 => MPIs::ECDHSecretKey { scalar: MPI::arbitrary(g) },
            18 => MPIs::ECDHCiphertext {
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
                MPIs::RSAPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSAPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        DSA, cur.into_inner()).unwrap(),
                MPIs::ElgamalPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                MPIs::EdDSAPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSAPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                MPIs::ECDHPublicKey { .. } =>
                    MPIs::parse_public_key_naked(
                        ECDH, cur.into_inner()).unwrap(),

                MPIs::RSASecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSASecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        DSA, cur.into_inner()).unwrap(),
                MPIs::EdDSASecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSASecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                MPIs::ECDHSecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        ECDH, cur.into_inner()).unwrap(),
                MPIs::ElgamalSecretKey { .. } =>
                    MPIs::parse_secret_key_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),

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
