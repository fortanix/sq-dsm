use std::fmt;
use quickcheck::{Arbitrary, Gen};

use constants::{
    SymmetricAlgorithm,
    HashAlgorithm,
};

use nettle::Hash;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MPI {
    pub bits: usize,
    pub value: Box<[u8]>,
}

impl MPI {
    // Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let len = &[(self.bits >> 8) as u8 & 0xFF, self.bits as u8];

        hash.update(len);
        hash.update(&self.value);
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
                "{} bits: {}",self.bits, ::to_hex(&*self.value, true)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum MPIs {
    // XXX
    None,

    RSAPublicKey{ e: MPI, n: MPI },
    RSASecretKey{ d: MPI, p: MPI, q: MPI, u: MPI },
    RSACiphertext{ c: MPI },
    RSASignature{ s: MPI },

    DSAPublicKey{ p: MPI, q: MPI, g: MPI, y: MPI },
    DSASecretKey{ x: MPI },
    DSASignature{ r: MPI, s: MPI },

    ElgamalPublicKey{ p: MPI, g: MPI, y: MPI },
    ElgamalSecretKey{ x: MPI },
    ElgamalCiphertext{ e: MPI, c: MPI },

    EdDSAPublicKey{ curve: Box<[u8]>, q: MPI },
    EdDSASecretKey{ scalar: MPI },
    EdDSASignature{ r: MPI, s: MPI },

    ECDSAPublicKey{ curve: Box<[u8]>, q: MPI },
    ECDSASecretKey{ scalar: MPI },
    ECDSASignature{ r: MPI, s: MPI },

    ECDHPublicKey{
        curve: Box<[u8]>, q: MPI,
        hash: HashAlgorithm, sym: SymmetricAlgorithm
    },
    ECDHSecretKey{ scalar: MPI },
    ECDHCiphertext{ e: MPI, key: Box<[u8]> },
}

impl MPIs {
    pub fn empty() -> Self {
        MPIs::None
    }

    pub fn serialized_len(&self) -> usize {
        use MPIs::*;

        // Fields are mostly MPIs that consist of two octets length plus the big endian value
        // itself. All other field types are commented.
        match self {
            &None => 0,

            &RSAPublicKey{ ref e, ref n } => 2 + e.value.len() + 2 + n.value.len(),
            &RSASecretKey{ ref d, ref p, ref q, ref u } =>
                2 + d.value.len() + 2 + q.value.len() +
                2 + p.value.len() + 2 + u.value.len(),
            &RSACiphertext{ ref c } => 2 + c.value.len(),
            &RSASignature{ ref s } => 2 + s.value.len(),

            &DSAPublicKey{ ref p, ref q, ref g, ref y } =>
                2 + p.value.len() + 2 + q.value.len() +
                2 + g.value.len() + 2 + y.value.len(),
            &DSASecretKey{ ref x } => 2 + x.value.len(),
            &DSASignature{ ref r, ref s } => 2 + r.value.len() + 2 + s.value.len(),

            &ElgamalPublicKey{ ref p, ref g, ref y } =>
                2 + p.value.len() +
                2 + g.value.len() + 2 + y.value.len(),
            &ElgamalSecretKey{ ref x } => 2 + x.value.len(),
            &ElgamalCiphertext{ ref e, ref c } => 2 + e.value.len() + 2 + c.value.len(),

            &EdDSAPublicKey{ ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.len(),
            &EdDSASecretKey{ ref scalar } => 2 + scalar.value.len(),
            &EdDSASignature{ ref r, ref s } => 2 + r.value.len() + 2 + s.value.len(),

            &ECDSAPublicKey{ ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.len(),
            &ECDSASecretKey{ ref scalar } => 2 + scalar.value.len(),
            &ECDSASignature{ ref r, ref s } => 2 + r.value.len() + 2 + s.value.len(),

            &ECDHPublicKey{ ref curve, ref q,.. } =>
                // one length octet plus the ASN.1 OID
                1 + curve.len() +
                2 + q.value.len() +
                // one octet length, one reserved and two algorithm identifier.
                4,
            &ECDHSecretKey{ ref scalar } => 2 + scalar.value.len(),
            &ECDHCiphertext{ ref e, ref key } =>
                2 + e.value.len() +
                // one length octet plus ephemeral key
                1 + key.len(),
        }
    }

    // Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        use MPIs::*;

        match self {
            &None => {}

            &RSAPublicKey{ ref e, ref n } => {
                n.hash(hash);
                e.hash(hash);
            }

            &RSASecretKey{ ref d, ref p, ref q, ref u } => {
                d.hash(hash);
                p.hash(hash);
                q.hash(hash);
                u.hash(hash);
            }

            &RSACiphertext{ ref c } => {
                c.hash(hash);
            }

            &RSASignature{ ref s } => {
                s.hash(hash);
            }

            &DSAPublicKey{ ref p, ref q, ref g, ref y } => {
                p.hash(hash);
                q.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &DSASecretKey{ ref x } => {
                x.hash(hash);
            }

            &DSASignature{ ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ElgamalPublicKey{ ref p, ref g, ref y } => {
                p.hash(hash);
                g.hash(hash);
                y.hash(hash);
            }

            &ElgamalSecretKey{ ref x } => {
                x.hash(hash);
            }

            &ElgamalCiphertext{ ref e, ref c } => {
                e.hash(hash);
                c.hash(hash);
            }

            &EdDSAPublicKey{ ref curve, ref q } => {
                hash.update(&[curve.len() as u8]);
                hash.update(&curve);
                q.hash(hash);
            }

            &EdDSASecretKey{ ref scalar } => {
                scalar.hash(hash);
            }

            &EdDSASignature{ ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
             }

            &ECDSAPublicKey{ ref curve, ref q } => {
                hash.update(&[curve.len() as u8]);
                hash.update(&curve);
                q.hash(hash);
             }

            &ECDSASecretKey{ ref scalar } => {
                scalar.hash(hash);
            }

            &ECDSASignature{ ref r, ref s } => {
                r.hash(hash);
                s.hash(hash);
            }

            &ECDHPublicKey{ ref curve, ref q, hash: h, sym } => {
                // curve
                hash.update(&[curve.len() as u8]);
                hash.update(&curve);

                // point MPI
                q.hash(hash);

                // KDF
                hash.update(&[3u8, 1u8, u8::from(h), u8::from(sym)]);
             }

            &ECDHSecretKey{ ref scalar } => {
                scalar.hash(hash);
            }

            &ECDHCiphertext{ ref e, ref key } => {
                e.hash(hash);

                // key
                hash.update(&[key.len() as u8]);
                hash.update(&key);
            }
        }
    }
}

impl Arbitrary for MPI {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use std::io::Cursor;

        loop {
            let mut buf = <Vec<u8>>::arbitrary(g);

            if !buf.is_empty() && buf[0] != 0 {
                let len = buf.len() * 8 - buf.first().unwrap_or(&0).leading_zeros() as usize;
                buf.insert(0, ((len >> 8) & 0xff) as u8);
                buf.insert(1, (len & 0xff) as u8);

                let mut cur = Cursor::new(buf);
                return MPI::parse_naked(&mut cur).unwrap();
            }
        }
    }
}

impl Arbitrary for MPIs {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 19) {
           // None,

            0 => MPIs::RSAPublicKey{
                e: MPI::arbitrary(g),
                n: MPI::arbitrary(g)
            },
            1 => MPIs::RSASecretKey{
                d: MPI::arbitrary(g),
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                u: MPI::arbitrary(g)
            },
            2 => MPIs::RSACiphertext{ c: MPI::arbitrary(g) },
            3 => MPIs::RSASignature{ s: MPI::arbitrary(g) },

            4 => MPIs::DSAPublicKey{
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g)
            },
            5 => MPIs::DSASecretKey{ x: MPI::arbitrary(g) },
            6 => MPIs::DSASignature{
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            7 => MPIs::ElgamalPublicKey{
                p: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g) },
            8 => MPIs::ElgamalSecretKey{ x: MPI::arbitrary(g) },
            9 => MPIs::ElgamalCiphertext{
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            10 => MPIs::EdDSAPublicKey{
                curve: <Vec<u8>>::arbitrary(g).into_boxed_slice(),
                q: MPI::arbitrary(g)
            },
            11 => MPIs::EdDSASecretKey{ scalar: MPI::arbitrary(g) },
            12 => MPIs::EdDSASignature{
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g)
            },

            13 => MPIs::ECDSAPublicKey{
                curve: <Vec<u8>>::arbitrary(g).into_boxed_slice(),
                q: MPI::arbitrary(g)
            },
            14 => MPIs::ECDSASecretKey{ scalar: MPI::arbitrary(g) },
            15 => MPIs::ECDSASignature{ r: MPI::arbitrary(g), s: MPI::arbitrary(g) },

            16 => MPIs::ECDHPublicKey{
                curve: <Vec<u8>>::arbitrary(g).into_boxed_slice(),
                q: MPI::arbitrary(g),
                hash: HashAlgorithm::arbitrary(g),
                sym: SymmetricAlgorithm::arbitrary(g)
            },
            17 => MPIs::ECDHSecretKey{ scalar: MPI::arbitrary(g) },
            18 => MPIs::ECDHCiphertext{
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
        fn round_trip(mpis: MPIs) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            mpis.serialize(&mut cur).unwrap();

            let mpis2 = match &mpis {
                MPIs::None => unreachable!(),
                MPIs::RSAPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSAPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(DSA, cur.into_inner()).unwrap(),
                MPIs::ElgamalPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(ElgamalEncrypt, cur.into_inner()).unwrap(),
                MPIs::EdDSAPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSAPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(ECDSA, cur.into_inner()).unwrap(),
                MPIs::ECDHPublicKey{ .. } =>
                    MPIs::parse_public_key_naked(ECDH, cur.into_inner()).unwrap(),

                MPIs::RSASecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSASecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(DSA, cur.into_inner()).unwrap(),
                MPIs::EdDSASecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSASecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(ECDSA, cur.into_inner()).unwrap(),
                MPIs::ECDHSecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(ECDH, cur.into_inner()).unwrap(),
                MPIs::ElgamalSecretKey{ .. } =>
                    MPIs::parse_secret_key_naked(ElgamalEncrypt, cur.into_inner()).unwrap(),

                MPIs::RSASignature{ .. } =>
                    MPIs::parse_signature_naked(RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::DSASignature{ .. } =>
                    MPIs::parse_signature_naked(DSA, cur.into_inner()).unwrap(),
                MPIs::EdDSASignature{ .. } =>
                    MPIs::parse_signature_naked(EdDSA, cur.into_inner()).unwrap(),
                MPIs::ECDSASignature{ .. } =>
                    MPIs::parse_signature_naked(ECDSA, cur.into_inner()).unwrap(),

                MPIs::RSACiphertext{ .. } =>
                    MPIs::parse_ciphertext_naked(RSAEncryptSign, cur.into_inner()).unwrap(),
                MPIs::ElgamalCiphertext{ .. } =>
                    MPIs::parse_ciphertext_naked(ElgamalEncrypt, cur.into_inner()).unwrap(),
                MPIs::ECDHCiphertext{ .. } =>
                    MPIs::parse_ciphertext_naked(ECDH, cur.into_inner()).unwrap(),
            };

            mpis == mpis2
        }
    }
}
