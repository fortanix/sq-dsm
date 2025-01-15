//! DER conversions of cryptographic material
//!
//! SUBJECT PUBLIC KEY INFO (See e.g. RFC3280)
//!
//! SubjectPublicKeyInfo  ::=  SEQUENCE  {
//!   algorithm         AlgorithmIdentifier,
//!   subjectPublicKey  BIT STRING
//! }

use super::{Result, SequoiaCurve as Curve};

pub mod parse {
    use std::convert::TryFrom;
    use spki::{ObjectIdentifier as Oid, SubjectPublicKeyInfo as Spki};

    const RSA_OID:    Oid = Oid::new("1.2.840.113549.1.1.1");
    const NIST_P_OID: Oid = Oid::new("1.2.840.10045.2.1");

    pub struct RsaPub {
        pub n: Vec<u8>,
        pub e: Vec<u8>,
    }

    pub struct RsaPriv {
        pub e: Vec<u8>,
        pub d: Vec<u8>,
        pub p: Vec<u8>,
        pub q: Vec<u8>,
    }

    pub fn rsa_n_e(buf: &[u8]) -> super::Result<RsaPub> {
        let pk = Spki::try_from(buf).unwrap();
        if pk.algorithm.oid != RSA_OID {
            return Err(anyhow::anyhow!("bad OID when parsing RSA key"));
        }
        // RFC3279 Sec. 2.3
        //
        // RSAPublicKey ::= SEQUENCE {
        //   modulus         INTEGER, -- n
        //   publicExponent  INTEGER  -- e
        // }
        //
        yasna::parse_der(pk.subject_public_key, |reader| {
            reader.read_sequence(|reader| {
                let n = reader.next().read_biguint()?.to_bytes_be();
                let e = reader.next().read_u32()?.to_be_bytes().to_vec();
                Ok(RsaPub { n, e })
            })
        })
        .map_err(|e| anyhow::anyhow!("ASN1 error: {:?}", e))
    }

    pub fn rsa_private_edpq(buf: &[u8]) -> super::Result<RsaPriv> {
        // RFC2437 Sec. 11.1.2
        //
        // RSAPrivateKey ::= SEQUENCE {
        //   version Version,
        //   modulus INTEGER, -- n
        //   publicExponent INTEGER, -- e
        //   privateExponent INTEGER, -- d
        //   prime1 INTEGER, -- p
        //   prime2 INTEGER, -- q
        //   exponent1 INTEGER, -- d mod (p-1)
        //   exponent2 INTEGER, -- d mod (q-1)
        //   coefficient INTEGER -- (inverse of q) mod p
        // }
        //
        yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let _version = reader.next().read_u32()?;
                let _n = reader.next().read_biguint()?;
                let e = reader.next().read_biguint()?.to_bytes_be();
                let d = reader.next().read_biguint()?.to_bytes_be();
                let p = reader.next().read_biguint()?.to_bytes_be();
                let q = reader.next().read_biguint()?.to_bytes_be();
                let _exp1 = reader.next().read_biguint()?;
                let _exp2 = reader.next().read_biguint()?;
                let _u = reader.next().read_biguint()?;

                Ok(RsaPriv { e, d, p, q })
            })
        }).map_err(|e| anyhow::anyhow!("ASN1 error: {:?}", e))
    }

    pub fn ec_point_x_y(buf: &[u8]) -> super::Result<(Vec<u8>, Vec<u8>)> {
        let pk = Spki::try_from(buf).unwrap();
        if pk.algorithm.oid != NIST_P_OID {
            return Err(anyhow::anyhow!("bad OID when parsing EC key"));
        }

        // RFC5480 Sec 2.2
        //
        // ECPoint ::= OCTET STRING

        let octet_string = pk.subject_public_key;
        let length = octet_string.len();
        if length < 3 {
            return Err(anyhow::anyhow!("bad EC point, or infinity"));
        }

        //
        // Standards for Elliptic-Curve Cryptography
        // https://www.secg.org/sec1-v2.pdf
        //

        let (w, x, y) = (
            octet_string[0],
            octet_string[1..(length + 1) / 2].to_vec(),
            octet_string[(length + 1) / 2..].to_vec(),
        );
        if w != 0x04 {
            return Err(anyhow::anyhow!("compressed EC point not supported"));
        }

        Ok((x, y))
    }

    pub fn ecdsa_r_s(buf: &[u8]) -> super::Result<(Vec<u8>, Vec<u8>)> {
        yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let r = reader.next().read_biguint()?.to_bytes_be();
                let s = reader.next().read_biguint()?.to_bytes_be();
                Ok((r, s))
            })
        }).map_err(|e| anyhow::anyhow!("ASN1 error: {:?}", e))
    }

    pub fn ec_priv_scalar(buf: &[u8]) -> super::Result<Vec<u8>> {
        yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let _version = reader.next().read_u32()?;
                let priv_key = reader.next().read_bytes()?;
                let _oid = reader.next().read_tagged_der()?;
                let _pk = reader.next().read_tagged_der()?;
                Ok(priv_key)
            })
        }).map_err(|e| anyhow::anyhow!("ASN1 error: {:?}", e))
    }
}

pub mod serialize {
    use super::*;

    use bit_vec::BitVec;
    use yasna::models::ObjectIdentifier as Oid;

    use sequoia_openpgp::crypto::mpi;
    use num::bigint::BigUint;

    pub fn rsa_private(
        n: &mpi::MPI,
        e: &mpi::MPI,
        d: &mpi::ProtectedMPI,
        p: &mpi::ProtectedMPI,
        q: &mpi::ProtectedMPI,
        u: &mpi::ProtectedMPI,
    ) -> Vec<u8> {
        let (n, e, d, p, q, u) = (
            BigUint::from_bytes_be(n.value()),
            BigUint::from_bytes_be(e.value()),
            BigUint::from_bytes_be(d.value()),
            BigUint::from_bytes_be(p.value()),
            BigUint::from_bytes_be(q.value()),
            BigUint::from_bytes_be(u.value()),
        );

        //
        // Note that `u` is defined in RFC4880bis 5.6.1 as p⁻¹ (mod q),
        // whereas RFC8017 A.1.2 defines the CRT coefficient as q⁻¹ (mod p).
        // We can conciliate both views noting that we know `u` such that
        //
        //                      up + qk = 1
        //                  k = - (up - 1)/q (mod p)
        //                  k = p - ((up - 1)/q (mod p))
        //
        let minus_k = ((u * p.clone() - 1u32) / q.clone()) % p.clone();
        let coeff = (p.clone() - minus_k) % p.clone();  // always well-defined
        let e1 = d.clone() % (p.clone() - 1u32);
        let e2 = d.clone() % (q.clone() - 1u32);
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u32(0);
                for mpi in [&n, &e, &d, &p, &q, &e1, &e2, &coeff] {
                    w.next().write_biguint(mpi);
                }
            })
        })
    }

    pub fn ec_private_25519(curve: &Curve, x: Vec<u8>) -> Result<Vec<u8>> {
        let opaque_octet_string = yasna::construct_der(|w| {
            w.write_bytes(&x);
        });

        let oid = curve_oid(curve)?;

        // RFC8410
        Ok(yasna::construct_der(|w|{
            w.write_sequence(|w| {
                w.next().write_u32(0);
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid);
                });
                w.next().write_bytes(&opaque_octet_string);
            });
        }))
    }

    pub fn ec_private(
        curve: &Curve,
        scalar: &mpi::ProtectedMPI,
    ) -> Result<Vec<u8>> {
        let mut d = scalar.value().to_vec();
        // For X25519, x is LITTLE ENDIAN!
        if curve == &Curve::Cv25519 {
            d.reverse();
            return ec_private_25519(curve, d);
        }
        if curve == &Curve::Ed25519 {
            return ec_private_25519(curve, d);
        }

        let oid = curve_oid(curve)?;

        // RFC5915
        Ok(yasna::construct_der(|w|{
            w.write_sequence(|w| {
                w.next().write_u32(1);
                w.next().write_bytes(&d);
                w.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_oid(&oid);
                });
                // We ignore the public key serialization
            });
        }))
    }

    pub fn spki_rsa(n: &mpi::MPI, e: &mpi::MPI) -> Vec<u8> {
        let rsa_oid = Oid::from_slice(&[1, 2, 840, 113549, 1, 1, 1]);

        // RSA public key
        let rsa_public_key = yasna::construct_der(|der_writer| {
            der_writer.write_sequence_of(|w| {
                w.next()
                    .write_biguint(&BigUint::from_bytes_be(n.value()));
                w.next()
                    .write_biguint(&BigUint::from_bytes_be(e.value()));
            });
        });

        // Construct the SPKI structure
        yasna::construct_der(|der_writer| {
            der_writer.write_sequence_of(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&rsa_oid);
                    w.next().write_null();
                });
                w.next().write_bitvec(&BitVec::from_bytes(&rsa_public_key));
            });
        })
    }

    pub fn spki_ec(curve: &Curve, e: &mpi::MPI) -> Vec<u8> {
        match curve {
            Curve::Cv25519 | Curve::Ed25519 => {
                let x = e.value();
                assert!(!x.is_empty());

                let x = x[1..].to_vec();

                let oid = curve_oid(curve).expect("bad curve OID");
                yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid);
                        });
                        w.next().write_bitvec(&BitVec::from_bytes(&x))
                    });
                })
            }
            _ => {
                //
                // Note: DSM expects UNRESTRICTED ALGORITHM IDENTIFIER
                // AND PARAMETERS (RFC5480 sec. 2.1.1) for Nist curves
                //
                let nist_oid = Oid::from_slice(&[1, 2, 840, 10045, 2, 1]);

                let named_curve = curve_oid(curve).expect("bad curve OID");

                let alg_id = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_oid(&nist_oid);
                        writer.next().write_oid(&named_curve);
                    });
                });

                let subj_public_key = BitVec::from_bytes(e.value());
                yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_der(&alg_id);
                        writer.next().write_bitvec(&subj_public_key);
                    });
                })
            }
        }
    }

    fn curve_oid(curve: &Curve) -> Result<Oid> {
        let oid = match curve {
            Curve::NistP256 => Oid::from_slice(&[1, 2, 840, 10045, 3, 1, 7]),
            Curve::NistP384 => Oid::from_slice(&[1, 3, 132, 0, 34]),
            Curve::NistP521 => Oid::from_slice(&[1, 3, 132, 0, 35]),
            Curve::Cv25519 => Oid::from_slice(&[1, 3, 101, 110]),
            Curve::Ed25519 => Oid::from_slice(&[1, 3, 101, 112]),
            curve => {
                return Err(anyhow::anyhow!("unsupported curve {}", curve));
            }
        };

        Ok(oid)
    }
}
