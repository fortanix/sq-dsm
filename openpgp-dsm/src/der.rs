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
        pub public: RsaPub,
        pub d:      Vec<u8>,
        pub p:      Vec<u8>,
        pub q:      Vec<u8>,
        pub u:      Vec<u8>,
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
        yasna::parse_der(&pk.subject_public_key, |reader| {
            Ok(reader.read_sequence(|reader| {
                let n = reader.next().read_biguint()?.to_bytes_be();
                let e = reader.next().read_u32()?.to_be_bytes().to_vec();
                Ok(RsaPub { n, e })
            })?)
        })
        .map_err(|e| e.into())
    }

    pub fn rsa_private_nedpqu(buf: &[u8]) -> super::Result<RsaPriv> {
        Ok(yasna::parse_der(&buf, |reader| {
            reader.read_sequence(|reader| {
                let _version = reader.next().read_u32()?;
                let n = reader.next().read_biguint()?.to_bytes_be();
                let e = reader.next().read_biguint()?.to_bytes_be();
                let d = reader.next().read_biguint()?.to_bytes_be();
                let p = reader.next().read_biguint()?.to_bytes_be();
                let q = reader.next().read_biguint()?.to_bytes_be();
                let _exp1 = reader.next().read_biguint()?;
                let _exp2 = reader.next().read_biguint()?;
                let u = reader.next().read_biguint()?.to_bytes_be();

                let public = RsaPub { n, e };

                Ok(RsaPriv { public, d, p, q, u })
            })
        })?)
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
        Ok(yasna::parse_der(&buf, |reader| {
            reader.read_sequence(|reader| {
                let r = reader.next().read_biguint()?.to_bytes_be();
                let s = reader.next().read_biguint()?.to_bytes_be();
                Ok((r, s))
            })
        })?)
    }

    pub fn ec_priv_scalar(buf: &[u8]) -> super::Result<Vec<u8>> {
        Ok(yasna::parse_der(&buf, |reader| {
            Ok(reader.read_sequence(|reader| {
                let _version = reader.next().read_u32()?;
                let priv_key = reader.next().read_bytes()?;
                let _oid = reader.next().read_tagged_der()?;
                let _pk = reader.next().read_tagged_der()?;
                Ok(priv_key)
            })?)
        })?)
    }
}

pub mod serialize {
    use super::*;

    use bit_vec::BitVec;
    use yasna::models::ObjectIdentifier as Oid;

    use sequoia_openpgp::crypto::mpi;

    pub fn spki_ecdh(curve: &Curve, e: &mpi::MPI) -> Vec<u8> {
        match curve {
            Curve::Cv25519 => {
                let x = e.value();
                if x.len() == 0 {
                    unreachable!();
                }

                let x = x[1..].to_vec();

                let curve_25519_oid = Oid::from_slice(&[1, 3, 101, 110]);
                yasna::construct_der(|w| {
                    w.write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&curve_25519_oid);
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

                let named_curve = curve_oid(&curve).expect("bad curve OID");

                let alg_id = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_oid(&nist_oid);
                        writer.next().write_oid(&named_curve);
                    });
                });

                let subj_public_key = BitVec::from_bytes(&e.value());
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
            curve @ _ => {
                return Err(anyhow::anyhow!("unsupported curve {}", curve));
            }
        };

        Ok(oid)
    }
}
