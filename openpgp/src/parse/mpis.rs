//! Functions for parsing MPIs.

use std::io::Read;
use {
    Result,
    Error,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    HashAlgorithm,
};
use constants::Curve;
use mpis::{MPI, MPIs};
use parse::{
    BufferedReaderGeneric,
    PacketHeaderParser,
    Cookie,
};

impl MPIs {
    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse_public_key_naked<T: AsRef<[u8]>>(
        algo: PublicKeyAlgorithm, buf: T)
        -> Result<Self>
    {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse_public_key(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn parse_public_key<'a>(algo: PublicKeyAlgorithm,
                            php: &mut PacketHeaderParser<'a>)
        -> Result<Self>
    {
        use PublicKeyAlgorithm::*;

        match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                let n = MPI::parse("rsa_public_n", php)?;
                let e = MPI::parse("rsa_public_e", php)?;

                Ok(MPIs::RSAPublicKey{ e: e, n: n })
            }

            DSA => {
                let p = MPI::parse("dsa_public_p", php)?;
                let q = MPI::parse("dsa_public_q", php)?;
                let g = MPI::parse("dsa_public_g", php)?;
                let y = MPI::parse("dsa_public_y", php)?;

                Ok(MPIs::DSAPublicKey{
                    p: p,
                    q: q,
                    g: g,
                    y: y,
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let p = MPI::parse("elgamal_public_p", php)?;
                let g = MPI::parse("elgamal_public_g", php)?;
                let y = MPI::parse("elgamal_public_y", php)?;

                Ok(MPIs::ElgamalPublicKey{
                    p: p,
                    g: g,
                    y: y,
                })
            }

            EdDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("eddsa_public", php)?;

                Ok(MPIs::EdDSAPublicKey{
                    curve: Curve::from_oid(&curve),
                    q: q
                })
            }

            ECDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdsa_public", php)?;

                Ok(MPIs::ECDSAPublicKey{
                    curve: Curve::from_oid(&curve),
                    q: q
                })
            }

            ECDH => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdh_public", php)?;
                let kdf_len = php.parse_u8("kdf_len")?;

                if kdf_len != 3 {
                    return Err(Error::MalformedPacket(
                            "wrong kdf length".into()).into());
                }

                let _reserved = php.parse_u8("kdf_reserved")?;
                let hash: HashAlgorithm = php.parse_u8("kdf_hash")?.into();
                let sym: SymmetricAlgorithm = php.parse_u8("kek_symm")?.into();

                Ok(MPIs::ECDHPublicKey{
                    curve: Curve::from_oid(&curve),
                    q: q,
                    hash: hash,
                    sym: sym
                })
            }

            Unknown(p) | Private(p) => {
                Err(Error::UnknownPublicKeyAlgorithm(p.into()).into())
            }
        }
    }

    /// Parses secret key MPIs for `algo` plus their SHA1 checksum. Fails if the
    /// checksum is wrong.
    pub fn parse_chksumd_secret_key<T: Read>(algo: PublicKeyAlgorithm, cur: T)
        -> Result<Self> {
        use std::io::Cursor;
        use serialize::Serialize;
        use nettle::Hash;
        use nettle::hash::insecure_do_not_use::Sha1;

        // read mpis
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        let mpis = Self::parse_secret_key(algo, &mut php)?;

        // read expected sha1 hash of the mpis
        let their_chksum = php.parse_bytes("checksum", 20)?;
        let mut cur = Cursor::new(vec![]);

        // compute sha1 hash
        mpis.serialize(&mut cur)?;
        let buf = cur.into_inner();
        let mut hsh = Sha1::default();

        hsh.update(&buf);
        let mut our_chksum = [0u8; 20];
        hsh.digest(&mut our_chksum);

        if our_chksum != their_chksum[..] {
            Err(Error::MalformedMPI("checksum wrong".to_string()).into())
        } else {
            Ok(mpis)
        }
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse_secret_key_naked<T: AsRef<[u8]>>(algo: PublicKeyAlgorithm,
                                                  buf: T)
        -> Result<Self>
    {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse_secret_key(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn parse_secret_key<'a>(algo: PublicKeyAlgorithm,
                                       php: &mut PacketHeaderParser<'a>)
        -> Result<Self>
    {
        use PublicKeyAlgorithm::*;

        match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                let d = MPI::parse("rsa_secret_d", php)?;
                let p = MPI::parse("rsa_secret_p", php)?;
                let q = MPI::parse("rsa_secret_q", php)?;
                let u = MPI::parse("rsa_secret_u", php)?;

                Ok(MPIs::RSASecretKey{
                    d: d,
                    p: p,
                    q: q,
                    u: u,
                })
            }

            DSA => {
                let x = MPI::parse("dsa_secret", php)?;

                Ok(MPIs::DSASecretKey{
                    x: x,
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let x = MPI::parse("elgamal_secret", php)?;

                Ok(MPIs::ElgamalSecretKey{
                    x: x,
                })
            }

            EdDSA => {
                Ok(MPIs::EdDSASecretKey{
                    scalar: MPI::parse("eddsa_secret", php)?
                })
            }

            ECDSA => {
                Ok(MPIs::ECDSASecretKey{
                    scalar: MPI::parse("ecdsa_secret", php)?
                })
            }

            ECDH => {
                Ok(MPIs::ECDHSecretKey{
                    scalar: MPI::parse("ecdh_secret", php)? })
            }

            Unknown(p) | Private(p) => {
                Err(Error::UnknownPublicKeyAlgorithm(p.into()).into())
            }
        }
    }

    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse_ciphertext_naked<T: AsRef<[u8]>>(algo: PublicKeyAlgorithm,
                                                  buf: T)
        -> Result<Self> {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse_ciphertext(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn parse_ciphertext<'a>(algo: PublicKeyAlgorithm,
                                       php: &mut PacketHeaderParser<'a>)
        -> Result<Self> {
        use PublicKeyAlgorithm::*;

        match algo {
            RSAEncryptSign | RSAEncrypt => {
                let c = MPI::parse("rsa_ciphertext", php)?;

                Ok(MPIs::RSACiphertext{
                    c: c,
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let e = MPI::parse("elgamal_e", php)?;
                let c = MPI::parse("elgamal_c", php)?;

                Ok(MPIs::ElgamalCiphertext{
                    e: e,
                    c: c,
                })
            }

            ECDH => {
                let e = MPI::parse("ecdh_e", php)?;
                let key_len = php.parse_u8("ecdh_key_len")? as usize;
                let key = Vec::from(&php.parse_bytes("ecdh_key", key_len)?
                                    [..key_len]);

                Ok(MPIs::ECDHCiphertext{
                    e: e, key: key.into_boxed_slice()
                })
            }

            Unknown(p) | Private(p) => {
                Err(Error::UnknownPublicKeyAlgorithm(p.into()).into())
            }

            RSASign | DSA | EdDSA | ECDSA => {
                Err(Error::UnknownPublicKeyAlgorithm(algo).into())
            }
        }
    }

    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse_signature_naked<T: AsRef<[u8]>>(
        algo: PublicKeyAlgorithm, buf: T)
        -> Result<Self>
    {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::parse_signature(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn parse_signature<'a>(algo: PublicKeyAlgorithm,
                                      php: &mut PacketHeaderParser<'a>)
        -> Result<Self>
    {
        use PublicKeyAlgorithm::*;

        match algo {
            RSAEncryptSign | RSASign => {
                let s = MPI::parse("rsa_signature", php)?;

                Ok(MPIs::RSASignature{
                    s: s,
                })
            }

            DSA => {
                let r = MPI::parse("dsa_signature_r", php)?;
                let s = MPI::parse("dsa_signature_s", php)?;

                Ok(MPIs::DSASignature{
                    r: r,
                    s: s,
                })
            }

            ElgamalEncryptSign => {
                let r = MPI::parse("elgamal_signature_r", php)?;
                let s = MPI::parse("elgamal_signature_s", php)?;

                Ok(MPIs::ElgamalSignature{
                    r: r,
                    s: s,
                })
            }

            EdDSA => {
                let r = MPI::parse("eddsa_signature_r", php)?;
                let s = MPI::parse("eddsa_signature_s", php)?;

                Ok(MPIs::EdDSASignature{
                    r: r,
                    s: s,
                })
            }

            ECDSA => {
                let r = MPI::parse("ecdsa_signature_r", php)?;
                let s = MPI::parse("ecdsa_signature_s", php)?;

                Ok(MPIs::ECDSASignature{
                    r: r,
                    s: s,
                })
            }

            Unknown(p) | Private(p) => {
                Err(Error::UnknownPublicKeyAlgorithm(p.into()).into())
            }

            RSAEncrypt | ElgamalEncrypt | ECDH => {
                Err(Error::UnknownPublicKeyAlgorithm(algo).into())
            }
        }
    }
}

#[test]
fn mpis_parse_test() {
    use std::io::Cursor;
    use PublicKeyAlgorithm::*;

    // Dummy RSA public key.
    {
        let buf = b"\x00\x01\x01\x00\x02\x02".to_vec();
        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        let mpis = MPIs::parse_public_key(RSAEncrypt, &mut parser).unwrap();

        //assert_eq!(mpis.serialized_len(), 6);
        match &mpis {
            &MPIs::RSAPublicKey{ ref n, ref e } => {
                assert_eq!(n.bits, 1);
                assert_eq!(n.value[0], 1);
                assert_eq!(n.value.len(), 1);
                assert_eq!(e.bits, 2);
                assert_eq!(e.value[0], 2);
                assert_eq!(e.value.len(), 1);
            }

            _ => assert!(false),
        }
    }

    // The number 2.
    {
        let buf = b"\x00\x02\x02".to_vec();
        let cur = Cursor::new(buf);
        let bio = BufferedReaderGeneric::with_cookie(
            cur, None, Cookie::default());
        let mut parser = PacketHeaderParser::new_naked(Box::new(bio));
        let mpis = MPIs::parse_ciphertext(RSAEncrypt, &mut parser).unwrap();

        assert_eq!(mpis.serialized_len(), 3);
    }

    // The number 511.
    let mpi = MPI::parse_naked(Cursor::new(b"\x00\x09\x01\xff".to_vec())).unwrap();
    assert_eq!(mpi.value.len(), 2);
    assert_eq!(mpi.bits, 9);
    assert_eq!(mpi.value[0], 1);
    assert_eq!(mpi.value[1], 0xff);

    // The number 1, incorrectly encoded (the length should be 1,
    // not 2).
    assert!(MPI::parse_naked(Cursor::new(b"\x00\x02\x01".to_vec())).is_err());
}
