//! Functions for parsing MPIs.

use std::io::Read;
use buffered_reader::BufferedReader;
use crate::{
    Result,
    Error,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    HashAlgorithm,
};
use crate::types::Curve;
use crate::crypto::{
    mem::Protected,
    mpi::{self, MPI, ProtectedMPI},
};
use crate::parse::{
    PacketHeaderParser,
    Cookie,
};

impl mpi::PublicKey {
    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub fn parse<R: Read + Send + Sync>(algo: PublicKeyAlgorithm, reader: R) -> Result<Self>
    {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub(crate) fn _parse(
        algo: PublicKeyAlgorithm,
        php: &mut PacketHeaderParser<'_>)
        -> Result<Self>
    {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                let n = MPI::parse("rsa_public_n_len", "rsa_public_n", php)?;
                let e = MPI::parse("rsa_public_e_len", "rsa_public_e", php)?;

                Ok(mpi::PublicKey::RSA { e, n })
            }

            DSA => {
                let p = MPI::parse("dsa_public_p_len", "dsa_public_p", php)?;
                let q = MPI::parse("dsa_public_q_len", "dsa_public_q", php)?;
                let g = MPI::parse("dsa_public_g_len", "dsa_public_g", php)?;
                let y = MPI::parse("dsa_public_y_len", "dsa_public_y", php)?;

                Ok(mpi::PublicKey::DSA {
                    p,
                    q,
                    g,
                    y,
                })
            }

            ElGamalEncrypt | ElGamalEncryptSign => {
                let p = MPI::parse("elgamal_public_p_len", "elgamal_public_p",
                                   php)?;
                let g = MPI::parse("elgamal_public_g_len", "elgamal_public_g",
                                   php)?;
                let y = MPI::parse("elgamal_public_y_len", "elgamal_public_y",
                                   php)?;

                Ok(mpi::PublicKey::ElGamal {
                    p,
                    g,
                    y,
                })
            }

            EdDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("eddsa_public_len", "eddsa_public", php)?;

                Ok(mpi::PublicKey::EdDSA {
                    curve: Curve::from_oid(&curve),
                    q
                })
            }

            ECDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdsa_public_len", "ecdsa_public", php)?;

                Ok(mpi::PublicKey::ECDSA {
                    curve: Curve::from_oid(&curve),
                    q
                })
            }

            ECDH => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdh_public_len", "ecdh_public", php)?;
                let kdf_len = php.parse_u8("kdf_len")?;

                if kdf_len != 3 {
                    return Err(Error::MalformedPacket(
                            "wrong kdf length".into()).into());
                }

                let reserved = php.parse_u8("kdf_reserved")?;
                if reserved != 1 {
                    return Err(Error::MalformedPacket(
                            format!("Reserved kdf field must be 0x01, \
                                     got 0x{:x}", reserved)).into());
                }
                let hash: HashAlgorithm = php.parse_u8("kdf_hash")?.into();
                let sym: SymmetricAlgorithm = php.parse_u8("kek_symm")?.into();

                Ok(mpi::PublicKey::ECDH {
                    curve: Curve::from_oid(&curve),
                    q,
                    hash,
                    sym
                })
            }

            X25519 => {
                let mut u = [0; 32];
                php.parse_bytes_into("x25519_public", &mut u)?;
                Ok(mpi::PublicKey::X25519 { u })
            },

            X448 => {
                let mut u = [0; 56];
                php.parse_bytes_into("x448_public", &mut u)?;
                Ok(mpi::PublicKey::X448 { u: Box::new(u) })
            },

            Ed25519 => {
                let mut a = [0; 32];
                php.parse_bytes_into("ed25519_public", &mut a)?;
                Ok(mpi::PublicKey::Ed25519 { a })
            },

            Ed448 => {
                let mut a = [0; 57];
                php.parse_bytes_into("ed448_public", &mut a)?;
                Ok(mpi::PublicKey::Ed448 { a: Box::new(a) })
            },

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_len",
                                               "unknown", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpi::PublicKey::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }
        }
    }
}

impl mpi::SecretKeyMaterial {
    /// Parses secret key MPIs for `algo` plus their SHA1 checksum.
    ///
    /// Fails if the checksum is wrong.
    #[deprecated(
        since = "1.14.0",
        note = "Leaks secrets into the heap, use [`SecretKeyMaterial::from_bytes_with_checksum`]")]
    pub fn parse_with_checksum<R: Read + Send + Sync>(algo: PublicKeyAlgorithm,
                                        reader: R,
                                        checksum: mpi::SecretKeyChecksum)
                                        -> Result<Self> {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php, Some(checksum))
    }

    /// Parses secret key MPIs for `algo` plus their SHA1 checksum.
    ///
    /// Fails if the checksum is wrong.
    pub fn from_bytes_with_checksum(algo: PublicKeyAlgorithm,
                                    bytes: &[u8],
                                    checksum: mpi::SecretKeyChecksum)
                                    -> Result<Self> {
        let bio = buffered_reader::Memory::with_cookie(
            bytes, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php, Some(checksum))
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    #[deprecated(
        since = "1.14.0",
        note = "Leaks secrets into the heap, use [`SecretKeyMaterial::from_bytes`]")]
    pub fn parse<R: Read + Send + Sync>(algo: PublicKeyAlgorithm, reader: R) -> Result<Self>
    {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php, None)
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub fn from_bytes(algo: PublicKeyAlgorithm, buf: &[u8]) -> Result<Self> {
        let bio = buffered_reader::Memory::with_cookie(
            buf, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php, None)
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub(crate) fn _parse(
        algo: PublicKeyAlgorithm,
        php: &mut PacketHeaderParser<'_>,
        checksum: Option<mpi::SecretKeyChecksum>,
    )
        -> Result<Self>
    {
        use crate::PublicKeyAlgorithm::*;

        // We want to get the data we are going to read next as raw
        // bytes later.  To do so, we remember the cursor position now
        // before reading the MPIs.
        let mpis_start = php.reader.total_out();

        #[allow(deprecated)]
        let mpis: Result<Self> = match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                Ok(mpi::SecretKeyMaterial::RSA {
                    d: ProtectedMPI::parse(
                        "rsa_secret_d_len", "rsa_secret_d", php)?,
                    p: ProtectedMPI::parse(
                        "rsa_secret_p_len", "rsa_secret_p", php)?,
                    q: ProtectedMPI::parse(
                        "rsa_secret_q_len", "rsa_secret_q", php)?,
                    u: ProtectedMPI::parse(
                        "rsa_secret_u_len", "rsa_secret_u", php)?,
                })
            }

            DSA => {
                Ok(mpi::SecretKeyMaterial::DSA {
                    x: ProtectedMPI::parse(
                        "dsa_secret_len", "dsa_secret", php)?,
                })
            }

            ElGamalEncrypt | ElGamalEncryptSign => {
                Ok(mpi::SecretKeyMaterial::ElGamal {
                    x: ProtectedMPI::parse(
                        "elgamal_secret_len", "elgamal_secret", php)?,
                })
            }

            EdDSA => {
                Ok(mpi::SecretKeyMaterial::EdDSA {
                    scalar: ProtectedMPI::parse(
                        "eddsa_secret_len", "eddsa_secret", php)?,
                })
            }

            ECDSA => {
                Ok(mpi::SecretKeyMaterial::ECDSA {
                    scalar: ProtectedMPI::parse(
                        "ecdsa_secret_len", "ecdsa_secret", php)?,
                })
            }

            ECDH => {
                Ok(mpi::SecretKeyMaterial::ECDH {
                    scalar: ProtectedMPI::parse(
                        "ecdh_secret_len", "ecdh_secret", php)?,
                })
            }

            X25519 => {
                let mut x: Protected = vec![0; 32].into();
                php.parse_bytes_into("x25519_secret", &mut x)?;
                Ok(mpi::SecretKeyMaterial::X25519 { x })
            },

            X448 => {
                let mut x: Protected = vec![0; 56].into();
                php.parse_bytes_into("x448_secret", &mut x)?;
                Ok(mpi::SecretKeyMaterial::X448 { x })
            },

            Ed25519 => {
                let mut x: Protected = vec![0; 32].into();
                php.parse_bytes_into("ed25519_secret", &mut x)?;
                Ok(mpi::SecretKeyMaterial::Ed25519 { x })
            },

            Ed448 => {
                let mut x: Protected = vec![0; 57].into();
                php.parse_bytes_into("ed448_secret", &mut x)?;
                Ok(mpi::SecretKeyMaterial::Ed448 { x })
            },

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = ProtectedMPI::parse("unknown_len",
                                               "unknown", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpi::SecretKeyMaterial::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into(),
                })
            }
        };
        let mpis = mpis?;

        if let Some(checksum) = checksum {
            // We want to get the data we are going to read next as
            // raw bytes later.  To do so, we remember the cursor
            // position now after reading the MPIs and compute the
            // length.
            let mpis_len = php.reader.total_out() - mpis_start;

            // We do a bit of acrobatics to avoid copying the secrets.
            // We read the checksum now, so that we can freely
            // manipulate the Dup reader and get a borrow of the raw
            // MPIs.
            let their_chksum = php.parse_bytes("checksum", checksum.len())?;

            // Remember how much we read in total for a sanity check.
            let total_out = php.reader.total_out();

            // Now get the secrets as raw byte slice.
            php.reader.rewind();
            php.reader.consume(mpis_start);
            let data = &php.reader.data_consume_hard(mpis_len)?[..mpis_len];

            let good = match checksum {
                mpi::SecretKeyChecksum::SHA1 => {
                    // Compute SHA1 hash.
                    let mut hsh = HashAlgorithm::SHA1.context().unwrap()
                        .for_digest();
                    hsh.update(data);
                    let mut our_chksum = [0u8; 20];
                    let _ = hsh.digest(&mut our_chksum);

                    our_chksum == their_chksum[..]
                },

                mpi::SecretKeyChecksum::Sum16 => {
                    // Compute sum.
                    let our_chksum = data.iter()
                        .fold(0u16, |acc, v| acc.wrapping_add(*v as u16))
                        .to_be_bytes();

                    our_chksum == their_chksum[..]
                },
            };

            // Finally, consume the checksum to fix the state of the
            // Dup reader.
            php.reader.consume(checksum.len());

            // See if we got the state right.
            debug_assert_eq!(total_out, php.reader.total_out());

            if good {
                Ok(mpis)
            } else {
                Err(Error::MalformedMPI("checksum wrong".to_string()).into())
            }
        } else {
            Ok(mpis)
        }
    }
}

impl mpi::Ciphertext {
    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub fn parse<R: Read + Send + Sync>(algo: PublicKeyAlgorithm, reader: R) -> Result<Self>
    {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub(crate) fn _parse(
        algo: PublicKeyAlgorithm,
        php: &mut PacketHeaderParser<'_>)
        -> Result<Self> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSAEncrypt => {
                let c = MPI::parse("rsa_ciphertxt_len", "rsa_ciphertxt",
                                   php)?;

                Ok(mpi::Ciphertext::RSA {
                    c,
                })
            }

            ElGamalEncrypt | ElGamalEncryptSign => {
                let e = MPI::parse("elgamal_e_len", "elgamal_e", php)?;
                let c = MPI::parse("elgamal_c_len", "elgamal_c", php)?;

                Ok(mpi::Ciphertext::ElGamal {
                    e,
                    c,
                })
            }

            ECDH => {
                let e = MPI::parse("ecdh_e_len", "ecdh_e", php)?;
                let key_len = php.parse_u8("ecdh_esk_len")? as usize;
                let key = Vec::from(&php.parse_bytes("ecdh_esk", key_len)?
                                    [..key_len]);

                Ok(mpi::Ciphertext::ECDH {
                    e, key: key.into_boxed_slice()
                })
            }

            X25519 => {
                let mut e = [0; 32];
                php.parse_bytes_into("x25519_e", &mut e)?;
                let key_len = php.parse_u8("x25519_esk_len")? as usize;
                let key = Vec::from(&php.parse_bytes("x25519_esk", key_len)?
                                    [..key_len]);
                Ok(mpi::Ciphertext::X25519 { e: Box::new(e), key: key.into() })
            },

            X448 => {
                let mut e = [0; 56];
                php.parse_bytes_into("x448_e", &mut e)?;
                let key_len = php.parse_u8("x448_esk_len")? as usize;
                let key = Vec::from(&php.parse_bytes("x448_esk", key_len)?
                                    [..key_len]);
                Ok(mpi::Ciphertext::X448 { e: Box::new(e), key: key.into() })
            },

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_len",
                                               "unknown", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpi::Ciphertext::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }

            RSASign | DSA | EdDSA | ECDSA | Ed25519 | Ed448
                => Err(Error::InvalidArgument(
                    format!("not an encryption algorithm: {:?}", algo)).into()),
        }
    }
}

impl mpi::Signature {
    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub fn parse<R: Read + Send + Sync>(algo: PublicKeyAlgorithm, reader: R) -> Result<Self>
    {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(bio.into_boxed());
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 9580] for details.
    ///
    ///   [Section 3.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.2
    pub(crate) fn _parse(
        algo: PublicKeyAlgorithm,
        php: &mut PacketHeaderParser<'_>)
        -> Result<Self> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSASign => {
                let s = MPI::parse("rsa_signature_len", "rsa_signature", php)?;

                Ok(mpi::Signature::RSA {
                    s,
                })
            }

            DSA => {
                let r = MPI::parse("dsa_sig_r_len", "dsa_sig_r",
                                   php)?;
                let s = MPI::parse("dsa_sig_s_len", "dsa_sig_s",
                                   php)?;

                Ok(mpi::Signature::DSA {
                    r,
                    s,
                })
            }

            ElGamalEncryptSign => {
                let r = MPI::parse("elgamal_sig_r_len",
                                   "elgamal_sig_r", php)?;
                let s = MPI::parse("elgamal_sig_s_len",
                                   "elgamal_sig_s", php)?;

                Ok(mpi::Signature::ElGamal {
                    r,
                    s,
                })
            }

            EdDSA => {
                let r = MPI::parse("eddsa_sig_r_len", "eddsa_sig_r",
                                   php)?;
                let s = MPI::parse("eddsa_sig_s_len", "eddsa_sig_s",
                                   php)?;

                Ok(mpi::Signature::EdDSA {
                    r,
                    s,
                })
            }

            ECDSA => {
                let r = MPI::parse("ecdsa_sig_r_len", "ecdsa_sig_r",
                                   php)?;
                let s = MPI::parse("ecdsa_sig_s_len", "ecdsa_sig_s",
                                   php)?;

                Ok(mpi::Signature::ECDSA {
                    r,
                    s,
                })
            }

            Ed25519 => {
                let mut s = [0; 64];
                php.parse_bytes_into("ed25519_sig", &mut s)?;
                Ok(mpi::Signature::Ed25519 { s: Box::new(s) })
            },

            Ed448 => {
                let mut s = [0; 114];
                php.parse_bytes_into("ed448_sig", &mut s)?;
                Ok(mpi::Signature::Ed448 { s: Box::new(s) })
            },

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_len",
                                               "unknown", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpi::Signature::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }

            RSAEncrypt | ElGamalEncrypt | ECDH | X25519 | X448
                => Err(Error::InvalidArgument(
                    format!("not a signature algorithm: {:?}", algo)).into()),
        }
    }
}

#[test]
fn mpis_parse_test() {
    use std::io::Cursor;
    use super::Parse;
    use crate::PublicKeyAlgorithm::*;
    use crate::serialize::MarshalInto;

    // Dummy RSA public key.
    {
        let buf = Cursor::new("\x00\x01\x01\x00\x02\x02");
        let mpis = mpi::PublicKey::parse(RSAEncryptSign, buf).unwrap();

        //assert_eq!(mpis.serialized_len(), 6);
        match &mpis {
            &mpi::PublicKey::RSA{ ref n, ref e } => {
                assert_eq!(n.bits(), 1);
                assert_eq!(n.value()[0], 1);
                assert_eq!(n.value().len(), 1);
                assert_eq!(e.bits(), 2);
                assert_eq!(e.value()[0], 2);
                assert_eq!(e.value().len(), 1);
            }

            _ => assert!(false),
        }
    }

    // The number 2.
    {
        let buf = Cursor::new("\x00\x02\x02");
        let mpis = mpi::Ciphertext::parse(RSAEncryptSign, buf).unwrap();

        assert_eq!(mpis.serialized_len(), 3);
    }

    // The number 511.
    let mpi = MPI::from_bytes(b"\x00\x09\x01\xff").unwrap();
    assert_eq!(mpi.value().len(), 2);
    assert_eq!(mpi.bits(), 9);
    assert_eq!(mpi.value()[0], 1);
    assert_eq!(mpi.value()[1], 0xff);

    // The number 1, incorrectly encoded (the length should be 1,
    // not 2).
    assert!(MPI::from_bytes(b"\x00\x02\x01").is_err());
}
