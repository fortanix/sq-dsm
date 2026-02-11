//! Hold the implementation of [`Signer`] and [`Decryptor`] for [`KeyPair`].
//!
//! [`Signer`]: crate::crypto::Signer
//! [`Decryptor`]: crate::crypto::Decryptor
//! [`KeyPair`]: crate::crypto::KeyPair

use nettle::{
    curve25519,
    curve448,
    dsa,
    ecc,
    ecdh,
    ecdsa,
    ed25519,
    ed448,
    rsa,
    random::Yarrow,
};

use crate::{Error, Result};

use crate::packet::{key, Key};
use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mpi::{self, MPI, ProtectedMPI, PublicKey};
use crate::crypto::{
    SessionKey,
    mem::Protected,
};
use crate::types::{Curve, HashAlgorithm};

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA
                => true,
            X448 | Ed448
                => curve448::IS_SUPPORTED,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        use Curve::*;
        match curve {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP384 | BrainpoolP512 | Unknown(_)
                => false,
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        debug_assert_eq!(curve25519::CURVE25519_SIZE, 32);
        let mut rng = Yarrow::default();
        let secret = curve25519::private_key(&mut rng);
        let mut public = [0; 32];
        curve25519::mul_g(&mut public, &secret)?;
        Ok((secret.into(), public))
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        debug_assert_eq!(curve25519::CURVE25519_SIZE, 32);
        let mut public = [0; 32];
        curve25519::mul_g(&mut public, secret)?;
        Ok(public)
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        debug_assert_eq!(curve25519::CURVE25519_SIZE, 32);
        let mut s: Protected = vec![0; 32].into();
        curve25519::mul(&mut s, secret, public)?;
        Ok(s)
    }

    fn x448_generate_key() -> Result<(Protected, [u8; 56])> {
        debug_assert_eq!(curve448::CURVE448_SIZE, 56);
        if ! curve448::IS_SUPPORTED {
            return Err(Error::UnsupportedPublicKeyAlgorithm(
                PublicKeyAlgorithm::Ed448).into());
        }
        let mut rng = Yarrow::default();
        let secret = curve448::private_key(&mut rng);
        let mut public = [0; 56];
        curve448::mul_g(&mut public, &secret)?;
        Ok((secret.into(), public))
    }

    fn x448_derive_public(secret: &Protected) -> Result<[u8; 56]> {
        debug_assert_eq!(curve448::CURVE448_SIZE, 56);
        if ! curve448::IS_SUPPORTED {
            return Err(Error::UnsupportedPublicKeyAlgorithm(
                PublicKeyAlgorithm::Ed448).into());
        }
        let mut public = [0; 56];
        curve448::mul_g(&mut public, secret)?;
        Ok(public)
    }

    fn x448_shared_point(secret: &Protected, public: &[u8; 56])
                           -> Result<Protected> {
        debug_assert_eq!(curve448::CURVE448_SIZE, 56);
        if ! curve448::IS_SUPPORTED {
            return Err(Error::UnsupportedPublicKeyAlgorithm(
                PublicKeyAlgorithm::Ed448).into());
        }
        let mut s: Protected = vec![0; 56].into();
        curve448::mul(&mut s, secret, public)?;
        Ok(s)
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        debug_assert_eq!(ed25519::ED25519_KEY_SIZE, 32);
        let mut rng = Yarrow::default();
        let mut public = [0; 32];
        let secret: Protected =
            ed25519::private_key(&mut rng).into();
        ed25519::public_key(&mut public, &secret)?;
        Ok((secret, public))
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        debug_assert_eq!(ed25519::ED25519_KEY_SIZE, 32);
        let mut public = [0; 32];
        ed25519::public_key(&mut public, secret)?;
        Ok(public)
    }

    fn ed25519_sign(secret: &Protected, public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        debug_assert_eq!(ed25519::ED25519_KEY_SIZE, 32);
        debug_assert_eq!(ed25519::ED25519_SIGNATURE_SIZE, 64);
        let mut sig = [0u8; 64];
        ed25519::sign(public, secret, digest, &mut sig)?;
        Ok(sig)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        debug_assert_eq!(ed25519::ED25519_KEY_SIZE, 32);
        debug_assert_eq!(ed25519::ED25519_SIGNATURE_SIZE, 64);
        Ok(ed25519::verify(public, digest, signature)?)
    }

    fn ed448_generate_key() -> Result<(Protected, [u8; 57])> {
        debug_assert_eq!(ed448::ED448_KEY_SIZE, 57);
        let mut rng = Yarrow::default();
        let mut public = [0; 57];
        let secret: Protected =
            ed448::private_key(&mut rng).into();
        ed448::public_key(&mut public, &secret)?;
        Ok((secret, public))
    }

    fn ed448_derive_public(secret: &Protected) -> Result<[u8; 57]> {
        debug_assert_eq!(ed448::ED448_KEY_SIZE, 57);
        let mut public = [0; 57];
        ed448::public_key(&mut public, secret)?;
        Ok(public)
    }

    fn ed448_sign(secret: &Protected, public: &[u8; 57], digest: &[u8])
                    -> Result<[u8; 114]> {
        debug_assert_eq!(ed448::ED448_KEY_SIZE, 57);
        debug_assert_eq!(ed448::ED448_SIGNATURE_SIZE, 114);
        let mut sig = [0u8; 114];
        ed448::sign(public, secret, digest, &mut sig)?;
        Ok(sig)
    }

    fn ed448_verify(public: &[u8; 57], digest: &[u8], signature: &[u8; 114])
                      -> Result<bool> {
        debug_assert_eq!(ed448::ED448_KEY_SIZE, 57);
        debug_assert_eq!(ed448::ED448_SIGNATURE_SIZE, 114);
        Ok(ed448::verify(public, digest, signature)?)
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        let mut rng = Yarrow::default();
        let q_bits = if p_bits <= 1024 { 160 } else { 256 };
        let params = dsa::Params::generate(&mut rng, p_bits, q_bits)?;
        let (p, q) = params.primes();
        let g = params.g();
        let (y, x) = dsa::generate_keypair(&params, &mut rng);
        Ok((p.into(), q.into(), g.into(), y.as_bytes().into(),
            x.as_bytes().into()))
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, _y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        let mut rng = Yarrow::default();
        let params = dsa::Params::new(p.value(), q.value(), g.value());
        let secret = dsa::PrivateKey::new(x.value());

        let sig = dsa::sign(&params, &secret, digest, &mut rng)?;

        Ok((MPI::new(&sig.r()), MPI::new(&sig.s())))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        let key = dsa::PublicKey::new(y.value());
        let params = dsa::Params::new(p.value(), q.value(), g.value());
        let signature = dsa::Signature::new(r.value(), s.value());
        Ok(dsa::verify(&params, &key, digest, &signature))
    }
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
                               -> Result<mpi::Signature>
    {
        use crate::PublicKeyAlgorithm::*;

        let mut rng = Yarrow::default();

        #[allow(deprecated)]
        match (self.public().pk_algo(), self.public().mpis(), secret)
        {
            (RSASign,
             &PublicKey::RSA { ref e, ref n },
             &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) |
            (RSAEncryptSign,
             &PublicKey::RSA { ref e, ref n },
             &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) => {
                let public = rsa::PublicKey::new(n.value(), e.value())?;
                let secret = rsa::PrivateKey::new(d.value(), p.value(),
                                                  q.value(), Option::None)?;

                // The signature has the length of the modulus.
                let mut sig = vec![0u8; n.value().len()];

                // As described in [Section 5.2.2 and 5.2.3 of RFC 9580],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 9580]:
                //   https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.2
                rsa::sign_digest_pkcs1(&public, &secret, digest,
                                       hash_algo.oid()?,
                                       &mut rng, &mut sig)?;

                Ok(mpi::Signature::RSA {
                    s: MPI::new(&sig),
                })
            },

            (ECDSA,
             &PublicKey::ECDSA { ref curve, .. },
             &mpi::SecretKeyMaterial::ECDSA { ref scalar }) => {
                let secret = match curve {
                    Curve::NistP256 =>
                        ecc::Scalar::new::<ecc::Secp256r1>(
                            scalar.value())?,
                    Curve::NistP384 =>
                        ecc::Scalar::new::<ecc::Secp384r1>(
                            scalar.value())?,
                    Curve::NistP521 =>
                        ecc::Scalar::new::<ecc::Secp521r1>(
                            scalar.value())?,
                    _ =>
                        return Err(
                            Error::UnsupportedEllipticCurve(curve.clone())
                                .into()),
                };

                let sig = ecdsa::sign(&secret, digest, &mut rng);

                Ok(mpi::Signature::ECDSA {
                    r: MPI::new(&sig.r()),
                    s: MPI::new(&sig.s()),
                })
            },

            (pk_algo, _, _) => Err(Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?}, key {:?}, \
                 and secret key {:?}",
                pk_algo, self.public(), self.secret())).into()),
        }
    }
}

impl KeyPair {
    pub(crate) fn decrypt_backend(&self, secret: &mpi::SecretKeyMaterial, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>
    {
        use crate::PublicKeyAlgorithm::*;

        Ok(match (self.public().mpis(), secret, ciphertext) {
            (PublicKey::RSA{ ref e, ref n },
             mpi::SecretKeyMaterial::RSA{ ref p, ref q, ref d, .. },
             mpi::Ciphertext::RSA{ ref c }) => {
                let public = rsa::PublicKey::new(n.value(), e.value())?;
                let secret = rsa::PrivateKey::new(d.value(), p.value(),
                                                  q.value(), Option::None)?;
                let mut rand = Yarrow::default();
                if let Some(l) = plaintext_len {
                    let mut plaintext: SessionKey = vec![0; l].into();
                    rsa::decrypt_pkcs1(&public, &secret, &mut rand,
                                       c.value(), plaintext.as_mut())?;
                    plaintext
                } else {
                    rsa::decrypt_pkcs1_insecure(&public, &secret,
                                                &mut rand, c.value())?
                    .into()
                }
            }

            (PublicKey::ElGamal{ .. },
             mpi::SecretKeyMaterial::ElGamal{ .. },
             mpi::Ciphertext::ElGamal{ .. }) => {
                #[allow(deprecated)]
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(ElGamalEncrypt).into());
            },

            (PublicKey::ECDH{ .. },
             mpi::SecretKeyMaterial::ECDH { .. },
             mpi::Ciphertext::ECDH { .. }) =>
                crate::crypto::ecdh::decrypt(self.public(), secret, ciphertext,
                                             plaintext_len)?,

            (public, secret, ciphertext) =>
                return Err(Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                    public, secret, ciphertext)).into()),
        })
    }
}


impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match self.mpis() {
                    mpi::PublicKey::RSA { e, n } => {
                        // The ciphertext has the length of the modulus.
                        let ciphertext_len = n.value().len();
                        if data.len() + 11 > ciphertext_len {
                            return Err(Error::InvalidArgument(
                                "Plaintext data too large".into()).into());
                        }

                        let mut esk = vec![0u8; ciphertext_len];
                        let mut rng = Yarrow::default();
                        let pk = rsa::PublicKey::new(n.value(), e.value())?;
                        rsa::encrypt_pkcs1(&pk, &mut rng, data,
                                           &mut esk)?;
                        Ok(mpi::Ciphertext::RSA {
                            c: MPI::new(&esk),
                        })
                    },
                    pk => {
                        Err(Error::MalformedPacket(
                            format!(
                                "Key: Expected RSA public key, got {:?}",
                                pk)).into())
                    },
                }
            },

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(),
                                                 data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            X25519 | // Handled in common code.
            X448 | // Handled in common code.
            ElGamalEncrypt | ElGamalEncryptSign |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()>
    {
        use crate::crypto::mpi::Signature;

        let ok = match (self.mpis(), sig) {
            (PublicKey::RSA { e, n }, Signature::RSA { s }) => {
                let key = rsa::PublicKey::new(n.value(), e.value())?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 9580],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 9580]:
                //   https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.2
                rsa::verify_digest_pkcs1(&key, digest, hash_algo.oid()?,
                                         s.value())?
            },
            (PublicKey::ECDSA { curve, q }, Signature::ECDSA { s, r }) =>
            {
                let (x, y) = q.decode_point(curve)?;
                let key = match curve {
                    Curve::NistP256 => ecc::Point::new::<ecc::Secp256r1>(x, y)?,
                    Curve::NistP384 => ecc::Point::new::<ecc::Secp384r1>(x, y)?,
                    Curve::NistP521 => ecc::Point::new::<ecc::Secp521r1>(x, y)?,
                    _ => return Err(
                        Error::UnsupportedEllipticCurve(curve.clone()).into()),
                };

                let signature = dsa::Signature::new(r.value(), s.value());
                ecdsa::verify(&key, digest, &signature)
            },
            _ => return Err(Error::MalformedPacket(format!(
                "unsupported combination of key {} and signature {:?}.",
                self.pk_algo(), sig)).into()),
        };

        if ok {
            Ok(())
        } else {
            Err(Error::ManipulatedMessage.into())
        }
    }
}

use std::time::SystemTime;
use crate::packet::key::{Key4, SecretParts};
use crate::types::PublicKeyAlgorithm;

impl<R> Key4<SecretParts, R>
    where R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing RSA key.
    ///
    /// The RSA key will use the secret exponent `d`, derived from the
    /// secret primes `p` and `q`.  The key will have its creation
    /// date set to `ctime` or the current time if `None` is given.
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        let sec = rsa::PrivateKey::new(d, p, q, None)?;
        let key = sec.public_key()?;
        let (a, b, c) = sec.as_rfc4880();

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(&key.e()[..]),
                n: mpi::MPI::new(&key.n()[..]),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: a.into(),
                q: b.into(),
                u: c.into(),
            }.into())
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// Like import_secret_rsa but uses the given public exponent `e`.
    ///
    /// Note that import_secret_rsa computes e such that ed == 1 mod phi(n), but
    /// most standards (e.g. RFC3447, referenced by RFC4880 as ultimate
    /// authority for PKCS#1) dictate ed == 1 mod lambda(n).
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa_unchecked_e<T>(
        e: &[u8], d: &[u8], p: &[u8], q: &[u8], ctime: T
    ) -> Result<Self> where T: Into<Option<SystemTime>>
    {
        let sec = rsa::PrivateKey::new(d, p, q, None)?;
        let key = sec.public_key()?;
        let (a, b, c) = sec.as_rfc4880();

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(e),
                n: mpi::MPI::new(&key.n()[..]),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: a.into(),
                q: b.into(),
                u: c.into(),
            }.into())
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let mut rng = Yarrow::default();

        let (public, private) = rsa::generate_keypair(&mut rng, bits as u32)?;
        let (p, q, u) = private.as_rfc4880();
        let public_mpis = PublicKey::RSA {
            e: MPI::new(&*public.e()),
            n: MPI::new(&*public.n()),
        };
        let private_mpis = mpi::SecretKeyMaterial::RSA {
            d: private.d().into(),
            p: p.into(),
            q: q.into(),
            u: u.into(),
        };

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public_mpis,
            private_mpis.into())
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub(crate) fn generate_ecc_backend(for_signing: bool, curve: Curve)
                                       -> Result<(PublicKeyAlgorithm,
                                                  mpi::PublicKey,
                                                  mpi::SecretKeyMaterial)>
    {
        let mut rng = Yarrow::default();

        match (curve.clone(), for_signing) {
            (Curve::Ed25519, true) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::Cv25519, false) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::NistP256, true)  | (Curve::NistP384, true)
            | (Curve::NistP521, true) => {
                let (public, private, field_sz) = match curve {
                    Curve::NistP256 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp256r1, _>(&mut rng)?;
                        (pu, sec, 256)
                    }
                    Curve::NistP384 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp384r1, _>(&mut rng)?;
                        (pu, sec, 384)
                    }
                    Curve::NistP521 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp521r1, _>(&mut rng)?;
                        (pu, sec, 521)
                    }
                    _ => unreachable!(),
                };
                let (pub_x, pub_y) = public.as_bytes();
                let public_mpis =  mpi::PublicKey::ECDSA{
                    curve,
                    q: MPI::new_point(&pub_x, &pub_y, field_sz),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA{
                    scalar: private.as_bytes().into(),
                };

                Ok((PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis))
            }

            (Curve::NistP256, false)  | (Curve::NistP384, false)
            | (Curve::NistP521, false) => {
                    let (private, field_sz) = match curve {
                        Curve::NistP256 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp256r1, _>(&mut rng);

                            (pv, 256)
                        }
                        Curve::NistP384 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp384r1, _>(&mut rng);

                            (pv, 384)
                        }
                        Curve::NistP521 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp521r1, _>(&mut rng);

                            (pv, 521)
                        }
                        _ => unreachable!(),
                    };
                    let public = ecdh::point_mul_g(&private);
                    let (pub_x, pub_y) = public.as_bytes();
                    let public_mpis = mpi::PublicKey::ECDH{
                        q: MPI::new_point(&pub_x, &pub_y, field_sz),
                        hash:
                        crate::crypto::ecdh::default_ecdh_kdf_hash(&curve),
                        sym:
                        crate::crypto::ecdh::default_ecdh_kek_cipher(&curve),
                        curve,
                    };
                    let private_mpis = mpi::SecretKeyMaterial::ECDH{
                        scalar: private.as_bytes().into(),
                    };

                    Ok((PublicKeyAlgorithm::ECDH, public_mpis, private_mpis))
                }

            _ => Err(Error::UnsupportedEllipticCurve(curve).into()),
        }
    }
}
