//! Holds the implementation of [`Signer`] and [`Decryptor`] for [`KeyPair`].
//!
//! [`Signer`]: ../../asymmetric/trait.Signer.html
//! [`Decryptor`]: ../../asymmetric/trait.Decryptor.html
//! [`KeyPair`]: ../../asymmetric/struct.KeyPair.html

use std::convert::TryFrom;
use std::time::SystemTime;

use num_bigint_dig::{traits::ModInverse, BigUint};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, RsaPrivateKey, Pkcs1v15Sign};

use ecdsa::{
    EncodedPoint,
    hazmat::{SignPrimitive, VerifyPrimitive},
};
use p256::elliptic_curve::{
    generic_array::GenericArray as GA,
    ops::Reduce,
    sec1::FromEncodedPoint,
};

use crate::{Error, Result};
use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{self, MPI, ProtectedMPI};
use crate::crypto::SessionKey;
use crate::crypto::pad_truncating;
use crate::packet::{key, Key};
use crate::packet::key::{Key4, SecretParts};
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use super::GenericArrayExt;

impl TryFrom<&Protected> for Box<ed25519_dalek::SigningKey> {
    type Error = anyhow::Error;

    fn try_from(value: &Protected) -> Result<Self> {
        if value.len() != ed25519_dalek::SECRET_KEY_LENGTH {
            return Err(crate::Error::InvalidArgument(
                "Bad Ed25519 secret length".into()).into());
        }
        Ok(Box::new(ed25519_dalek::SigningKey::from_bytes(
            value.as_ref().try_into().map_err(
                |e: std::array::TryFromSliceError| {
                    Error::InvalidKey(e.to_string())
                })?)))
    }
}

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            RSAEncryptSign | RSAEncrypt | RSASign | ECDH | EdDSA | ECDSA
                => true,
            DSA
                => true,
            X448 | Ed448 |
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        use self::Curve::*;
        match curve {
            NistP256 | NistP384 | NistP521
                => true,
            Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP384 | BrainpoolP512 | Unknown(_)
                => false,
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        use x25519_dalek::{StaticSecret, PublicKey};

        // x25519_dalek v2.0 doesn't reexport OsRng.  It
        // depends on rand_core 0.6.
        use rand_core::OsRng;

        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        let mut secret_bytes = secret.to_bytes();
        let secret: Protected = secret_bytes.into();
        unsafe {
            memsec::memzero(secret_bytes.as_mut_ptr(), secret_bytes.len());
        }

        Ok((secret, public.to_bytes()))
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(<[u8; 32]>::try_from(&secret[..])?);
        Ok(*PublicKey::from(&secret).as_bytes())
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        use x25519_dalek::{StaticSecret, PublicKey};

        let secret = StaticSecret::from(<[u8; 32]>::try_from(&secret[..])?);
        let public = PublicKey::from(public.clone());
        Ok((&secret.diffie_hellman(&public).as_bytes()[..]).into())
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        use rand_core::OsRng as OsRng;
        let pair = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Ok((pair.to_bytes().into(), pair.verifying_key().to_bytes()))
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        use ed25519_dalek::SigningKey;
        let secret: Box<SigningKey> = secret.try_into()?;
        let public = secret.verifying_key();
        Ok(public.to_bytes())
    }

    fn ed25519_sign(secret: &Protected, _public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        use ed25519_dalek::{SigningKey, Signer};
        let pair: Box<SigningKey> = secret.try_into()?;
        Ok(pair.sign(digest).to_bytes().try_into()?)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        use ed25519_dalek::{VerifyingKey, Verifier, Signature};

        let public = VerifyingKey::from_bytes(public).map_err(|e| {
            Error::InvalidKey(e.to_string())
        })?;
        let signature = Signature::from_bytes(signature);
        Ok(public.verify(digest, &signature).is_ok())
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        #[allow(deprecated)]
        let size = match p_bits {
            1024 => dsa::KeySize::DSA_1024_160,
            2048 => dsa::KeySize::DSA_2048_256,
            3072 => dsa::KeySize::DSA_3072_256,
            n => return Err(Error::InvalidArgument(
                format!("Key size {} is not supported", n)).into()),
        };

        let mut rng = rand_core::OsRng;
        let components = dsa::Components::generate(&mut rng, size);
        let p = components.p().into();
        let q = components.q().into();
        let g = components.g().into();
        let secret = dsa::SigningKey::generate(&mut rng, components);
        let public = secret.verifying_key();

        Ok((p, q, g, public.y().into(), secret.x().into()))
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        use dsa::signature::hazmat::PrehashSigner;
        let c = dsa::Components::from_components(
            p.into(), q.into(), g.into())?;
        let public =
            dsa::VerifyingKey::from_components(c, y.into())?;
        let secret =
            dsa::SigningKey::from_components(public, x.into())?;
        let sig = secret.sign_prehash(digest)?;
        Ok((sig.r().into(), sig.s().into()))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        use dsa::signature::hazmat::PrehashVerifier;
        let c = dsa::Components::from_components(
            p.into(), q.into(), g.into())?;
        let public = dsa::VerifyingKey::from_components(c, y.into())?;
        let sig = dsa::Signature::from_components(r.into(), s.into())?;
        public.verify_prehash(digest, &sig)?;
        Ok(true)
    }
}

impl From<&BigUint> for ProtectedMPI {
    fn from(v: &BigUint) -> Self {
        v.to_bytes_be().into()
    }
}

impl From<&ProtectedMPI> for BigUint {
    fn from(v: &ProtectedMPI) -> Self {
        BigUint::from_bytes_be(v.value()).into()
    }
}

impl From<&BigUint> for MPI {
    fn from(v: &BigUint) -> Self {
        v.to_bytes_be().into()
    }
}

impl From<&MPI> for BigUint {
    fn from(v: &MPI) -> Self {
        BigUint::from_bytes_be(v.value()).into()
    }
}

fn pkcs1_padding(hash_algo: HashAlgorithm) -> Result<Pkcs1v15Sign> {
    let hash = match hash_algo {
        HashAlgorithm::MD5 => Pkcs1v15Sign::new::<md5::Md5>(),
        HashAlgorithm::SHA1 => Pkcs1v15Sign::new::<sha1collisiondetection::Sha1CD>(),
        HashAlgorithm::SHA224 => Pkcs1v15Sign::new::<sha2::Sha224>(),
        HashAlgorithm::SHA256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        HashAlgorithm::SHA384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        HashAlgorithm::SHA512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        HashAlgorithm::RipeMD => Pkcs1v15Sign::new::<ripemd::Ripemd160>(),
        _ => return Err(Error::InvalidArgument(format!(
            "Algorithm {:?} not representable", hash_algo)).into()),
    };
    Ok(hash)
}

fn rsa_public_key(e: &MPI, n: &MPI) -> Result<RsaPublicKey> {
    let n = BigUint::from_bytes_be(n.value());
    let e = BigUint::from_bytes_be(e.value());
    Ok(RsaPublicKey::new(n, e)?)
}

fn rsa_private_key(e: &MPI, n: &MPI, p: &ProtectedMPI, q: &ProtectedMPI, d: &ProtectedMPI)
    -> Result<RsaPrivateKey>
{
    let n = BigUint::from_bytes_be(n.value());
    let e = BigUint::from_bytes_be(e.value());
    let p = BigUint::from_bytes_be(p.value());
    let q = BigUint::from_bytes_be(q.value());
    let d = BigUint::from_bytes_be(d.value());
    Ok(RsaPrivateKey::from_components(n, e, d, vec![p, q])?)
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
            -> Result<mpi::Signature>
    {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match (self.public().pk_algo(), self.public().mpis(), secret) {
            (RSAEncryptSign,
             mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. }) |
            (RSASign,
             mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. }) => {
                let key = rsa_private_key(e, n, p, q, d)?;
                let padding = pkcs1_padding(hash_algo)?;
                let sig = key.sign(padding, digest)?;
                Ok(mpi::Signature::RSA {
                    s: mpi::MPI::new(&sig),
                })
            },

            (PublicKeyAlgorithm::ECDSA,
             mpi::PublicKey::ECDSA { curve, .. },
             mpi::SecretKeyMaterial::ECDSA { scalar }) => match curve
            {
                Curve::NistP256 => {
                    use p256::Scalar;
                    const LEN: usize = 32;

                    let key = scalar.value_padded(LEN);
                    let key = Scalar::reduce_bytes(GA::try_from_slice(&key)?);
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;

                    let sig = loop {
                        let mut k: Protected = vec![0; LEN].into();
                        crate::crypto::random(&mut k)?;
                        let k = Scalar::reduce_bytes(
                            GA::try_from_slice(&k)?);
                        if let Ok(s) = key.try_sign_prehashed(k, &dig) {
                            break s.0;
                        }
                    };

                    Ok(mpi::Signature::ECDSA {
                        r: MPI::new(&sig.r().to_bytes()),
                        s: MPI::new(&sig.s().to_bytes()),
                    })
                },

                Curve::NistP384 => {
                    use p384::Scalar;
                    const LEN: usize = 48;

                    let key = scalar.value_padded(LEN);
                    let key = Scalar::reduce_bytes(GA::try_from_slice(&key)?);
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;

                    let sig = loop {
                        let mut k: Protected = vec![0; LEN].into();
                        crate::crypto::random(&mut k)?;
                        let k = Scalar::reduce_bytes(
                            GA::try_from_slice(&k)?);
                        if let Ok(s) = key.try_sign_prehashed(k, &dig) {
                            break s.0;
                        }
                    };

                    Ok(mpi::Signature::ECDSA {
                        r: MPI::new(&sig.r().to_bytes()),
                        s: MPI::new(&sig.s().to_bytes()),
                    })
                },

                Curve::NistP521 => {
                    use p521::Scalar;
                    const LEN: usize = 66;

                    let key = scalar.value_padded(LEN);
                    let key = Scalar::reduce_bytes(GA::try_from_slice(&key)?);
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;

                    let sig = loop {
                        let mut k: Protected = vec![0; LEN].into();
                        crate::crypto::random(&mut k)?;
                        let k = Scalar::reduce_bytes(
                            GA::try_from_slice(&k)?);
                        if let Ok(s) = key.try_sign_prehashed(k, &dig) {
                            break s.0;
                        }
                    };

                    Ok(mpi::Signature::ECDSA {
                        r: MPI::new(&sig.r().to_bytes()),
                        s: MPI::new(&sig.s().to_bytes()),
                    })
                },

                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (pk_algo, _, _) => {
                Err(Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                        and secret key {:?}",
                    pk_algo,
                    self.public(),
                    self.secret()
                )).into())
            }
        }
    }
}

impl KeyPair {
    pub(crate) fn decrypt_backend(&self, secret: &mpi::SecretKeyMaterial, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>
    {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match (self.public().mpis(), secret, ciphertext) {
            (mpi::PublicKey::RSA { e, n },
             mpi::SecretKeyMaterial::RSA { p, q, d, .. },
             mpi::Ciphertext::RSA { c }) => {
                let key = rsa_private_key(e, n, p, q, d)?;
                let decrypted = key.decrypt(Pkcs1v15Encrypt, c.value())?;
                Ok(SessionKey::from(decrypted))
            }

            (mpi::PublicKey::ElGamal { .. },
             mpi::SecretKeyMaterial::ElGamal { .. },
             mpi::Ciphertext::ElGamal { .. }) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(ElGamalEncrypt).into()),

            (mpi::PublicKey::ECDH { .. },
             mpi::SecretKeyMaterial::ECDH { .. },
             mpi::Ciphertext::ECDH { .. }) =>
                crate::crypto::ecdh::decrypt(self.public(), secret, ciphertext,
                                             plaintext_len),

            (public, secret, ciphertext) =>
                Err(Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                    public, secret, ciphertext)).into()),
        }
    }
}


impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => match self.mpis() {
                mpi::PublicKey::RSA { e, n } => {
                    // The ciphertext has the length of the modulus.
                    let ciphertext_len = n.value().len();
                    if data.len() + 11 > ciphertext_len {
                        return Err(Error::InvalidArgument(
                            "Plaintext data too large".into()).into());
                    }
                    let key = rsa_public_key(e, n)?;
                    let ciphertext = key.encrypt(
                        &mut rsa::rand_core::OsRng,
                        Pkcs1v15Encrypt, data.as_ref())?;
                    Ok(mpi::Ciphertext::RSA {
                        c: mpi::MPI::new(&ciphertext)
                    })
                }
                pk => Err(Error::MalformedPacket(format!(
                    "Key: Expected RSA public key, got {:?}", pk)).into())
            }

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            ElGamalEncrypt | ElGamalEncryptSign |
            X25519 | X448 |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()>
    {
        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }
        match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                let key = rsa_public_key(e, n)?;
                let padding = pkcs1_padding(hash_algo)?;
                // Originally, we had:
                //
                // key.verify(padding, digest, s.value())?;
                //
                // Since version 0.9.0 of the rsa crate, this no
                // longer works, because the verify function checks
                // that the signature length in bytes is the same as
                // the key length.  No other crypto backend appears
                // care (including older version of the rsa crate),
                // but would happily left pad it with zeros.  We now
                // do that manually:
                //
                // See
                // https://docs.rs/rsa/0.9.0/src/rsa/pkcs1v15.rs.html#212
                // and https://github.com/RustCrypto/RSA/issues/322.
                key.verify(padding, digest, &s.value_padded(key.size())?)?;
                Ok(())
            }

            (mpi::PublicKey::ECDSA { curve, q },
             mpi::Signature::ECDSA { r, s }) => match curve
            {
                Curve::NistP256 => {
                    use p256::{AffinePoint, ecdsa::Signature};
                    const LEN: usize = 32;

                    let key = AffinePoint::from_encoded_point(
                        &EncodedPoint::<p256::NistP256>::from_bytes(q.value())?);
                    let key = if key.is_some().into() {
                        key.unwrap()
                    } else {
                        return Err(Error::InvalidKey(
                            "Point is not on the curve".into()).into());
                    };

                    let sig = Signature::from_scalars(
                        GA::try_clone_from_slice(
                            &r.value_padded(LEN).map_err(bad)?)?,
                        GA::try_clone_from_slice(
                            &s.value_padded(LEN).map_err(bad)?)?)
                        .map_err(bad)?;
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;
                    key.verify_prehashed(&dig, &sig).map_err(bad)
                },

                Curve::NistP384 => {
                    use p384::{AffinePoint, ecdsa::Signature};
                    const LEN: usize = 48;

                    let key = AffinePoint::from_encoded_point(
                        &EncodedPoint::<p384::NistP384>::from_bytes(q.value())?);
                    let key = if key.is_some().into() {
                        key.unwrap()
                    } else {
                        return Err(Error::InvalidKey(
                            "Point is not on the curve".into()).into());
                    };

                    let sig = Signature::from_scalars(
                        GA::try_clone_from_slice(
                            &r.value_padded(LEN).map_err(bad)?)?,
                        GA::try_clone_from_slice(
                            &s.value_padded(LEN).map_err(bad)?)?)
                        .map_err(bad)?;
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;
                    key.verify_prehashed(&dig, &sig).map_err(bad)
                },

                Curve::NistP521 => {
                    use p521::{AffinePoint, ecdsa::Signature};
                    const LEN: usize = 66;

                    let key = AffinePoint::from_encoded_point(
                        &EncodedPoint::<p521::NistP521>::from_bytes(q.value())?);
                    let key = if key.is_some().into() {
                        key.unwrap()
                    } else {
                        return Err(Error::InvalidKey(
                            "Point is not on the curve".into()).into());
                    };

                    let sig = Signature::from_scalars(
                        GA::try_clone_from_slice(
                            &r.value_padded(LEN).map_err(bad)?)?,
                        GA::try_clone_from_slice(
                            &s.value_padded(LEN).map_err(bad)?)?)
                        .map_err(bad)?;
                    let dig = pad_truncating(digest, LEN);
                    let dig = GA::try_from_slice(&dig)?;
                    key.verify_prehashed(&dig, &sig).map_err(bad)
                },

                _ => Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },
            _ => Err(Error::MalformedPacket(format!(
                "unsupported combination of key {} and signature {:?}.",
                self.pk_algo(), sig)).into()),
        }
    }
}

impl<R> Key4<SecretParts, R>
    where R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing RSA key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_cv25519<H, S, T>(private_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<SystemTime>>
    {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(<[u8; 32]>::try_from(private_key)?);
        let public_key = PublicKey::from(&secret);

        let mut private_key = Vec::from(private_key);
        private_key.reverse();

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or(HashAlgorithm::SHA512),
                sym: sym.into().unwrap_or(SymmetricAlgorithm::AES256),
                q: MPI::new_compressed_point(&*public_key.as_bytes()),
            },
            mpi::SecretKeyMaterial::ECDH {
                scalar: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        use ed25519_dalek::{PublicKey, SecretKey};

        let private = SecretKey::from_bytes(private_key).map_err(|e| {
            Error::InvalidKey(e.to_string())
        })?;

        // Mark MPI as compressed point with 0x40 prefix. See
        // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
        let mut public = [0u8; 1 + CURVE25519_SIZE];
        public[0] = 0x40;
        public[1..].copy_from_slice(Into::<PublicKey>::into(&private).as_bytes());

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: mpi::MPI::new(&public)
            },
            mpi::SecretKeyMaterial::EdDSA {
                scalar: mpi::MPI::new(private_key).into(),
            }.into()
        )
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
        // RFC 4880: `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };

        // RustCrypto can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(e),
                n: mpi::MPI::new(&n.to_bytes_be()),
            },
            mpi::SecretKeyMaterial::RSA {
                d: mpi::MPI::new(d).into(),
                p: mpi::MPI::new(p).into(),
                q: mpi::MPI::new(q).into(),
                u: mpi::MPI::new(&u.to_bytes_be()).into(),
            }.into()
        )
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        // RFC 4880: `p < q`
        let (p, q) = crate::crypto::rsa_sort_raw_pq(p, q);

        // RustCrypto can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let big_d = BigUint::from_bytes_be(d);
        let big_phi = (big_p.clone() - 1u32) * (big_q.clone() - 1u32);
        let e = big_d.mod_inverse(big_phi) // e ≡ d⁻¹ (mod 𝜙)
            .and_then(|x| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `d` and `(p-1)(q-1)` aren't coprime".into()))?;

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(&e.to_bytes_be()),
                n: mpi::MPI::new(&n.to_bytes_be()),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.to_bytes_be().into(),
            }.into()
        )
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits)?;
        let (p, q) = match key.primes() {
            [p, q] => (p, q),
            _ => panic!("RSA key generation resulted in wrong number of primes"),
        };
        // RFC 4880: `p < q`
        let (p, q) = rsa_sort_pq(p, q);
        let u = p.mod_inverse(q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x| x.to_biguint())
            .expect("rsa crate did not generate coprime p and q");

        let public = mpi::PublicKey::RSA {
            e: mpi::MPI::new(&key.to_public_key().e().to_bytes_be()),
            n: mpi::MPI::new(&key.to_public_key().n().to_bytes_be()),
        };

        let private = mpi::SecretKeyMaterial::RSA {
            p: p.to_bytes_be().into(),
            q: q.to_bytes_be().into(),
            d: key.d().to_bytes_be().into(),
            u: u.to_bytes_be().into(),
        };

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public,
            private.into(),
        )
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
        match (&curve, for_signing) {
            (Curve::Ed25519, true) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::Cv25519, false) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::NistP256, true) => {
                use p256::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDSA {
                    curve,
                    q: MPI::new(public.as_bytes()),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis))
            },

            (Curve::NistP256, false) => {
                use p256::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDH {
                    q: MPI::new(public.as_bytes()),
                    hash:
                    crate::crypto::ecdh::default_ecdh_kdf_hash(&curve),
                    sym:
                    crate::crypto::ecdh::default_ecdh_kek_cipher(&curve),
                    curve,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDH, public_mpis, private_mpis))
            },

            (Curve::NistP384, true) => {
                use p384::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p384::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDSA {
                    curve,
                    q: MPI::new(public.as_bytes()),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis))
            },

            (Curve::NistP384, false) => {
                use p384::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p384::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDH {
                    q: MPI::new(public.as_bytes()),
                    hash:
                    crate::crypto::ecdh::default_ecdh_kdf_hash(&curve),
                    sym:
                    crate::crypto::ecdh::default_ecdh_kek_cipher(&curve),
                    curve,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDH, public_mpis, private_mpis))
            },

            (Curve::NistP521, true) => {
                use p521::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p521::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDSA {
                    curve,
                    q: MPI::new(public.as_bytes()),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis))
            },

            (Curve::NistP521, false) => {
                use p521::{EncodedPoint, SecretKey};

                let secret = SecretKey::random(
                    &mut p521::elliptic_curve::rand_core::OsRng);
                let public = EncodedPoint::from(secret.public_key());

                let public_mpis = mpi::PublicKey::ECDH {
                    q: MPI::new(public.as_bytes()),
                    hash:
                    crate::crypto::ecdh::default_ecdh_kdf_hash(&curve),
                    sym:
                    crate::crypto::ecdh::default_ecdh_kek_cipher(&curve),
                    curve,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: Vec::from(secret.to_bytes().as_slice()).into(),
                };

                Ok((PublicKeyAlgorithm::ECDH, public_mpis, private_mpis))
            },

            _ => Err(Error::UnsupportedEllipticCurve(curve).into()),
        }
    }
}

/// Given the secret prime values `p` and `q`, returns the pair of
/// primes so that the smaller one comes first.
///
/// Section 5.5.3 of RFC4880 demands that `p < q`.  This function can
/// be used to order `p` and `q` accordingly.
///
/// Note: even though this function seems trivial, we introduce it as
/// explicit abstraction.  The reason is that the function's
/// expression also "works" (as in it compiles) for byte slices, but
/// does the wrong thing, see [`crate::crypto::rsa_sort_raw_pq`].
fn rsa_sort_pq<'a>(p: &'a BigUint, q: &'a BigUint)
                   -> (&'a BigUint, &'a BigUint)
{
    if p < q {
        (p, q)
    } else {
        (q, p)
    }
}
