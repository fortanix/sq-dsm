//! Asymmetric crypt operations.

use nettle::{dsa, ecc, ecdsa, ed25519, rsa, Yarrow};

use crate::packet::{self, Key};
use crate::crypto::SessionKey;
use crate::crypto::mpis::{self, MPI};
use crate::constants::{Curve, HashAlgorithm};

use crate::Error;
use crate::Result;

/// Creates a signature.
///
/// This is a low-level mechanism to produce an arbitrary OpenPGP
/// signature.  Using this trait allows Sequoia to perform all
/// operations involving signing to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
pub trait Signer {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key;

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpis::Signature>;
}

/// Decrypts a message.
///
/// This is a low-level mechanism to decrypt an arbitrary OpenPGP
/// ciphertext.  Using this trait allows Sequoia to perform all
/// operations involving decryption to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
pub trait Decryptor {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key;

    /// Decrypts `ciphertext`, returning the plain session key.
    fn decrypt(&mut self, ciphertext: &mpis::Ciphertext)
               -> Result<SessionKey>;
}

/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  If both
/// are available in memory, a `KeyPair` is a convenient
/// implementation of [`Signer`] and [`Decryptor`].
///
/// [`Signer`]: trait.Signer.html
/// [`Decryptor`]: trait.Decryptor.html
#[derive(Clone)]
pub struct KeyPair {
    public: Key,
    secret: packet::key::Unencrypted,
}

impl KeyPair {
    /// Creates a new key pair.
    pub fn new(public: Key, secret: packet::key::Unencrypted) -> Result<Self> {
        Ok(Self {
            public: public,
            secret: secret,
        })
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &Key {
        &self.public
    }

    /// Returns a reference to the secret key.
    pub fn secret(&self) -> &packet::key::Unencrypted {
        &self.secret
    }
}

impl Signer for KeyPair {
    fn public(&self) -> &Key {
        &self.public
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpis::Signature>
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;

        let mut rng = Yarrow::default();

        self.secret.map(|secret| {
            #[allow(deprecated)]
            match (self.public.pk_algo(), self.public.mpis(), secret)
        {
            (RSASign,
             &PublicKey::RSA { ref e, ref n },
             &mpis::SecretKey::RSA { ref p, ref q, ref d, .. }) |
            (RSAEncryptSign,
             &PublicKey::RSA { ref e, ref n },
             &mpis::SecretKey::RSA { ref p, ref q, ref d, .. }) => {
                let public = rsa::PublicKey::new(n.value(), e.value())?;
                let secret = rsa::PrivateKey::new(d.value(), p.value(),
                                                  q.value(), Option::None)?;

                // The signature has the length of the modulus.
                let mut sig = vec![0u8; n.value().len()];

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                rsa::sign_digest_pkcs1(&public, &secret, digest,
                                       hash_algo.oid()?,
                                       &mut rng, &mut sig)?;

                Ok(mpis::Signature::RSA {
                    s: MPI::new(&sig),
                })
            },

            (DSA,
             &PublicKey::DSA { ref p, ref q, ref g, .. },
             &mpis::SecretKey::DSA { ref x }) => {
                let params = dsa::Params::new(p.value(), q.value(), g.value());
                let secret = dsa::PrivateKey::new(x.value());

                let sig = dsa::sign(&params, &secret, digest, &mut rng)?;

                Ok(mpis::Signature::DSA {
                    r: MPI::new(&sig.r()),
                    s: MPI::new(&sig.s()),
                })
            },

            (EdDSA,
             &PublicKey::EdDSA { ref curve, ref q },
             &mpis::SecretKey::EdDSA { ref scalar }) => match curve {
                Curve::Ed25519 => {
                    let public = q.decode_point(&Curve::Ed25519)?.0;

                    let mut sig = vec![0; ed25519::ED25519_SIGNATURE_SIZE];

                    // Nettle expects the private key to be exactly
                    // ED25519_KEY_SIZE bytes long but OpenPGP allows leading
                    // zeros to be stripped.
                    // Padding has to be unconditional; otherwise we have a
                    // secret-dependent branch.
                    let missing = ed25519::ED25519_KEY_SIZE
                        .saturating_sub(scalar.value().len());
                    let mut sec = [0u8; ed25519::ED25519_KEY_SIZE];
                    sec[missing..].copy_from_slice(scalar.value());

                    let res = ed25519::sign(public, &sec[..], digest, &mut sig);
                    unsafe {
                        memsec::memzero(sec.as_mut_ptr(),
                                        ed25519::ED25519_KEY_SIZE);
                    }
                    res?;

                    Ok(mpis::Signature::EdDSA {
                        r: MPI::new(&sig[..32]),
                        s: MPI::new(&sig[32..]),
                    })
                },
                _ => Err(
                    Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (ECDSA,
             &PublicKey::ECDSA { ref curve, .. },
             &mpis::SecretKey::ECDSA { ref scalar }) => {
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

                Ok(mpis::Signature::ECDSA {
                    r: MPI::new(&sig.r()),
                    s: MPI::new(&sig.s()),
                })
            },

            (pk_algo, _, _) => Err(Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?}, key {:?}, \
                 and secret key {:?}",
                pk_algo, self.public, self.secret)).into()),
        }})
    }
}

impl Decryptor for KeyPair {
    fn public(&self) -> &Key {
        &self.public
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn decrypt(&mut self, ciphertext: &mpis::Ciphertext)
               -> Result<SessionKey>
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;

        self.secret.map(
            |secret| Ok(match (self.public.mpis(), secret, ciphertext)
        {
            (PublicKey::RSA{ ref e, ref n },
             mpis::SecretKey::RSA{ ref p, ref q, ref d, .. },
             mpis::Ciphertext::RSA{ ref c }) => {
                let public = rsa::PublicKey::new(n.value(), e.value())?;
                let secret = rsa::PrivateKey::new(d.value(), p.value(),
                                                  q.value(), Option::None)?;
                let mut rand = Yarrow::default();
                rsa::decrypt_pkcs1(&public, &secret, &mut rand, c.value())?
                    .into()
            }

            (PublicKey::Elgamal{ .. },
             mpis::SecretKey::Elgamal{ .. },
             mpis::Ciphertext::Elgamal{ .. }) =>
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(ElgamalEncrypt).into()),

            (PublicKey::ECDH{ .. },
             mpis::SecretKey::ECDH { .. },
             mpis::Ciphertext::ECDH { .. }) =>
                crate::crypto::ecdh::decrypt(&self.public, secret, ciphertext)?,

            (public, secret, ciphertext) =>
                return Err(Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                    public, secret, ciphertext)).into()),
        }))
    }
}

impl From<KeyPair> for packet::Key {
    fn from(p: KeyPair) -> Self {
        let (mut key, secret) = (p.public, p.secret);
        key.set_secret(Some(secret.into()));
        key
    }

}
