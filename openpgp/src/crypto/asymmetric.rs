//! Asymmetric crypt operations.

use nettle::{dsa, ecc, ecdsa, ed25519, rsa, random::Yarrow};

use crate::packet::{self, key, Key};
use crate::crypto::SessionKey;
use crate::crypto::mpis::{self, MPI};
use crate::types::{Curve, HashAlgorithm};

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
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpis::Signature>;
}

impl Signer for Box<dyn Signer> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpis::Signature> {
        self.as_mut().sign(hash_algo, digest)
    }
}

/// Decrypts a message.
///
/// This is a low-level mechanism to decrypt an arbitrary OpenPGP
/// ciphertext.  Using this trait allows Sequoia to perform all
/// operations involving decryption to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
pub trait Decryptor {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Decrypts `ciphertext`, returning the plain session key.
    fn decrypt(&mut self, ciphertext: &mpis::Ciphertext,
               plaintext_len: Option<usize>)
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
    public: Key<key::PublicParts, key::UnspecifiedRole>,
    secret: packet::key::Unencrypted,
}

impl KeyPair {
    /// Creates a new key pair.
    pub fn new(public: Key<key::PublicParts, key::UnspecifiedRole>,
               secret: packet::key::Unencrypted)
        -> Result<Self>
    {
        Ok(Self {
            public,
            secret,
        })
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    /// Returns a reference to the secret key.
    pub fn secret(&self) -> &packet::key::Unencrypted {
        &self.secret
    }
}

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
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
             &mpis::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) |
            (RSAEncryptSign,
             &PublicKey::RSA { ref e, ref n },
             &mpis::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) => {
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
             &mpis::SecretKeyMaterial::DSA { ref x }) => {
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
             &mpis::SecretKeyMaterial::EdDSA { ref scalar }) => match curve {
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
             &mpis::SecretKeyMaterial::ECDSA { ref scalar }) => {
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
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn decrypt(&mut self, ciphertext: &mpis::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;

        self.secret.map(
            |secret| Ok(match (self.public.mpis(), secret, ciphertext)
        {
            (PublicKey::RSA{ ref e, ref n },
             mpis::SecretKeyMaterial::RSA{ ref p, ref q, ref d, .. },
             mpis::Ciphertext::RSA{ ref c }) => {
                // Workaround for #440:  Make sure c is of the same
                // length as n.
                // XXX: Remove once we depend on nettle > 7.0.0.
                let c_ = if c.value().len() < n.value().len() {
                    let mut c_ = vec![0; n.value().len() - c.value().len()];
                    c_.extend_from_slice(c.value());
                    Some(c_)
                }  else {
                    // If it is bigger, then the packet is likely
                    // corrupted, tough luck then.
                    None
                };
                let c = if let Some(c_) = c_.as_ref() {
                    &c_[..]
                } else {
                    c.value()
                };
                // End of workaround.

                let public = rsa::PublicKey::new(n.value(), e.value())?;
                let secret = rsa::PrivateKey::new(d.value(), p.value(),
                                                  q.value(), Option::None)?;
                let mut rand = Yarrow::default();
                if let Some(l) = plaintext_len {
                    let mut plaintext: SessionKey = vec![0; l].into();
                    rsa::decrypt_pkcs1(&public, &secret, &mut rand,
                                       c, plaintext.as_mut())?;
                    plaintext
                } else {
                    rsa::decrypt_pkcs1_insecure(&public, &secret,
                                                &mut rand, c)?
                    .into()
                }
            }

            (PublicKey::ElGamal{ .. },
             mpis::SecretKeyMaterial::ElGamal{ .. },
             mpis::Ciphertext::ElGamal{ .. }) =>
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(ElGamalEncrypt).into()),

            (PublicKey::ECDH{ .. },
             mpis::SecretKeyMaterial::ECDH { .. },
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

impl From<KeyPair> for Key<key::SecretParts, key::UnspecifiedRole> {
    fn from(p: KeyPair) -> Self {
        let (key, secret) = (p.public, p.secret);
        key.add_secret(secret.into()).0
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub fn encrypt(&self, data: &SessionKey) -> Result<mpis::Ciphertext> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match self.mpis() {
                    mpis::PublicKey::RSA { e, n } => {
                        // The ciphertext has the length of the modulus.
                        let mut esk = vec![0u8; n.value().len()];
                        let mut rng = Yarrow::default();
                        let pk = rsa::PublicKey::new(n.value(), e.value())?;
                        rsa::encrypt_pkcs1(&pk, &mut rng, data,
                                           &mut esk)?;
                        Ok(mpis::Ciphertext::RSA {
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
            algo => Err(Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        }
    }

    /// Verifies the given signature.
    pub fn verify(&self, sig: &packet::Signature, digest: &[u8]) -> Result<()>
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::{PublicKey, Signature};

        #[allow(deprecated)]
        let ok = match (sig.pk_algo(), self.mpis(), sig.mpis()) {
            (RSASign,        PublicKey::RSA { e, n }, Signature::RSA { s }) |
            (RSAEncryptSign, PublicKey::RSA { e, n }, Signature::RSA { s }) => {
                let key = rsa::PublicKey::new(n.value(), e.value())?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                rsa::verify_digest_pkcs1(&key, digest, sig.hash_algo().oid()?,
                                         s.value())?
            },
            (DSA, PublicKey::DSA{ y, p, q, g }, Signature::DSA { s, r }) => {
                let key = dsa::PublicKey::new(y.value());
                let params = dsa::Params::new(p.value(), q.value(), g.value());
                let signature = dsa::Signature::new(r.value(), s.value());

                dsa::verify(&params, &key, digest, &signature)
            },
            (EdDSA, PublicKey::EdDSA{ curve, q }, Signature::EdDSA { r, s }) =>
              match curve {
                Curve::Ed25519 => {
                    if q.value().get(0).map(|&b| b != 0x40).unwrap_or(true) {
                        return Err(Error::MalformedPacket(
                            "Invalid point encoding".into()).into());
                    }

                    // OpenPGP encodes R and S separately, but our
                    // cryptographic library expects them to be
                    // concatenated.
                    let mut signature =
                        Vec::with_capacity(ed25519::ED25519_SIGNATURE_SIZE);

                    // We need to zero-pad them at the front, because
                    // the MPI encoding drops leading zero bytes.
                    let half = ed25519::ED25519_SIGNATURE_SIZE / 2;
                    if r.value().len() < half {
                        for _ in 0..half - r.value().len() {
                            signature.push(0);
                        }
                    }
                    signature.extend_from_slice(r.value());
                    if s.value().len() < half {
                        for _ in 0..half - s.value().len() {
                            signature.push(0);
                        }
                    }
                    signature.extend_from_slice(s.value());

                    // Let's see if we got it right.
                    if signature.len() != ed25519::ED25519_SIGNATURE_SIZE {
                        return Err(Error::MalformedPacket(
                            format!(
                                "Invalid signature size: {}, r: {:?}, s: {:?}",
                                signature.len(), r.value(), s.value())).into());
                    }

                    ed25519::verify(&q.value()[1..], digest, &signature)?
                },
                _ => return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },
            (ECDSA, PublicKey::ECDSA{ curve, q }, Signature::ECDSA { s, r }) =>
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
                "unsupported combination of algorithm {}, key {} and \
                 signature {:?}.",
                sig.pk_algo(), self.pk_algo(), sig.mpis())).into()),
        };

        if ok {
            Ok(())
        } else {
            Err(Error::ManipulatedMessage.into())
        }
    }
}
