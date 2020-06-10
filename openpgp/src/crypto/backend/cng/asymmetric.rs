//! Implementation of asymmetric cryptography using Windows CNG API.
#![allow(unused_variables)]

use std::time::SystemTime;
use std::convert::TryInto;

use crate::{Error, Result};

use crate::crypto::asymmetric::{Decryptor, KeyPair, Signer};
use crate::crypto::mem::Protected;
use crate::crypto::mpi;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{self, key, Key};
use crate::types::{PublicKeyAlgorithm, SymmetricAlgorithm};
use crate::types::{Curve, HashAlgorithm};

use num_bigint_dig::{traits::ModInverse, BigInt, BigUint};
use win_crypto_ng as cng;

const CURVE25519_SIZE: usize = 32;

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::{AsymmetricKey, Private, Rsa};
        use cng::asymmetric::signature::{Signer, SignaturePadding};
        use cng::key_blob::RsaKeyPrivatePayload;
        use cng::key_blob::EccKeyPrivatePayload;
        use cng::asymmetric::ecc::NamedCurve;

        #[allow(deprecated)]
        self.secret().map(|secret| {
            Ok(match (self.public().pk_algo(), self.public().mpis(), secret) {
                (PublicKeyAlgorithm::RSAEncryptSign,
                    &mpi::PublicKey::RSA { ref e, ref n },
                    &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) |
                (PublicKeyAlgorithm::RSASign,
                &mpi::PublicKey::RSA { ref e, ref n },
                &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) => {
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                    let key = AsymmetricKey::<Rsa, Private>::import_from_parts(
                        &provider,
                        &RsaKeyPrivatePayload {
                            modulus: n.value(),
                            pub_exp: e.value(),
                            prime1: p.value(),
                            prime2: q.value(),
                        }
                    )?;

                    // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                    // to verify the signature, we need to encode the
                    // signature data in a PKCS1-v1.5 packet.
                    //
                    //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                    //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                    let hash = hash_algo.try_into()?;
                    let padding = SignaturePadding::pkcs1(hash);
                    let sig = key.sign(digest, Some(padding))?;

                    mpi::Signature::RSA { s: mpi::MPI::new(&*sig) }
                },
                (PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { curve, q },
                mpi::SecretKeyMaterial::ECDSA { scalar }) =>
                {
                    let (x, y) = q.decode_point(curve)?;

                    // It's expected for the private key to be exactly 32/48/66
                    // (respective curve field size) bytes long but OpenPGP
                    // allows leading zeros to be stripped.
                    // Padding has to be unconditional; otherwise we have a
                    // secret-dependent branch.
                    let curve_bits = curve.bits().ok_or_else(||
                        Error::UnsupportedEllipticCurve(curve.clone())
                    )?;
                    let curve_bytes = (curve_bits + 7) / 8;
                    let mut secret = Protected::from(vec![0u8; curve_bytes]);
                    let missing = curve_bytes.saturating_sub(scalar.value().len());
                    secret.as_mut()[missing..].copy_from_slice(scalar.value());

                    use cng::asymmetric::{ecc::{NistP256, NistP384, NistP521}, Ecdsa};

                    // TODO: Improve CNG public API
                    let sig = match curve {
                        Curve::NistP256 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP256>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        Curve::NistP384 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP384>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        Curve::NistP521 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP521>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        _ => return Err(
                            Error::UnsupportedEllipticCurve(curve.clone()).into()),
                    };

                    // CNG outputs a P1363 formatted signature - r || s
                    let (r, s) = sig.split_at(sig.len() / 2);
                    mpi::Signature::ECDSA {
                        r: mpi::MPI::new(r),
                        s: mpi::MPI::new(s),
                    }
                },
                _ => todo!()
            })
        })
    }
}

impl Decryptor for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        unimplemented!()
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub fn encrypt(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        unimplemented!()
    }

    /// Verifies the given signature.
    pub fn verify(&self, sig: &packet::Signature, digest: &[u8]) -> Result<()> {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::{AsymmetricKey, Public, Rsa};
        use cng::asymmetric::ecc::NamedCurve;
        use cng::asymmetric::signature::{Verifier, SignaturePadding};
        use cng::key_blob::RsaKeyPublicPayload;

        use PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        let ok = match (sig.pk_algo(), self.mpis(), sig.mpis()) {
            (RSASign,        mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) |
            (RSAEncryptSign, mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                // CNG accepts only full-size signatures. Since for RSA it's a
                // big-endian number, just left-pad with zeroes as necessary.
                let sig_diff = n.value().len().saturating_sub(s.value().len());
                let mut _s: Vec<u8> = vec![];
                let s = if sig_diff > 0 {
                    _s = [&vec![0u8; sig_diff], s.value()].concat();
                    &_s
                } else {
                    s.value()
                };

                // CNG supports RSA keys that are at least 512 bit long.
                // Since it just checks the MPI length rather than data itself,
                // just pad it with zeroes as necessary.
                let mut _n: Vec<u8> = vec![];
                let missing_size = 512usize.saturating_sub(n.value().len());
                let n = if missing_size > 0 {
                    _n = [&vec![0u8; missing_size], n.value()].concat();
                    &_n
                } else {
                    n.value()
                };

                let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                let key = AsymmetricKey::<Rsa, Public>::import_from_parts(
                    &provider,
                    &RsaKeyPublicPayload {
                        modulus: n,
                        pub_exp: e.value(),
                    }
                )?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                let hash = sig.hash_algo().try_into()?;
                let padding = SignaturePadding::pkcs1(hash);

                key.verify(digest, s, Some(padding)).map(|_| true)?
            },
            (DSA, mpi:: PublicKey::DSA { y, p, q, g }, mpi::Signature::DSA { s, r }) => todo!(),
            (ECDSA, mpi::PublicKey::ECDSA { curve, q }, mpi::Signature::ECDSA { s, r }) =>
            {
                let (x, y) = q.decode_point(curve)?;
                // CNG expects full-sized signatures
                let field_sz = x.len();
                let r = [&vec![0u8; field_sz - r.value().len()], r.value()].concat();
                let s = [&vec![0u8; field_sz - s.value().len()], s.value()].concat();
                let signature = [r, s].concat();

                use cng::key_blob::EccKeyPublicPayload;
                use cng::asymmetric::{ecc::{NistP256, NistP384, NistP521}, Ecdsa};

                // TODO: Improve CNG public API
                match curve {
                    Curve::NistP256 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP256>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    Curve::NistP384 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP384>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    Curve::NistP521 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP521>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    _ => return Err(
                        Error::UnsupportedEllipticCurve(curve.clone()).into()),
                }
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

impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have its creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_cv25519<H, S, T>(
        private_key: &[u8],
        hash: H,
        sym: S,
        ctime: T,
    ) -> Result<Self>
    where
        H: Into<Option<HashAlgorithm>>,
        S: Into<Option<SymmetricAlgorithm>>,
        T: Into<Option<SystemTime>>,
    {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, Ecdh, Private};
        use cng::asymmetric::{AsymmetricKey, Export};
        use cng::asymmetric::ecc::{Curve25519, NamedCurve};

        let provider = AsymmetricAlgorithm::open(
            AsymmetricAlgorithmId::Ecdh(NamedCurve::Curve25519)
        )?;
        let key = AsymmetricKey::<Ecdh<Curve25519>, Private>::import_from_parts(
            &provider,
            private_key
        )?;
        let blob = key.export()?;

        // Mark MPI as compressed point with 0x40 prefix. See
        // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
        let mut public = [0u8; 1 + CURVE25519_SIZE];
        public[0] = 0x40;
        &mut public[1..].copy_from_slice(blob.x());

        // Reverse the scalar.  See
        // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
        let mut private = blob.d().to_vec();
        private.reverse();

        Self::with_secret(
            ctime.into().unwrap_or_else(SystemTime::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or(HashAlgorithm::SHA512),
                sym: sym.into().unwrap_or(SymmetricAlgorithm::AES256),
                q: mpi::MPI::new(&public),
            },
            mpi::SecretKeyMaterial::ECDH { scalar: private.into() }.into()
        )
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The key will have it's creation date set to `ctime` or the current time
    /// if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // CNG doesn't support Ed25519 at all
        Err(Error::UnsupportedEllipticCurve(Curve::Ed25519).into())
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // RFC 4880: `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };

        // CNG can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let big_d = BigUint::from_bytes_be(d);
        let big_phi = (big_p.clone() - 1u32) * (big_q.clone() - 1u32);
        let e = big_d.mod_inverse(big_phi) // e ≡ d⁻¹ (mod 𝜙)
            .and_then(|x: BigInt| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `d` and `(p-1)(q-1)` aren't coprime".into()))?;

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x: BigInt| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(SystemTime::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(&e.to_bytes_be()),
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

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        use win_crypto_ng::asymmetric::{AsymmetricKey, Rsa};

        let blob = AsymmetricKey::builder(Rsa)
            .key_bits(bits as u32)
            .build()?
            .export_full()?;

        let public = mpi::PublicKey::RSA {
            e: mpi::MPI::new(blob.pub_exp()).into(),
            n: mpi::MPI::new(blob.modulus()).into(),
        };

        let p = mpi::MPI::new(blob.prime1());
        let q = mpi::MPI::new(blob.prime2());
        // RSA prime generation in CNG returns them in arbitrary order but
        // RFC 4880 expects `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };
        // CNG `coeff` is `prime1`^-1 mod `prime2` so adjust for possible p,q reorder
        let big_p = BigUint::from_bytes_be(p.value());
        let big_q = BigUint::from_bytes_be(q.value());
        let u = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x: BigInt| x.to_biguint())
            .expect("CNG to generate a valid RSA key (where p, q are coprime)");

        let private = mpi::SecretKeyMaterial::RSA {
            p: p.into(),
            q: q.into(),
            d: mpi::MPI::new(blob.priv_exp()).into(),
            u: mpi::MPI::new(&u.to_bytes_be()).into(),
        };

        Self::with_secret(
            SystemTime::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public,
            private.into()
        )
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true`
    /// and `curve == Cv25519` will produce an error.  Similar for
    /// `for_signing == false` and `curve == Ed25519`.
    /// signing/encryption
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        // CNG doesn't support Ed25519 at all
        if (for_signing && curve == Curve::Cv25519) || curve == Curve::Ed25519 {
            return Err(Error::UnsupportedEllipticCurve(curve).into());
        }

        use crate::PublicKeyAlgorithm::*;

        use cng::asymmetric::{ecc, Export};
        use cng::asymmetric::{AsymmetricKey, AsymmetricAlgorithmId, Ecdh};

        let (algo, public, private) = match curve {
            Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
                let (cng_curve, hash) = match curve {
                    Curve::NistP256 => (ecc::NamedCurve::NistP256, HashAlgorithm::SHA256),
                    Curve::NistP384 => (ecc::NamedCurve::NistP384, HashAlgorithm::SHA384),
                    Curve::NistP521 => (ecc::NamedCurve::NistP521, HashAlgorithm::SHA512),
                    _ => unreachable!()
                };

                let ecc_algo = if for_signing {
                    AsymmetricAlgorithmId::Ecdsa(cng_curve)
                } else {
                    AsymmetricAlgorithmId::Ecdh(cng_curve)
                };

                let blob = AsymmetricKey::builder(ecc_algo).build()?.export()?;
                let blob = match blob.try_into::<cng::key_blob::EccKeyPrivateBlob>() {
                    Ok(blob) => blob,
                    // Dynamic algorithm specified is either ECDSA or ECDH so
                    // exported blob should be of appropriate type
                    Err(..) => unreachable!()
                };
                let field_sz = cng_curve.key_bits() as usize;

                let q = mpi::MPI::new_point(blob.x(), blob.y(), field_sz);
                let scalar = mpi::MPI::new(blob.d());

                if for_signing {
                    (
                        ECDSA,
                        mpi::PublicKey::ECDSA { curve, q },
                        mpi::SecretKeyMaterial::ECDSA { scalar: scalar.into() },
                    )
                } else {
                    let sym = SymmetricAlgorithm::AES256;
                    (
                        ECDH,
                        mpi::PublicKey::ECDH { curve, q, hash, sym },
                        mpi::SecretKeyMaterial::ECDH { scalar: scalar.into() },
                    )
                }
            },
            Curve::Cv25519 => {
                debug_assert!(!for_signing);
                let blob = AsymmetricKey::builder(Ecdh(ecc::Curve25519)).build()?.export()?;

                // Mark MPI as compressed point with 0x40 prefix. See
                // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
                let mut public = [0u8; 1 + CURVE25519_SIZE];
                public[0] = 0x40;
                &mut public[1..].copy_from_slice(blob.x());

                // Reverse the scalar.  See
                // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
                let mut private: Protected = blob.d().into();
                private.reverse();

                (
                    ECDH,
                    mpi::PublicKey::ECDH {
                        curve,
                        q: mpi::MPI::new(&public),
                        hash: HashAlgorithm::SHA256,
                        sym: SymmetricAlgorithm::AES256,
                    },
                    mpi::SecretKeyMaterial::ECDH { scalar: private.into() }
                )
            },
            // TODO: Support Brainpool curves
            curve => {
                return Err(Error::UnsupportedEllipticCurve(curve).into());
            }
        };

        Self::with_secret(SystemTime::now(), algo, public, private.into())
    }
}
