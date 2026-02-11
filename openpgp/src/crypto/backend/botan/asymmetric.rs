//! Hold the implementation of [`Signer`] and [`Decryptor`] for [`KeyPair`].
//!
//! [`Signer`]: super::super::asymmetric::Signer
//! [`Decryptor`]: super::super::asymmetric::Decryptor
//! [`KeyPair`]: super::super::asymmetric::KeyPair

use std::time::SystemTime;

use botan::{
    RandomNumberGenerator,
    Pubkey,
    Privkey,
};

use crate::{
    Error,
    Result,
    crypto::{
        asymmetric::KeyPair,
        backend::interface::Asymmetric,
        mem::Protected,
        mpi::{self, MPI, ProtectedMPI, PublicKey},
        SessionKey,
    },
    packet::{
        key::{self, Key4, SecretParts},
        Key,
    },
    types::{
        Curve,
        HashAlgorithm,
        PublicKeyAlgorithm,
    },
};

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA |
            ElGamalEncrypt | ElGamalEncryptSign
                => true,
            X448 | Ed448 |
            Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        use Curve::*;
        match curve {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519 |
            BrainpoolP256 | BrainpoolP384 | BrainpoolP512
                => true,
            Unknown(_)
                => false,
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let secret = Privkey::create("Curve25519", "", &mut rng)?;
        let mut public = [0u8; 32];
        public.copy_from_slice(&secret.pubkey()?.get_x25519_key()?);
        let secret: Protected = secret.get_x25519_key()?.into();
        Ok((secret, public))
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let secret = Privkey::load_x25519(secret)?;
        Ok(<[u8; 32]>::try_from(&secret.pubkey()?.get_x25519_key()?[..])?)
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        let secret = Privkey::load_x25519(&secret)?;
        Ok(secret.agree(public, 32, b"", "Raw")?.into())
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let secret = Privkey::create("Ed25519", "", &mut rng)?;
        let (public, secret) = secret.get_ed25519_key()?;
        Ok((secret.into(), public.as_slice().try_into()?))
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let secret = Privkey::load_ed25519(secret)?;
        let (public, secret) = secret.get_ed25519_key()?;
        let _ = Protected::from(secret); // Securely dispose.
        Ok(public.as_slice().try_into()?)
    }

    fn ed25519_sign(secret: &Protected, _public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let secret = Privkey::load_ed25519(&secret)?;
        Ok(secret.sign(digest, "", &mut rng)?.as_slice().try_into()?)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        let pk = Pubkey::load_ed25519(public)?;
        Ok(pk.verify(digest, signature, "")?)
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let q_bits = if p_bits <= 1024 { 160 } else { 256 };
        let secret = Privkey::create_dsa(p_bits, q_bits, &mut rng)?;
        let public = secret.pubkey()?;
        Ok((public.get_field("p")?.try_into()?,
            public.get_field("q")?.try_into()?,
            public.get_field("g")?.try_into()?,
            public.get_field("y")?.try_into()?,
            secret.get_field("x")?.try_into()?))
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, _y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let secret = Privkey::load_dsa(&p.try_into()?, &q.try_into()?,
                                       &g.try_into()?, &x.try_into()?)?;
        let size = q.value().len();
        let truncated_digest = &digest[..size.min(digest.len())];
        let sig = secret.sign(truncated_digest, "Raw", &mut rng)?;

        if sig.len() != size * 2 {
            return Err(Error::MalformedMPI(
                format!("Expected signature with length {}, got {}",
                        size * 2, sig.len())).into());
        }

        Ok((MPI::new(&sig[..size]), MPI::new(&sig[size..])))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        // OpenPGP encodes R and S separately, but our cryptographic
        // library expects them to be concatenated.
        let size = q.value().len();
        let mut sig = Vec::with_capacity(2 * size);

        // We need to zero-pad them at the front, because the MPI
        // encoding drops leading zero bytes.
        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }
        sig.extend_from_slice(&r.value_padded(size).map_err(bad)?);
        sig.extend_from_slice(&s.value_padded(size).map_err(bad)?);

        let pk = Pubkey::load_dsa(&p.try_into()?, &q.try_into()?,
                                  &g.try_into()?, &y.try_into()?)?;
        let truncated_digest = &digest[..size.min(digest.len())];
        Ok(pk.verify(truncated_digest, &sig, "Raw")?)
    }

    fn elgamal_generate_key(p_bits: usize)
                            -> Result<(MPI, MPI, MPI, ProtectedMPI)>
    {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let q_bits = if p_bits <= 1024 { 160 } else { 256 };
        let secret = Privkey::create_elgamal(p_bits, q_bits, &mut rng)?;
        let public = secret.pubkey()?;
        Ok((public.get_field("p")?.try_into()?,
            public.get_field("g")?.try_into()?,
            public.get_field("y")?.try_into()?,
            secret.get_field("x")?.try_into()?))
    }
}

// CONFIDENTIALITY: Botan clears the MPIs after use.
impl TryFrom<&ProtectedMPI> for botan::MPI {
    type Error = anyhow::Error;
    fn try_from(mpi: &ProtectedMPI) -> anyhow::Result<botan::MPI> {
        Ok(botan::MPI::new_from_bytes(mpi.value())?)
    }
}

impl TryFrom<&botan::MPI> for ProtectedMPI {
    type Error = anyhow::Error;
    fn try_from(bn: &botan::MPI) -> anyhow::Result<Self> {
        Ok(bn.to_bin()?.into())
    }
}

impl TryFrom<botan::MPI> for ProtectedMPI {
    type Error = anyhow::Error;
    fn try_from(bn: botan::MPI) -> anyhow::Result<Self> {
        Ok(bn.to_bin()?.into())
    }
}

impl TryFrom<&MPI> for botan::MPI {
    type Error = anyhow::Error;
    fn try_from(mpi: &MPI) -> anyhow::Result<botan::MPI> {
        Ok(botan::MPI::new_from_bytes(mpi.value())?)
    }
}

impl TryFrom<&botan::MPI> for MPI {
    type Error = anyhow::Error;
    fn try_from(bn: &botan::MPI) -> anyhow::Result<Self> {
        Ok(bn.to_bin()?.into())
    }
}

impl TryFrom<botan::MPI> for MPI {
    type Error = anyhow::Error;
    fn try_from(bn: botan::MPI) -> anyhow::Result<Self> {
        Ok(bn.to_bin()?.into())
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

        let mut rng = RandomNumberGenerator::new_userspace()?;

        #[allow(deprecated)]
        match (self.public().pk_algo(), self.public().mpis(), secret)
        {
            (RSASign,
             PublicKey::RSA { e, .. },
             mpi::SecretKeyMaterial::RSA { p, q, .. }) |
            (RSAEncryptSign,
             PublicKey::RSA { e, .. },
             mpi::SecretKeyMaterial::RSA { p, q, .. }) => {
                let secret = Privkey::load_rsa(&p.try_into()?, &q.try_into()?,
                                               &e.try_into()?)?;
                let sig = secret.sign(
                    digest,
                    &format!("PKCS1v15(Raw,{})", hash_algo.botan_name()?),
                    &mut rng)?;
                Ok(mpi::Signature::RSA {
                    s: MPI::new(&sig),
                })
            },

            (ECDSA,
             PublicKey::ECDSA { curve, .. },
             mpi::SecretKeyMaterial::ECDSA { scalar }) => {
                let size = curve.field_size()?;
                let secret = Privkey::load_ecdsa(
                    &scalar.try_into()?, curve.botan_name()?)?;
                let sig = secret.sign(digest, "Raw", &mut rng)?;

                if sig.len() != size * 2 {
                    return Err(Error::MalformedMPI(
                        format!("Expected signature with length {}, got {}",
                                size * 2, sig.len())).into());
                }

                Ok(mpi::Signature::ECDSA {
                    r: MPI::new(&sig[..size]),
                    s: MPI::new(&sig[size..]),
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
        fn bad(e: impl ToString) -> anyhow::Error {
            // XXX: Not a great error to return.
            Error::MalformedMessage(e.to_string()).into()
        }

        Ok(match (self.public().mpis(), secret, ciphertext) {
            (PublicKey::RSA { e, .. },
             mpi::SecretKeyMaterial::RSA { p, q, .. },
             mpi::Ciphertext::RSA { c }) => {
                let secret = Privkey::load_rsa(&p.try_into()?, &q.try_into()?,
                                               &e.try_into()?)?;
                secret.decrypt(c.value(), "PKCS1v15")?.into()
            },

            (PublicKey::ElGamal{ p, g, .. },
             mpi::SecretKeyMaterial::ElGamal{ x },
             mpi::Ciphertext::ElGamal{ e, c }) => {
                // OpenPGP encodes E and C separately, but our
                // cryptographic library expects them to be
                // concatenated.
                let size = p.value().len();
                let mut ctxt = Vec::with_capacity(2 * size);

                // We need to zero-pad them at the front, because
                // the MPI encoding drops leading zero bytes.
                ctxt.extend_from_slice(&e.value_padded(size).map_err(bad)?);
                ctxt.extend_from_slice(&c.value_padded(size).map_err(bad)?);

                let secret =
                    Privkey::load_elgamal(&p.try_into()?, &g.try_into()?,
                                          &x.try_into()?)?;
                secret.decrypt(&ctxt, "PKCS1v15")?.into()
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
            RSAEncryptSign |
            RSAEncrypt => if let mpi::PublicKey::RSA { e, n } =
                self.mpis()
            {
                // The ciphertext has the length of the modulus.
                let ciphertext_len = n.value().len();
                if data.len() + 11 > ciphertext_len {
                    return Err(Error::InvalidArgument(
                        "Plaintext data too large".into()).into());
                }

                let mut rng = RandomNumberGenerator::new_userspace()?;
                let pk =
                    Pubkey::load_rsa(&n.try_into()?, &e.try_into()?)?;
                let esk = pk.encrypt(data, "PKCS1v15", &mut rng)?;
                Ok(mpi::Ciphertext::RSA {
                    c: MPI::new(&esk),
                })
            } else {
                Err(Error::MalformedPacket(format!(
                    "Expected RSA public key, got {:?}", self.mpis())).into())
            },

            ElGamalEncryptSign |
            ElGamalEncrypt => if let mpi::PublicKey::ElGamal { p, g, y } =
                self.mpis()
            {
                // OpenPGP encodes E and C separately, but our
                // cryptographic library concatenates them.
                let size = p.value().len();

                let mut rng = RandomNumberGenerator::new_userspace()?;
                let pk =
                    Pubkey::load_elgamal(&p.try_into()?, &g.try_into()?,
                                         &y.try_into()?)?;
                let esk = pk.encrypt(data, "PKCS1v15", &mut rng)?;

                if esk.len() != size * 2 {
                    return Err(Error::MalformedMPI(
                        format!("Expected ciphertext with length {}, got {}",
                                size * 2, esk.len())).into());
                }

                Ok(mpi::Ciphertext::ElGamal {
                    e: MPI::new(&esk[..size]),
                    c: MPI::new(&esk[size..]),
                })
            } else {
                Err(Error::MalformedPacket(format!(
                    "Expected ElGamal public key, got {:?}", self.mpis())).into())
            },

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            X25519 | X448 |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()>
    {
        use crate::crypto::mpi::Signature;

        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }

        let ok = match (self.mpis(), sig) {
            (PublicKey::RSA { e, n }, Signature::RSA { s }) => {
                let pk = Pubkey::load_rsa(&n.try_into()?, &e.try_into()?)?;
                pk.verify(digest, s.value(),
                          &format!("PKCS1v15(Raw,{})", hash_algo.botan_name()?))?
            },

            (PublicKey::ECDSA { curve, q }, Signature::ECDSA { s, r }) =>
            {
                // OpenPGP encodes R and S separately, but our
                // cryptographic library expects them to be
                // concatenated.
                let size = curve.field_size()?;
                let mut sig = Vec::with_capacity(2 * size);

                // We need to zero-pad them at the front, because
                // the MPI encoding drops leading zero bytes.
                sig.extend_from_slice(&r.value_padded(size).map_err(bad)?);
                sig.extend_from_slice(&s.value_padded(size).map_err(bad)?);

                let (x, y) = q.decode_point(curve)?;
                let pk = Pubkey::load_ecdsa(&botan::MPI::new_from_bytes(&x)?,
                                            &botan::MPI::new_from_bytes(&y)?,
                                            curve.botan_name()?)?;
                pk.verify(digest, &sig, "Raw")?
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
        let d = botan::MPI::new_from_bytes(d)?;
        let p = botan::MPI::new_from_bytes(p)?;
        let q = botan::MPI::new_from_bytes(q)?;

        // Compute e ≡ d⁻¹ (mod 𝜙).
        let phi = p.mp_sub_u32(1)?.mp_mul(&q.mp_sub_u32(1)?)?;
        let e = botan::MPI::modular_inverse(&d, &phi)?;

        let secret = Privkey::load_rsa(&p.try_into()?, &q.try_into()?,
                                       &e.try_into()?)?;

        let (public, secret) = rsa_rfc4880(secret)?;
        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            public, secret.into())
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let secret = Privkey::create("RSA", &format!("{}", bits), &mut rng)?;

        let (public, secret) = rsa_rfc4880(secret)?;
        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public, secret.into())
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
        let mut rng = RandomNumberGenerator::new_userspace()?;
        let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
        let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);
        let field_sz_bits = curve.bits()?;

        match (curve, for_signing) {
            (Curve::Ed25519, true) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::Cv25519, false) =>
                unreachable!("handled in Key4::generate_ecc"),

            (curve, true) => {
                let secret = Privkey::create("ECDSA", curve.botan_name()?,
                                             &mut rng)?;
                let public = secret.pubkey()?;

                let public_mpis = mpi::PublicKey::ECDSA {
                    curve,
                    q: MPI::new_point(&public.get_field("public_x")?.to_bin()?,
                                      &public.get_field("public_y")?.to_bin()?,
                                      field_sz_bits),
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDSA {
                    scalar: secret.get_field("x")?.try_into()?,
                };

                Ok((PublicKeyAlgorithm::ECDSA, public_mpis, private_mpis))
            },

            (curve, false) => {
                let secret = Privkey::create("ECDH", curve.botan_name()?,
                                             &mut rng)?;
                let public = secret.pubkey()?;

                let public_mpis = mpi::PublicKey::ECDH {
                    curve,
                    q: MPI::new_point(&public.get_field("public_x")?.to_bin()?,
                                      &public.get_field("public_y")?.to_bin()?,
                                      field_sz_bits),
                    hash,
                    sym,
                };
                let private_mpis = mpi::SecretKeyMaterial::ECDH {
                    scalar: secret.get_field("x")?.try_into()?,
                };

                Ok((PublicKeyAlgorithm::ECDH, public_mpis, private_mpis))
            },
        }
    }
}

/// Returns an RSA secret key in the format that OpenPGP
/// expects.
fn rsa_rfc4880(secret: Privkey) -> Result<(mpi::PublicKey,
                                           mpi::SecretKeyMaterial)>
{
    let public = secret.pubkey()?;

    let e = public.get_field("e")?;
    let n = public.get_field("n")?;
    let d = secret.get_field("d")?;
    let p = secret.get_field("p")?;
    let q = secret.get_field("q")?;

    let (p, q, u) =
        if p.compare(&q)? == std::cmp::Ordering::Less {
            let u = botan::MPI::modular_inverse(&p, &q)?;
            (p, q, u)
        } else {
            let c = secret.get_field("c")?;
            (q, p, c)
        };

    let public = mpi::PublicKey::RSA {
        e: e.try_into()?,
        n: n.try_into()?,
    };
    let secret = mpi::SecretKeyMaterial::RSA {
        d: d.try_into()?,
        p: p.try_into()?,
        q: q.try_into()?,
        u: u.try_into()?,
    };

    Ok((public, secret))
}

impl Curve {
    /// Returns the name of the algorithm for use with Botan's
    /// constructor.
    pub(crate) fn botan_name(&self) -> Result<&'static str> {
        use Curve::*;
        match self {
            NistP256 => Ok("secp256r1"),
            NistP384 => Ok("secp384r1"),
            NistP521 => Ok("secp521r1"),
            BrainpoolP256 => Ok("brainpool256r1"),
            BrainpoolP384 => Ok("brainpool384r1"),
            BrainpoolP512 => Ok("brainpool512r1"),
            Ed25519 | // Handled differently.
            Cv25519 | // Handled differently.
            Unknown(_) =>
                Err(Error::UnsupportedEllipticCurve(self.clone()).into()),
        }
    }
}
