use crate::{Error, Result};

use crate::packet::{key, Key};
use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{self, MPI, ProtectedMPI};
use crate::crypto::SessionKey;
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

impl Asymmetric for super::Backend {
    fn supports_algo(_: PublicKeyAlgorithm) -> bool {
        true
    }

    fn supports_curve(_: &Curve) -> bool {
        true
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        Ok((vec![4; 32].into(), [4; 32]))
    }

    fn x25519_derive_public(_: &Protected) -> Result<[u8; 32]> {
        Ok([4; 32])
    }

    fn x25519_shared_point(_: &Protected, _: &[u8; 32])
                           -> Result<Protected> {
        Ok(vec![4; 32].into())
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        Ok((vec![4; 32].into(), [4; 32]))
    }

    fn ed25519_derive_public(_: &Protected) -> Result<[u8; 32]> {
        Ok([4; 32])
    }

    fn ed25519_sign(_: &Protected, _: &[u8; 32], _: &[u8]) -> Result<[u8; 64]> {
        Ok([4; 64])
    }

    fn ed25519_verify(_: &[u8; 32], _: &[u8], _: &[u8; 64]) -> Result<bool> {
        Ok(true)
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        let four = MPI::new(&[4]);
        Ok((four.clone(),
            four.clone(),
            four.clone(),
            four.clone(),
            vec![4].into()))
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        let four = MPI::new(&[4]);
        Ok((four.clone(), four))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        Ok(true)
    }

    fn elgamal_generate_key(p_bits: usize)
                            -> Result<(MPI, MPI, MPI, ProtectedMPI)>
    {
        let four = MPI::new(&[4]);
        Ok((four.clone(),
            four.clone(),
            four.clone(),
            vec![4].into()))
    }
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               _: &mpi::SecretKeyMaterial,
                               _: HashAlgorithm,
                               _: &[u8])
                               -> Result<mpi::Signature>
    {
        Err(Error::InvalidOperation("not implemented".into()).into())
    }

    pub(crate) fn decrypt_backend(&self,
                                  _: &mpi::SecretKeyMaterial,
                                  ciphertext: &mpi::Ciphertext,
                                  _: Option<usize>)
                                  -> Result<SessionKey>
    {
        match ciphertext {
            mpi::Ciphertext::RSA { c }
            | mpi::Ciphertext::ElGamal { c, .. } =>
                Ok(Vec::from(c.value()).into()),
            mpi::Ciphertext::ECDH { key, .. } =>
                Ok(Vec::from(&key[..]).into()),
            _ => Err(Error::InvalidOperation("not implemented".into()).into()),
        }
    }
}


impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt =>
                Ok(mpi::Ciphertext::RSA {
                    c: MPI::new(&data),
                }),
            ElGamalEncrypt | ElGamalEncryptSign =>
                Ok(mpi::Ciphertext::ElGamal {
                    e: MPI::new(&data),
                    c: MPI::new(&data),
                }),
            ECDH =>
                Ok(mpi::Ciphertext::ECDH {
                    e: MPI::new(&data),
                    key: Vec::from(&data[..]).into_boxed_slice(),
                }),
            _ => Err(Error::InvalidOperation("not implemented".into()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(&self, _: &mpi::Signature, _: HashAlgorithm,
                                 _: &[u8]) -> Result<()>
    {
        let ok = true; // XXX maybe we also want to have bad signatures?
        if ok {
            Ok(())
        } else {
            Err(Error::ManipulatedMessage.into())
        }
    }
}

use std::time::SystemTime;
use crate::packet::key::{Key4, SecretParts};

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
        Err(Error::InvalidOperation("not implemented".into()).into())
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        Err(Error::InvalidOperation("not implemented".into()).into())
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
        Err(Error::InvalidOperation("not implemented".into()).into())
    }
}
