//! Implementation of asymmetric cryptography using Windows CNG API.
#![allow(unused_variables)]

use std::time::SystemTime;

use crate::Result;

use crate::crypto::asymmetric::{Decryptor, KeyPair, Signer};
use crate::crypto::mpi;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{self, key, Key};
use crate::types::SymmetricAlgorithm;
use crate::types::{Curve, HashAlgorithm};

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        unimplemented!()
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
        unimplemented!()
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
    /// will be used.  The key will have it's creation date set to
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
        unimplemented!()
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        unimplemented!()
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
        unimplemented!()
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        unimplemented!()
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true`
    /// and `curve == Cv25519` will produce an error.  Similar for
    /// `for_signing == false` and `curve == Ed25519`.
    /// signing/encryption
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        unimplemented!()
    }
}
