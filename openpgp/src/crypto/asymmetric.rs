//! Asymmetric crypt operations.

use crate::packet::{self, key, Key};
use crate::crypto::SessionKey;
use crate::crypto::mpi;
use crate::types::HashAlgorithm;

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
            -> Result<mpi::Signature>;
}

impl Signer for Box<dyn Signer> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature> {
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
    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
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

impl From<KeyPair> for Key<key::SecretParts, key::UnspecifiedRole> {
    fn from(p: KeyPair) -> Self {
        let (key, secret) = (p.public, p.secret);
        key.add_secret(secret.into()).0
    }
}
