//! This module abstracts over in-memory or external secrets for low-level
//! cryptographic operations.
use anyhow::Error;

use sequoia_openpgp::crypto::mpi::{Ciphertext, Signature};
use sequoia_openpgp::crypto::{Decryptor, KeyPair, SessionKey, Signer};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::HashAlgorithm;

use openpgp_sdkms::SdkmsAgent;

/// A Secret can be a private key loaded from memory, or stored externally. It
/// implements the [Decryptor] and [Signer] traits.
///
///   [Decryptor]: ../../crypto/trait.Decryptor.html
///   [Signer]: ../../crypto/trait.Signer.html
pub enum Secret {
    /// A [KeyPair] stored in local memory
    ///
    ///   [KeyPair]: ../../crypto/struct.KeyPair.html
    InMemory(KeyPair),
    Sdkms(SdkmsAgent),
}

impl Signer for Secret {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        match self {
            Secret::InMemory(signer) => signer.public(),
            Secret::Sdkms(signer) => <SdkmsAgent as Signer>::public(signer),
        }
    }

    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Signature, Error> {
        match self {
            Secret::InMemory(signer) => signer.sign(hash, digest),
            Secret::Sdkms(signer) => signer.sign(hash, digest),
        }
    }
}

impl Decryptor for Secret {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        match self {
            Secret::InMemory(decryptor) => decryptor.public(),
            Secret::Sdkms(decryptor) => <SdkmsAgent as Decryptor>::public(decryptor),
        }
    }

    fn decrypt(&mut self, ciphertext: &Ciphertext, plaintext_len: Option<usize>) -> Result<SessionKey, Error> {
        match self {
            Secret::InMemory(decryptor) => decryptor.decrypt(ciphertext, plaintext_len),
            Secret::Sdkms(decryptor) => decryptor.decrypt(ciphertext, plaintext_len),
        }
    }
}
