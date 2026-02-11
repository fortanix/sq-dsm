//! Elliptic Curve Diffie-Hellman.

use crate::{Error, Result};
use crate::crypto::SessionKey;
use crate::crypto::mpi::{MPI, Ciphertext, SecretKeyMaterial};
use crate::packet::{key, Key};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(dead_code)]
pub fn encrypt<R>(recipient: &Key<key::PublicParts, R>,
                  session_key: &SessionKey)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    Ok(Ciphertext::ECDH {
        e: MPI::new(&session_key),
        key: Vec::from(&session_key[..]).into_boxed_slice(),
    })
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(dead_code)]
pub fn decrypt<R>(recipient: &Key<key::PublicParts, R>,
                  recipient_sec: &SecretKeyMaterial,
                  ciphertext: &Ciphertext,
                  plaintext_len: Option<usize>)
    -> Result<SessionKey>
    where R: key::KeyRole
{
    match ciphertext {
        Ciphertext::ECDH { key, .. } => Ok(Vec::from(&key[..]).into()),
        _ => Err(Error::InvalidArgument("not a ecdh ciphertext".into()).into()),
    }
}
