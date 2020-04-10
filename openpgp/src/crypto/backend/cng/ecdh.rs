//! Elliptic Curve Diffie-Hellman.
#![allow(unused_variables)]

use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::Result;

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<Ciphertext>
where
    R: key::KeyRole,
{
    unimplemented!()
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
) -> Result<SessionKey>
where
    R: key::KeyRole,
{
    unimplemented!()
}
