//! Elliptic Curve Diffie-Hellman.

use std::convert::TryInto;

use p256::elliptic_curve::{
    ecdh::diffie_hellman,
    generic_array::GenericArray as GA,
};

use crate::{Error, Result};
use crate::crypto::SessionKey;
use crate::crypto::mem::Protected;
use crate::crypto::ecdh::{encrypt_wrap, decrypt_unwrap};
use crate::crypto::mpi::{self, Ciphertext, SecretKeyMaterial, MPI};
use crate::packet::{key, Key};
use crate::types::Curve;

use super::GenericArrayExt;

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(recipient: &Key<key::PublicParts, R>,
                  session_key: &SessionKey)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    let (curve, q) = match recipient.mpis() {
        mpi::PublicKey::ECDH { curve, q, .. } => (curve, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    let (VB, shared) = match curve {
        Curve::Cv25519 => return
            Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

        Curve::NistP256 => {
            use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};

            // Decode the recipient's public key.
            let recipient_key = PublicKey::from_sec1_bytes(q.value())?;

            // Generate a keypair and perform Diffie-Hellman.
            let secret = EphemeralSecret::random(
                &mut p256::elliptic_curve::rand_core::OsRng);
            let public = EncodedPoint::from(PublicKey::from(&secret));
            let shared = secret.diffie_hellman(&recipient_key);

            // Encode our public key.
            let VB = MPI::new(public.as_bytes());

            // Encode the shared secret.
            let shared: &[u8] = shared.raw_secret_bytes();
            let shared = Protected::from(shared);

            (VB, shared)
        },

        Curve::NistP384 => {
            use p384::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};

            // Decode the recipient's public key.
            let recipient_key = PublicKey::from_sec1_bytes(q.value())?;

            // Generate a keypair and perform Diffie-Hellman.
            let secret = EphemeralSecret::random(
                &mut p384::elliptic_curve::rand_core::OsRng);
            let public = EncodedPoint::from(PublicKey::from(&secret));
            let shared = secret.diffie_hellman(&recipient_key);

            // Encode our public key.
            let VB = MPI::new(public.as_bytes());

            // Encode the shared secret.
            let shared: &[u8] = shared.raw_secret_bytes();
            let shared = Protected::from(shared);

            (VB, shared)
        },

        Curve::NistP521 => {
            use p521::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};

            // Decode the recipient's public key.
            let recipient_key = PublicKey::from_sec1_bytes(q.value())?;

            // Generate a keypair and perform Diffie-Hellman.
            let secret = EphemeralSecret::random(
                &mut p521::elliptic_curve::rand_core::OsRng);
            let public = EncodedPoint::from(PublicKey::from(&secret));
            let shared = secret.diffie_hellman(&recipient_key);

            // Encode our public key.
            let VB = MPI::new(public.as_bytes());

            // Encode the shared secret.
            let shared: &[u8] = shared.raw_secret_bytes();
            let shared = Protected::from(shared);

            (VB, shared)
        },

        _ =>
            return Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
    };

    encrypt_wrap(recipient.role_as_subordinate(), session_key, VB, &shared)
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn decrypt<R>(recipient: &Key<key::PublicParts, R>,
                  recipient_sec: &SecretKeyMaterial,
                  ciphertext: &Ciphertext,
                  plaintext_len: Option<usize>)
    -> Result<SessionKey>
    where R: key::KeyRole
{
    let (curve, scalar, e) = match (recipient.mpis(), recipient_sec, ciphertext) {
        (mpi::PublicKey::ECDH { ref curve, ..},
        SecretKeyMaterial::ECDH { ref scalar, },
        Ciphertext::ECDH { ref e, .. }) => (curve, scalar, e),
         _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    let S: Protected = match curve {
        Curve::Cv25519 => return
            Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

        Curve::NistP256 => {
            use p256::{SecretKey, PublicKey};
            const NISTP256_SIZE: usize = 32;

            // Get the public part V of the ephemeral key.
            let V = PublicKey::from_sec1_bytes(e.value())?;

            let scalar: [u8; NISTP256_SIZE] =
                scalar.value_padded(NISTP256_SIZE).as_ref().try_into()?;
            let scalar = GA::try_from_slice(&scalar)?;
            let r = SecretKey::from_bytes(&scalar)?;

            let secret = diffie_hellman(r.to_nonzero_scalar(), V.as_affine());
            Vec::from(secret.raw_secret_bytes().as_slice()).into()
        },

        Curve::NistP384 => {
            use p384::{SecretKey, PublicKey};
            const NISTP384_SIZE: usize = 48;

            // Get the public part V of the ephemeral key.
            let V = PublicKey::from_sec1_bytes(e.value())?;

            let scalar: [u8; NISTP384_SIZE] =
                scalar.value_padded(NISTP384_SIZE).as_ref().try_into()?;
            let scalar = GA::try_from_slice(&scalar)?;
            let r = SecretKey::from_bytes(&scalar)?;

            let secret = diffie_hellman(r.to_nonzero_scalar(), V.as_affine());
            Vec::from(secret.raw_secret_bytes().as_slice()).into()
        },

        Curve::NistP521 => {
            use p521::{SecretKey, PublicKey};
            const NISTP521_SIZE: usize = 66;

            // Get the public part V of the ephemeral key.
            let V = PublicKey::from_sec1_bytes(e.value())?;

            let scalar: [u8; NISTP521_SIZE] =
                scalar.value_padded(NISTP521_SIZE).as_ref().try_into()?;
            let scalar = GA::try_from_slice(&scalar)?;
            let r = SecretKey::from_bytes(&scalar)?;

            let secret = diffie_hellman(r.to_nonzero_scalar(), V.as_affine());
            Vec::from(secret.raw_secret_bytes().as_slice()).into()
        },

        _ => {
            return Err(Error::UnsupportedEllipticCurve(curve.clone()).into());
        },
    };

    decrypt_unwrap(recipient.role_as_unspecified(), &S, ciphertext,
                   plaintext_len)
}
