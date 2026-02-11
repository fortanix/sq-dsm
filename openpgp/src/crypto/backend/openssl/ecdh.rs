//! Elliptic Curve Diffie-Hellman.
use std::convert::{TryFrom, TryInto};

use crate::crypto::ecdh::{decrypt_unwrap, encrypt_wrap};
use crate::crypto::mpi;
use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::pkey::PKey;

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<Ciphertext>
where
    R: key::KeyRole,
{
    let (curve, q) = match recipient.mpis() {
        mpi::PublicKey::ECDH { curve, q, .. } => (curve, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };
    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let nid = curve.try_into()?;
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, q.value(), &mut ctx)?;
    let recipient_key = EcKey::from_public_key(&group, &point)?;
    let recipient_key = PKey::<_>::try_from(recipient_key)?;

    let key = EcKey::generate(&group)?;

    let q = mpi::MPI::new(&key.public_key().to_bytes(
        &group,
        PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?);

    let key = PKey::<_>::try_from(key)?;
    let mut deriver = Deriver::new(&key)?;
    deriver.set_peer(&recipient_key)?;

    let secret = deriver.derive_to_vec()?.into();

    encrypt_wrap(recipient.role_as_subordinate(), session_key, q, &secret)
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
    plaintext_len: Option<usize>,
) -> Result<SessionKey>
where
    R: key::KeyRole,
{
    let (curve, scalar, e, q) = match (recipient.mpis(), recipient_sec, ciphertext) {
        (
            mpi::PublicKey::ECDH {
                ref curve, ref q, ..
            },
            SecretKeyMaterial::ECDH { ref scalar },
            Ciphertext::ECDH { ref e, .. },
        ) => (curve, scalar, e, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let nid = curve.try_into()?;
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, e.value(), &mut ctx)?;

    let public_point = EcPoint::from_bytes(&group, q.value(), &mut ctx)?;
    let scalar = BigNum::from_slice(scalar.value())?;
    let key = EcKey::from_private_components(&group, &scalar, &public_point)?;

    let recipient_key = EcKey::from_public_key(&group, &point)?;
    let recipient_key = PKey::<_>::try_from(recipient_key)?;

    let key = PKey::<_>::try_from(key)?;
    let mut deriver = Deriver::new(&key)?;
    deriver.set_peer(&recipient_key)?;
    let secret = deriver.derive_to_vec()?.into();

    decrypt_unwrap(recipient.role_as_unspecified(), &secret, ciphertext,
                   plaintext_len)
}
