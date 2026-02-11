//! Elliptic Curve Diffie-Hellman.

use botan::{
    RandomNumberGenerator,
    Privkey,
};

use crate::{
    Error,
    Result,
};
use crate::crypto::SessionKey;
use crate::crypto::ecdh::{encrypt_wrap, decrypt_unwrap};
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{
    MPI,
    PublicKey, SecretKeyMaterial, Ciphertext};
use crate::packet::{key, Key};
use crate::types::Curve;

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(recipient: &Key<key::PublicParts, R>,
                  session_key: &SessionKey)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    let mut rng = RandomNumberGenerator::new_userspace()?;

    if let PublicKey::ECDH {
        ref curve, ref q,..
    } = recipient.mpis() {
        match curve {
            Curve::Cv25519 =>
                Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

            // N/A
            Curve::Unknown(_) =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            Curve::Ed25519 =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

            Curve::NistP256 | Curve::NistP384 | Curve::NistP521 |
            Curve::BrainpoolP256 |
            Curve::BrainpoolP384 |
            Curve::BrainpoolP512 => {
                // Obtain the recipient public key R
                let R = &q.value();

                // Generate an ephemeral key pair {v, V=vG}
                let field_size = curve.field_size()?;
                let v = Privkey::create("ECDH", curve.botan_name()?, &mut rng)?;
                let Vx = v.pubkey()?.get_field("public_x")?;
                let Vy = v.pubkey()?.get_field("public_y")?;

                // Compute the shared point S = vR;
                let S: Protected = v.agree(&R, 32, b"", "Raw")?.into();
                let Sx: Protected = S[..field_size].into();

                encrypt_wrap(recipient.role_as_subordinate(), session_key,
                             MPI::new_point(&Vx.to_bin()?, &Vy.to_bin()?,
                                            field_size * 8),
                             &Sx.into())
            }
        }
    } else {
        Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into())
    }
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
    match (recipient.mpis(), recipient_sec, ciphertext) {
        (PublicKey::ECDH { ref curve, ..},
         SecretKeyMaterial::ECDH { ref scalar, },
         Ciphertext::ECDH { ref e, .. }) =>
        {
            let S: Protected = match curve {
                Curve::Cv25519 => return
                    Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

                // N/A
                Curve::Unknown(_) => return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
                Curve::Ed25519 => return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),


                Curve::NistP256 | Curve::NistP384 | Curve::NistP521 |
                Curve::BrainpoolP256 |
                Curve::BrainpoolP384 |
                Curve::BrainpoolP512 => {
                    // Get the public part V of the ephemeral key.
                    let V = &e.value();

                    // Get our secret key.
                    let r = Privkey::load_ecdh(
                        &botan::MPI::new_from_bytes(scalar.value())?,
                        curve.botan_name()?)?;

                    // Compute the shared point S = rV = rvG, where (r, R)
                    // is the recipient's key pair.
                    r.agree(V, curve.field_size()?, b"", "Raw")?.into()
                },
            };

            decrypt_unwrap(recipient.role_as_unspecified(), &S, ciphertext,
                           plaintext_len)
        }

        _ =>
            Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    }
}
