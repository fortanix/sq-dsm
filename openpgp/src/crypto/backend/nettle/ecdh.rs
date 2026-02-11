//! Elliptic Curve Diffie-Hellman.

use nettle::{ecc, ecdh, random::Yarrow};

use crate::{Error, Result};
use crate::crypto::SessionKey;
use crate::crypto::ecdh::{encrypt_wrap, decrypt_unwrap};
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{MPI, PublicKey, SecretKeyMaterial, Ciphertext};
use crate::packet::{key, Key};
use crate::types::Curve;

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(recipient: &Key<key::PublicParts, R>,
                  session_key: &SessionKey)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    let mut rng = Yarrow::default();

    if let PublicKey::ECDH {
        ref curve, ref q,..
    } = recipient.mpis() {
        match curve {
            Curve::Cv25519 =>
                Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

            Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
                // Obtain the authenticated recipient public key R and
                // generate an ephemeral private key v.

                // Note: ecc::Point and ecc::Scalar are cleaned up by
                // nettle.
                let (Rx, Ry) = q.decode_point(curve)?;
                let (R, v, field_sz) = match curve {
                    Curve::NistP256 => {
                        let R = ecc::Point::new::<ecc::Secp256r1>(Rx, Ry)?;
                        let v =
                            ecc::Scalar::new_random::<ecc::Secp256r1, _>(&mut rng);
                        let field_sz = 256;

                        (R, v, field_sz)
                    }
                    Curve::NistP384 => {
                        let R = ecc::Point::new::<ecc::Secp384r1>(Rx, Ry)?;
                        let v =
                            ecc::Scalar::new_random::<ecc::Secp384r1, _>(&mut rng);
                        let field_sz = 384;

                        (R, v, field_sz)
                    }
                    Curve::NistP521 => {
                        let R = ecc::Point::new::<ecc::Secp521r1>(Rx, Ry)?;
                        let v =
                            ecc::Scalar::new_random::<ecc::Secp521r1, _>(&mut rng);
                        let field_sz = 521;

                        (R, v, field_sz)
                    }
                    _ => unreachable!(),
                };

                // Compute the public key.
                let VB = ecdh::point_mul_g(&v);
                let (VBx, VBy) = VB.as_bytes();
                let VB = MPI::new_point(&VBx, &VBy, field_sz);

                // Compute the shared point S = vR;
                let S = ecdh::point_mul(&v, &R)?;

                // Get the X coordinate, safely dispose of Y.
                let (Sx, Sy) = S.as_bytes();
                let _ = Protected::from(Sy); // Just a precaution.

                // Zero-pad to the size of the underlying field,
                // rounded to the next byte.
                let mut Sx = Vec::from(Sx);
                while Sx.len() < (field_sz + 7) / 8 {
                    Sx.insert(0, 0);
                }

                encrypt_wrap(recipient.role_as_subordinate(),
                             session_key, VB, &Sx.into())
            }

            // Not implemented in Nettle
            Curve::BrainpoolP256 | Curve::BrainpoolP384 | Curve::BrainpoolP512 =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

            // N/A
            Curve::Unknown(_) | Curve::Ed25519 =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
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

                Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
                    // Get the public part V of the ephemeral key and
                    // compute the shared point S = rV = rvG, where (r, R)
                    // is the recipient's key pair.
                    let (Vx, Vy) = e.decode_point(curve)?;
                    let (V, r, field_sz) = match curve {
                        Curve::NistP256 => {
                            let V =
                                ecc::Point::new::<ecc::Secp256r1>(Vx, Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp256r1>(scalar.value())?;

                            (V, r, 256)
                        }
                        Curve::NistP384 => {
                            let V =
                                ecc::Point::new::<ecc::Secp384r1>(Vx, Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp384r1>(scalar.value())?;

                            (V, r, 384)
                        }
                        Curve::NistP521 => {
                            let V =
                                ecc::Point::new::<ecc::Secp521r1>(Vx, Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp521r1>(scalar.value())?;

                            (V, r, 521)
                        }
                        _ => unreachable!(),
                    };
                    let S = ecdh::point_mul(&r, &V)?;

                    // Get the X coordinate, safely dispose of Y.
                    let (Sx, Sy) = S.as_bytes();
                    let _ = Protected::from(Sy); // Just a precaution.

                    // Zero-pad to the size of the underlying field,
                    // rounded to the next byte.
                    let mut Sx = Vec::from(Sx);
                    while Sx.len() < (field_sz + 7) / 8 {
                        Sx.insert(0, 0);
                    }

                    Sx.into()
                }

                // Not implemented in Nettle
                Curve::BrainpoolP256 | Curve::BrainpoolP384 | Curve::BrainpoolP512 =>
                    return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

                // N/A
                Curve::Unknown(_) | Curve::Ed25519 =>
                    return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            };

            decrypt_unwrap(recipient.role_as_unspecified(), &S, ciphertext,
                           plaintext_len)
        }

        _ =>
            Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    }
}
