//! Elliptic Curve Diffie-Hellman.

use nettle::{curve25519, ecc, ecdh, random::Yarrow};

use crate::{Error, Result};
use crate::crypto::SessionKey;
use crate::crypto::ecdh::{aes_key_wrap, aes_key_unwrap, kdf, pkcs5_pad, pkcs5_unpad};
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{MPI, PublicKey, SecretKeyMaterial, Ciphertext};
use crate::packet::{key, Key};
use crate::types::{Curve, HashAlgorithm, SymmetricAlgorithm, PublicKeyAlgorithm};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(recipient: &Key<key::PublicParts, R>,
                  session_key: &SessionKey)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    let mut rng = Yarrow::default();

    if let &PublicKey::ECDH {
        ref curve, ref q,..
    } = recipient.mpis() {
        match curve {
            Curve::Cv25519 => {
                // Obtain the authenticated recipient public key R
                let R = q.decode_point(curve)?.0;

                // Generate an ephemeral key pair {v, V=vG}
                let v: Protected =
                    curve25519::private_key(&mut rng).into();

                // Compute the public key.  We need to add an encoding
                // octet in front of the key.
                let mut VB = [0x40; 1 + curve25519::CURVE25519_SIZE];
                curve25519::mul_g(&mut VB[1..], &v)
                    .expect("buffers are of the wrong size");
                let VB = MPI::new(&VB);

                // Compute the shared point S = vR;
                let mut S: Protected =
                    vec![0; curve25519::CURVE25519_SIZE].into();
                curve25519::mul(&mut S, &v, R)
                    .expect("buffers are of the wrong size");

                encrypt_shared(recipient, session_key, VB, &S)
            }
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
                let VB = MPI::new_weierstrass(&VBx, &VBy, field_sz);

                // Compute the shared point S = vR;
                let S = ecdh::point_mul(&v, &R)?;

                // Get the X coordinate, safely dispose of Y.
                let (Sx, Sy) = S.as_bytes();
                Protected::from(Sy); // Just a precaution.

                // Zero-pad to the size of the underlying field,
                // rounded to the next byte.
                let mut Sx = Vec::from(Sx);
                while Sx.len() < (field_sz + 7) / 8 {
                    Sx.insert(0, 0);
                }

                encrypt_shared(recipient, session_key, VB, &Sx.into())
            }

            // Not implemented in Nettle
            Curve::BrainpoolP256 | Curve::BrainpoolP512 =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

            // N/A
            Curve::Unknown(_) | Curve::Ed25519 =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

            Curve::__Nonexhaustive => unreachable!(),
        }
    } else {
        Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into())
    }
}

/// Wraps a session key.
///
/// After using Elliptic Curve Diffie-Hellman to compute a shared
/// secret, this function deterministically encrypts the given session
/// key.
///
/// `VB` is the ephemeral public key (with 0x40 prefix), `S` is the
/// shared Diffie-Hellman secret.
#[allow(non_snake_case)]
pub fn encrypt_shared<R>(recipient: &Key<key::PublicParts, R>,
                         session_key: &SessionKey, VB: MPI,
                         S: &Protected)
    -> Result<Ciphertext>
    where R: key::KeyRole
{
    match recipient.mpis() {
        &PublicKey::ECDH{ ref curve, ref hash, ref sym,.. } => {
            // m = sym_alg_ID || session key || checksum || pkcs5_padding;
            let mut m = Vec::with_capacity(40);
            m.extend_from_slice(session_key);
            let m = pkcs5_pad(m.into(), 40);
            // Note: We always pad up to 40 bytes to obfuscate the
            // length of the symmetric key.

            // Compute KDF input.
            let param = make_param(recipient, curve, hash, sym);

            // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
            // Compute Z = KDF( S, Z_len, Param );
            #[allow(non_snake_case)]
            let Z = kdf(S, sym.key_size()?, *hash, &param)?;

            // Compute C = AESKeyWrap( Z, m ) as per [RFC3394]
            #[allow(non_snake_case)]
            let C = aes_key_wrap(*sym, &Z, &m)?;

            // Output (MPI(VB) || len(C) || C).
            Ok(Ciphertext::ECDH {
                e: VB,
                key: C.into_boxed_slice(),
            })
        }

        _ =>
            Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    }
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn decrypt<R>(recipient: &Key<key::PublicParts, R>,
                  recipient_sec: &SecretKeyMaterial,
                  ciphertext: &Ciphertext)
    -> Result<SessionKey>
    where R: key::KeyRole
{
    match (recipient.mpis(), recipient_sec, ciphertext) {
        (PublicKey::ECDH { ref curve, ..},
         SecretKeyMaterial::ECDH { ref scalar, },
         Ciphertext::ECDH { ref e, .. }) =>
        {
            let S: Protected = match curve {
                Curve::Cv25519 => {
                    // Get the public part V of the ephemeral key.
                    let V = e.decode_point(curve)?.0;

                    // Nettle expects the private key to be exactly
                    // CURVE25519_SIZE bytes long but OpenPGP allows leading
                    // zeros to be stripped.
                    // Padding has to be unconditional; otherwise we have a
                    // secret-dependent branch.
                    //
                    // Reverse the scalar.  See
                    // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
                    let missing = curve25519::CURVE25519_SIZE
                        .saturating_sub(scalar.value().len());
                    let mut r = [0u8; curve25519::CURVE25519_SIZE];

                    r[missing..].copy_from_slice(scalar.value());
                    r.reverse();

                    // Compute the shared point S = rV = rvG, where (r, R)
                    // is the recipient's key pair.
                    let mut S: Protected =
                        vec![0; curve25519::CURVE25519_SIZE].into();
                    let res = curve25519::mul(&mut S, &r[..], V);

                    unsafe {
                        memsec::memzero(r.as_mut_ptr(),
                        curve25519::CURVE25519_SIZE);
                    }
                    res.expect("buffers are of the wrong size");
                    S
                }

                Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
                    // Get the public part V of the ephemeral key and
                    // compute the shared point S = rV = rvG, where (r, R)
                    // is the recipient's key pair.
                    let (Vx, Vy) = e.decode_point(curve)?;
                    let (V, r, field_sz) = match curve {
                        Curve::NistP256 => {
                            let V =
                                ecc::Point::new::<ecc::Secp256r1>(&Vx, &Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp256r1>(scalar.value())?;

                            (V, r, 256)
                        }
                        Curve::NistP384 => {
                            let V =
                                ecc::Point::new::<ecc::Secp384r1>(&Vx, &Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp384r1>(scalar.value())?;

                            (V, r, 384)
                        }
                        Curve::NistP521 => {
                            let V =
                                ecc::Point::new::<ecc::Secp521r1>(&Vx, &Vy)?;
                            let r =
                                ecc::Scalar::new::<ecc::Secp521r1>(scalar.value())?;

                            (V, r, 521)
                        }
                        _ => unreachable!(),
                    };
                    let S = ecdh::point_mul(&r, &V)?;

                    // Get the X coordinate, safely dispose of Y.
                    let (Sx, Sy) = S.as_bytes();
                    Protected::from(Sy); // Just a precaution.

                    // Zero-pad to the size of the underlying field,
                    // rounded to the next byte.
                    let mut Sx = Vec::from(Sx);
                    while Sx.len() < (field_sz + 7) / 8 {
                        Sx.insert(0, 0);
                    }

                    Sx.into()
                }

                _ => {
                    return Err(Error::UnsupportedEllipticCurve(curve.clone()).into());
                }
            };

            decrypt_shared(recipient, &S, ciphertext)
        }

        _ =>
            Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    }
}

/// Unwraps a session key.
///
/// After using Elliptic Curve Diffie-Hellman to compute the shared
/// secret, this function decrypts the given encrypted session key.
///
/// `recipient` is the message receiver's public key, `S` is the
/// shared Diffie-Hellman secret used to encrypt `ciphertext`.
#[allow(non_snake_case)]
pub fn decrypt_shared<R>(recipient: &Key<key::PublicParts, R>,
                         S: &Protected,
                         ciphertext: &Ciphertext)
    -> Result<SessionKey>
    where R: key::KeyRole
{
    match (recipient.mpis(), ciphertext) {
        (PublicKey::ECDH { ref curve, ref hash, ref sym, ..},
         Ciphertext::ECDH { ref key, .. }) => {
            // Compute KDF input.
            let param = make_param(recipient, curve, hash, sym);

            // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
            // Compute Z = KDF( S, Z_len, Param );
            #[allow(non_snake_case)]
            let Z = kdf(&S, sym.key_size()?, *hash, &param)?;

            // Compute m = AESKeyUnwrap( Z, C ) as per [RFC3394]
            let m = aes_key_unwrap(*sym, &Z, key)?;
            let cipher = SymmetricAlgorithm::from(m[0]);
            let m = pkcs5_unpad(m, 1 + cipher.key_size()? + 2)?;

            Ok(m.into())
        },

        _ =>
            Err(Error::InvalidArgument(
                "Expected an ECDH key and ciphertext".into()).into()),
    }
}

fn make_param<P, R>(recipient: &Key<P, R>,
              curve: &Curve, hash: &HashAlgorithm,
              sym: &SymmetricAlgorithm)
    -> Vec<u8>
    where P: key::KeyParts,
          R: key::KeyRole
{
    // Param = curve_OID_len || curve_OID ||
    // public_key_alg_ID || 03 || 01 || KDF_hash_ID ||
    // KEK_alg_ID for AESKeyWrap || "Anonymous Sender    " ||
    // recipient_fingerprint;
    let fp = recipient.fingerprint();

    let mut param = Vec::with_capacity(
        1 + curve.oid().len()        // Length and Curve OID,
            + 1                      // Public key algorithm ID,
            + 4                      // KDF parameters,
            + 20                     // "Anonymous Sender    ",
            + fp.as_bytes().len());  // Recipients key fingerprint.

    param.push(curve.oid().len() as u8);
    param.extend_from_slice(curve.oid());
    param.push(PublicKeyAlgorithm::ECDH.into());
    param.push(3);
    param.push(1);
    param.push((*hash).into());
    param.push((*sym).into());
    param.extend_from_slice(b"Anonymous Sender    ");
    param.extend_from_slice(fp.as_bytes());
    assert_eq!(param.len(),
               1 + curve.oid().len()    // Length and Curve OID,
               + 1                      // Public key algorithm ID,
               + 4                      // KDF parameters,
               + 20                     // "Anonymous Sender    ",
               + fp.as_bytes().len());  // Recipients key fingerprint.

    param
}
