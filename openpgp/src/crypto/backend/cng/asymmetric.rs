//! Implementation of asymmetric cryptography using Windows CNG API.
#![allow(unused_variables)]

use std::time::SystemTime;
use std::convert::TryInto;

use crate::{Error, Result};

use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mem::Protected;
use crate::crypto::mpi::{self, MPI, ProtectedMPI};
use crate::crypto::SessionKey;
use crate::crypto::{pad, pad_at_least, pad_truncating};
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{key, Key};
use crate::types::PublicKeyAlgorithm;
use crate::types::{Curve, HashAlgorithm};

use num_bigint_dig::{traits::ModInverse, BigInt, BigUint};
use win_crypto_ng as cng;

impl TryFrom<&Protected> for Box<ed25519_dalek::SigningKey> {
    type Error = anyhow::Error;

    fn try_from(value: &Protected) -> Result<Self> {
        if value.len() != ed25519_dalek::SECRET_KEY_LENGTH {
            return Err(crate::Error::InvalidArgument(
                "Bad Ed25519 secret length".into()).into());
        }
        Ok(Box::new(ed25519_dalek::SigningKey::from_bytes(
            value.as_ref().try_into().map_err(
                |e: std::array::TryFromSliceError| {
                    Error::InvalidKey(e.to_string())
                })?)))
    }
}

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA
                => true,
            X448 | Ed448 |
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        use Curve::*;
        match curve {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP384 | BrainpoolP512 | Unknown(_)
                => false,
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        use cng::asymmetric::{Ecdh, AsymmetricKey, Export};
        use cng::asymmetric::ecc::Curve25519;

        let pair =
            AsymmetricKey::builder(Ecdh(Curve25519)).build()?.export()?;

        let mut public = [0u8; 32];
        public.copy_from_slice(pair.x());

        let mut clamped_secret = pair.d().into();
        Self::x25519_clamp_secret(&mut clamped_secret);

        Ok((clamped_secret, public))
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, Ecdh,
                              Private, AsymmetricKey, Export};
        use cng::asymmetric::ecc::{Curve25519, NamedCurve};

        let provider = AsymmetricAlgorithm::open(
            AsymmetricAlgorithmId::Ecdh(NamedCurve::Curve25519)
        )?;

        let mut clamped_secret = secret.clone();
        Self::x25519_clamp_secret(&mut clamped_secret);
        let key = AsymmetricKey::<Ecdh<Curve25519>, Private>::import_from_parts(
            &provider,
            &clamped_secret,
        )?;
        Ok(<[u8; 32]>::try_from(&key.export()?.x()[..])?)
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        use cng::asymmetric::{Ecdh, AsymmetricKey, Public, Private,
                              AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::agreement::secret_agreement;
        use cng::asymmetric::ecc::{NamedCurve, Curve25519};

        let provider =
            AsymmetricAlgorithm::open(
                AsymmetricAlgorithmId::Ecdh(NamedCurve::Curve25519))?;
        let public =
            AsymmetricKey::<Ecdh<Curve25519>, Public>::import_from_parts(
                &provider,
                public,
            )?;

        let mut clamped_secret = secret.clone();
        Self::x25519_clamp_secret(&mut clamped_secret);
        let secret =
            AsymmetricKey::<Ecdh<Curve25519>, Private>::import_from_parts(
                &provider,
                &clamped_secret,
            )?;

        let shared = secret_agreement(&secret, &public)?;
        let mut shared = Protected::from(shared.derive_raw()?);
        // Returned secret is little-endian, flip it to big-endian
        shared.reverse();
        Ok(shared)
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let mut rng = cng::random::RandomNumberGenerator::system_preferred();
        let pair = ed25519_dalek::SigningKey::generate(&mut rng);
        Ok((pair.to_bytes().into(), pair.verifying_key().to_bytes()))
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        use ed25519_dalek::SigningKey;
        let secret: Box<SigningKey> = secret.try_into()?;
        let public = secret.verifying_key();
        Ok(public.to_bytes())
    }

    fn ed25519_sign(secret: &Protected, _public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        use ed25519_dalek::{SigningKey, Signer};
        let secret: Box<SigningKey> = secret.try_into()?;
        Ok(secret.sign(digest).to_bytes().try_into()?)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        use ed25519_dalek::{VerifyingKey, Verifier, Signature};

        let public = VerifyingKey::from_bytes(public).map_err(|e| {
            Error::InvalidKey(e.to_string())
        })?;
        let signature = signature.as_ref().try_into().map_err(|e: std::array::TryFromSliceError| {
            Error::InvalidArgument(e.to_string())
        })?;

        let signature = Signature::from_bytes(signature);
        Ok(public.verify(digest, &signature).is_ok())
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        // XXX: DSA key generation needs fixes upstream, or at least I
        // didn't figure out how to do that properly, see
        // https://github.com/emgre/win-crypto-ng/issues/47
        let _ = p_bits;
        #[allow(deprecated)]
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::DSA).into())
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        use cng::key_blob::{DsaKeyPrivateV2Payload, DsaKeyPrivateV2Blob};
        use cng::key_blob::{DsaKeyPrivatePayload, DsaKeyPrivateBlob};
        use cng::asymmetric::{
            AsymmetricAlgorithm,
            AsymmetricAlgorithmId,
            AsymmetricKey,
            Dsa,
            DsaPrivateBlob,
            Private,
            signature::Signer,
        };
        use cng::helpers::Blob;

        let y = y.value_padded(p.value().len())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;

        if y.len() > 3072 / 8 {
            return Err(Error::InvalidOperation(
                "DSA keys are supported up to 3072-bits".to_string()).into()
            );
        }

        enum Version { V1, V2 }
        // 1024-bit DSA keys are handled differently
        let version = if y.len() <= 128 { Version::V1 } else { Version::V2 };

        let blob: DsaPrivateBlob = match version {
            Version::V1 => {
                let mut group = [0; 20];
                if let Ok(v) = q.value_padded(group.len()) {
                    group[..].copy_from_slice(&v);
                } else {
                    return Err(Error::InvalidOperation(
                        "DSA keys' group parameter exceeds 160 bits"
                            .to_string()).into());
                }

                DsaPrivateBlob::V1(Blob::<DsaKeyPrivateBlob>::clone_from_parts(
                    &winapi::shared::bcrypt::BCRYPT_DSA_KEY_BLOB {
                        dwMagic: winapi::shared::bcrypt::BCRYPT_DSA_PUBLIC_MAGIC,
                        cbKey: y.len() as u32,
                        Count: [0; 4], // unused
                        Seed: [0; 20], // unused
                        q: group,
                    },
                    &DsaKeyPrivatePayload {
                        modulus: p.value(),
                        generator: g.value(),
                        public: &y,
                        priv_exp: x.value(),
                    },
                ))
            },
            Version::V2 => {
                // https://github.com/dotnet/runtime/blob/67d74fca70d4670ad503e23dba9d6bc8a1b5909e/src/libraries/Common/src/System/Security/Cryptography/DSACng.ImportExport.cs#L276-L282
                let hash = match q.value().len() {
                    20 => 0,
                    32 => 1,
                    64 => 2,
                    _ => return Err(Error::InvalidOperation(
                        "CNG accepts DSA q with length of either length of 20, 32 or 64".into())
                                    .into()),
                };

                // We don't use counter/seed values so set them to 0.
                // CNG pre-checks that the seed is at least |Q| long,
                // so we can't use an empty buffer here.
                let (count, seed) = ([0x0; 4], vec![0x0; q.value().len()]);

                let group_size = std::cmp::min(q.value().len(), 32);
                let key_size = y.len();

                DsaPrivateBlob::V2(Blob::<DsaKeyPrivateV2Blob>::clone_from_parts(
                    &winapi::shared::bcrypt::BCRYPT_DSA_KEY_BLOB_V2 {
                        dwMagic: winapi::shared::bcrypt::BCRYPT_DSA_PRIVATE_MAGIC_V2,
                        Count: count,
                        // Size of the prime number q.
                        // Currently, if the key is less than 128
                        // bits, q is 20 bytes long.
                        // If the key exceeds 256 bits, q is 32 bytes long.
                        cbGroupSize: group_size as u32,
                        cbKey: key_size as u32,
                        cbSeedLength: seed.len() as u32,
                        hashAlgorithm: hash,
                        standardVersion: 1, // FIPS 186-3

                    },
                    &DsaKeyPrivateV2Payload {
                        seed: &seed,
                        group: &q.value_padded(group_size)?,
                        modulus: &p.value_padded(key_size)?,
                        generator: &g.value_padded(key_size)?,
                        public: &y,
                        priv_exp: &x.value_padded(group_size),
                    },
                ))
            },
        };

        use win_crypto_ng::asymmetric::{Import};

        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Dsa)?;
        let pair = AsymmetricKey::<Dsa, Private>::import(
            Dsa,
            &provider,
            blob
        )?;

        // CNG accepts only hash and Q of equal length. Either trim the
        // digest or pad it with zeroes (since it's treated as a
        // big-endian number).
        // See https://github.com/dotnet/runtime/blob/67d74fca70d4670ad503e23dba9d6bc8a1b5909e/src/libraries/Common/src/System/Security/Cryptography/DSACng.SignVerify.cs#L148.
        let digest = pad_truncating(&digest, q.value().len());
        assert_eq!(q.value().len(), digest.len());

        let sig = pair.sign(&digest, None)?;

        // https://tools.ietf.org/html/rfc8032#section-5.1.6
        let (r, s) = sig.split_at(sig.len() / 2);
        Ok((mpi::MPI::new(r), mpi::MPI::new(s)))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        use cng::key_blob::{DsaKeyPublicPayload, DsaKeyPublicBlob};
        use cng::key_blob::{DsaKeyPublicV2Payload, DsaKeyPublicV2Blob};
        use cng::asymmetric::{
            AsymmetricAlgorithm,
            AsymmetricAlgorithmId,
            AsymmetricKey,
            Dsa,
            DsaPublicBlob,
            Public,
            signature::Verifier,
        };
        use cng::helpers::Blob;

        let y = y.value_padded(p.value().len())
            .map_err(|e| Error::InvalidKey(e.to_string()))?;

        if y.len() > 3072 / 8 {
            return Err(Error::InvalidOperation(
                "DSA keys are supported up to 3072-bits".to_string()).into()
            );
        }

        // CNG expects full-sized signatures
        let field_sz = q.value().len();
        let mut signature = vec![0u8; 2 * field_sz];

        // We need to zero-pad them at the front, because
        // the MPI encoding drops leading zero bytes.
        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }
        signature[..field_sz].copy_from_slice(
            &r.value_padded(field_sz).map_err(bad)?);
        signature[field_sz..].copy_from_slice(
            &s.value_padded(field_sz).map_err(bad)?);

        enum Version { V1, V2 }
        // 1024-bit DSA keys are handled differently
        let version = if y.len() <= 128 { Version::V1 } else { Version::V2 };

        let blob: DsaPublicBlob = match version {
            Version::V1 => {
                let mut group = [0; 20];
                if let Ok(v) = q.value_padded(group.len()) {
                    group[..].copy_from_slice(&v);
                } else {
                    return Err(Error::InvalidOperation(
                        "DSA keys' group parameter exceeds 160 bits"
                            .to_string()).into());
                }

                DsaPublicBlob::V1(Blob::<DsaKeyPublicBlob>::clone_from_parts(
                    &winapi::shared::bcrypt::BCRYPT_DSA_KEY_BLOB {
                        dwMagic: winapi::shared::bcrypt::BCRYPT_DSA_PUBLIC_MAGIC,
                        cbKey: y.len() as u32,
                        Count: [0; 4], // unused
                        Seed: [0; 20], // unused
                        q: group,
                    },
                    &DsaKeyPublicPayload {
                        modulus: p.value(),
                        generator: g.value(),
                        public: &y,
                    },
                ))
            },
            Version::V2 => {
                // https://github.com/dotnet/runtime/blob/67d74fca70d4670ad503e23dba9d6bc8a1b5909e/src/libraries/Common/src/System/Security/Cryptography/DSACng.ImportExport.cs#L276-L282
                let hash = match q.value().len() {
                    20 => 0,
                    32 => 1,
                    64 => 2,
                    _ => return Err(Error::InvalidOperation(
                        "CNG accepts DSA q with length of either length of 20, 32 or 64".into())
                                    .into()),
                };

                // We don't use counter/seed values so set them to 0.
                // CNG pre-checks that the seed is at least |Q| long,
                // so we can't use an empty buffer here.
                let (count, seed) = ([0x0; 4], vec![0x0; q.value().len()]);

                DsaPublicBlob::V2(Blob::<DsaKeyPublicV2Blob>::clone_from_parts(
                    &winapi::shared::bcrypt::BCRYPT_DSA_KEY_BLOB_V2 {
                        dwMagic: winapi::shared::bcrypt::BCRYPT_DSA_PUBLIC_MAGIC_V2,
                        Count: count,
                        // Size of the prime number q .
                        // Currently, if the key is less than 128
                        // bits, q is 20 bytes long.
                        // If the key exceeds 256 bits, q is 32 bytes long.
                        cbGroupSize: q.value().len() as u32,
                        cbKey: y.len() as u32,
                        // https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
                        // Length of the seed used to generate the
                        // prime number q.
                        cbSeedLength: seed.len() as u32,
                        hashAlgorithm: hash,
                        standardVersion: 1, // FIPS 186-3

                    },
                    &DsaKeyPublicV2Payload {
                        seed: &seed,
                        group: q.value(),
                        modulus: p.value(),
                        generator: g.value(),
                        public: &y,
                    },
                ))
            },
        };

        use win_crypto_ng::asymmetric::Import;
        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Dsa)?;
        let key = AsymmetricKey::<Dsa, Public>::import(
            Dsa,
            &provider,
            blob
        )?;

        // CNG accepts only hash and Q of equal length. Either trim the
        // digest or pad it with zeroes (since it's treated as a
        // big-endian number).
        // See https://github.com/dotnet/runtime/blob/67d74fca70d4670ad503e23dba9d6bc8a1b5909e/src/libraries/Common/src/System/Security/Cryptography/DSACng.SignVerify.cs#L148.
        let digest = pad_truncating(&digest, q.value().len());
        assert_eq!(q.value().len(), digest.len());

        Ok(key.verify(&digest, &signature, None).map(|_| true)?)
    }
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
                               -> Result<mpi::Signature>
    {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::{AsymmetricKey, Private, Rsa};
        use cng::asymmetric::signature::{Signer, SignaturePadding};
        use cng::key_blob::RsaKeyPrivatePayload;
        use cng::key_blob::EccKeyPrivatePayload;
        use cng::asymmetric::ecc::NamedCurve;

        #[allow(deprecated)]
        Ok(match (self.public().pk_algo(), self.public().mpis(), secret) {
                (PublicKeyAlgorithm::RSAEncryptSign,
                    &mpi::PublicKey::RSA { ref e, ref n },
                    &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) |
                (PublicKeyAlgorithm::RSASign,
                &mpi::PublicKey::RSA { ref e, ref n },
                &mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. }) => {
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                    let key = AsymmetricKey::<Rsa, Private>::import_from_parts(
                        &provider,
                        &RsaKeyPrivatePayload {
                            modulus: n.value(),
                            pub_exp: e.value(),
                            prime1: p.value(),
                            prime2: q.value(),
                        }
                    )?;

                    // As described in [Section 5.2.2 and 5.2.3 of RFC 9580],
                    // to verify the signature, we need to encode the
                    // signature data in a PKCS1-v1.5 packet.
                    //
                    //   [Section 5.2.2 and 5.2.3 of RFC 9580]:
                    //   https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.2
                    let hash = hash_algo.try_into()?;
                    let padding = SignaturePadding::pkcs1(hash);
                    let sig = key.sign(digest, Some(padding))?;

                    mpi::Signature::RSA { s: mpi::MPI::new(&*sig) }
                },
                (PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { curve, q },
                mpi::SecretKeyMaterial::ECDSA { scalar }) =>
                {
                    let (x, y) = q.decode_point(curve)?;

                    // It's expected for the private key to be exactly 32/48/66
                    // (respective curve field size) bytes long but OpenPGP
                    // allows leading zeros to be stripped.
                    // Padding has to be unconditional; otherwise we have a
                    // secret-dependent branch.
                    let curve_bytes = curve.field_size()?;
                    let secret = scalar.value_padded(curve_bytes);

                    use cng::asymmetric::{ecc::{NistP256, NistP384, NistP521}, Ecdsa};

                    // TODO: Improve CNG public API
                    let sig = match curve {
                        Curve::NistP256 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP256>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        Curve::NistP384 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP384>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        Curve::NistP521 => {
                            let provider = AsymmetricAlgorithm::open(
                                AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521)
                            )?;
                            let key = AsymmetricKey::<Ecdsa<NistP521>, Private>::import_from_parts(
                                &provider,
                                &EccKeyPrivatePayload { x, y, d: &secret }
                            )?;
                            key.sign(digest, None)?
                        },
                        _ => return Err(
                            Error::UnsupportedEllipticCurve(curve.clone()).into()),
                    };

                    // CNG outputs a P1363 formatted signature - r || s
                    let (r, s) = sig.split_at(sig.len() / 2);
                    mpi::Signature::ECDSA {
                        r: mpi::MPI::new(r),
                        s: mpi::MPI::new(s),
                    }
                },

                (pk_algo, _, _) => Err(Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                     and secret key {:?}",
                    pk_algo, self.public(), self.secret())))?,
        })
    }
}

impl KeyPair {
    pub(crate) fn decrypt_backend(
        &self,
        secret: &mpi::SecretKeyMaterial,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        Ok(match (self.public().mpis(), secret, ciphertext) {
            (mpi::PublicKey::RSA { ref e, ref n },
             mpi::SecretKeyMaterial::RSA { ref p, ref q, ref d, .. },
             mpi::Ciphertext::RSA { ref c }) => {
                use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
                use cng::asymmetric::{AsymmetricKey, Private, Rsa};
                use cng::asymmetric::EncryptionPadding;
                use cng::key_blob::RsaKeyPrivatePayload;

                let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                let key = AsymmetricKey::<Rsa, Private>::import_from_parts(
                    &provider,
                    &RsaKeyPrivatePayload {
                        modulus: n.value(),
                        pub_exp: e.value(),
                        prime1: p.value(),
                        prime2: q.value(),
                    }
                )?;

                // CNG expects RSA ciphertext length to be a multiple of 8
                // bytes. Since this is a big endian MPI, left-pad it with zeros
                let pad_to = round_up_to_multiple_of(c.value().len(), 8);
                assert!(pad_to >= c.value().len());
                let c = c.value_padded(pad_to).expect("we don't truncate");

                let decrypted =
                    key.decrypt(Some(EncryptionPadding::Pkcs1), &c)?;

                SessionKey::from(decrypted)
            }

            (mpi::PublicKey::ElGamal { .. },
             mpi::SecretKeyMaterial::ElGamal { .. },
             mpi::Ciphertext::ElGamal { .. }) =>
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(ElGamalEncrypt).into()),

            (mpi::PublicKey::ECDH{ .. },
             mpi::SecretKeyMaterial::ECDH { .. },
             mpi::Ciphertext::ECDH { .. }) =>
                crate::crypto::ecdh::decrypt(self.public(), secret, ciphertext,
                                             plaintext_len)?,

            (public, secret, ciphertext) =>
                return Err(Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                    public, secret, ciphertext)).into()),
        })
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::{AsymmetricKey, Public, Rsa};
        use cng::key_blob::RsaKeyPublicPayload;

        use PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match self.mpis() {
                    mpi::PublicKey::RSA { e, n } => {
                        // The ciphertext has the length of the modulus.
                        let ciphertext_len = n.value().len();
                        if data.len() + 11 > ciphertext_len {
                            return Err(Error::InvalidArgument(
                                "Plaintext data too large".into()).into());
                        }

                        let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                        let key = AsymmetricKey::<Rsa, Public>::import_from_parts(
                            &provider,
                            &RsaKeyPublicPayload {
                                modulus: n.value(),
                                pub_exp: e.value(),
                            }
                        )?;

                        let padding = win_crypto_ng::asymmetric::EncryptionPadding::Pkcs1;
                        let ciphertext = key.encrypt(Some(padding), data)?;

                        Ok(mpi::Ciphertext::RSA {
                            c: mpi::MPI::new(ciphertext.as_ref()),
                        })
                    },
                    pk => {
                        Err(Error::MalformedPacket(
                            format!(
                                "Key: Expected RSA public key, got {:?}",
                                pk)).into())
                    },
                }
            },

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            ElGamalEncrypt | ElGamalEncryptSign |
            X25519 | X448 |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()> {
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId};
        use cng::asymmetric::{AsymmetricKey, Public, Rsa};
        use cng::asymmetric::ecc::NamedCurve;
        use cng::asymmetric::signature::{Verifier, SignaturePadding};
        use cng::key_blob::RsaKeyPublicPayload;

        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }

        let ok = match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                // CNG accepts only full-size signatures. Since for RSA it's a
                // big-endian number, just left-pad with zeroes as necessary.
                let s = pad(s.value(), n.value().len()).map_err(bad)?;

                // CNG supports RSA keys that are at least 512 bit long.
                // Since it just checks the MPI length rather than data itself,
                // just pad it with zeroes as necessary.
                let n = pad_at_least(n.value(), 512);

                let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Rsa)?;
                let key = AsymmetricKey::<Rsa, Public>::import_from_parts(
                    &provider,
                    &RsaKeyPublicPayload {
                        modulus: &n,
                        pub_exp: e.value(),
                    }
                )?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 9580],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 9580]:
                //   https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.2
                let hash = hash_algo.try_into()?;
                let padding = SignaturePadding::pkcs1(hash);

                key.verify(digest, &s, Some(padding)).map(|_| true)?
            },

            (mpi::PublicKey::ECDSA { curve, q }, mpi::Signature::ECDSA { s, r }) =>
            {
                let (x, y) = q.decode_point(curve)?;
                // CNG expects full-sized signatures
                let field_sz = x.len();
                let mut signature = vec![0u8; 2 * field_sz];

                // We need to zero-pad them at the front, because
                // the MPI encoding drops leading zero bytes.
                signature[..field_sz].copy_from_slice(
                    &r.value_padded(field_sz).map_err(bad)?);
                signature[field_sz..].copy_from_slice(
                    &s.value_padded(field_sz).map_err(bad)?);

                use cng::key_blob::EccKeyPublicPayload;
                use cng::asymmetric::{ecc::{NistP256, NistP384, NistP521}, Ecdsa};

                // TODO: Improve CNG public API
                match curve {
                    Curve::NistP256 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP256)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP256>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    Curve::NistP384 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP384)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP384>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    Curve::NistP521 => {
                        let provider = AsymmetricAlgorithm::open(
                            AsymmetricAlgorithmId::Ecdsa(NamedCurve::NistP521)
                        )?;
                        let key = AsymmetricKey::<Ecdsa<NistP521>, Public>::import_from_parts(
                            &provider,
                            &EccKeyPublicPayload { x, y }
                        )?;
                        key.verify(digest, &signature, None).map(|_| true)?
                    },
                    _ => return Err(
                        Error::UnsupportedEllipticCurve(curve.clone()).into()),
                }
            },
            _ => return Err(Error::MalformedPacket(format!(
                "unsupported combination of key {} and signature {:?}.",
                self.pk_algo(), sig)).into()),
        };

        if ok {
            Ok(())
        } else {
            Err(Error::ManipulatedMessage.into())
        }
    }
}

impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing RSA key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have its creation date set to
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
        use cng::asymmetric::{AsymmetricAlgorithm, AsymmetricAlgorithmId, Ecdh, Private};
        use cng::asymmetric::{AsymmetricKey, Export};
        use cng::asymmetric::ecc::{Curve25519, NamedCurve};

        let provider = AsymmetricAlgorithm::open(
            AsymmetricAlgorithmId::Ecdh(NamedCurve::Curve25519)
        )?;
        let key = AsymmetricKey::<Ecdh<Curve25519>, Private>::import_from_parts(
            &provider,
            private_key
        )?;
        let blob = key.export()?;

        // Mark MPI as compressed point with 0x40 prefix. See
        // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
        let mut public = [0u8; 1 + CURVE25519_SIZE];
        public[0] = 0x40;
        public[1..].copy_from_slice(blob.x());

        // Reverse the scalar.  See
        // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
        let mut private = blob.d().to_vec();
        private.reverse();

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or(HashAlgorithm::SHA512),
                sym: sym.into().unwrap_or(SymmetricAlgorithm::AES256),
                q: mpi::MPI::new(&public),
            },
            mpi::SecretKeyMaterial::ECDH { scalar: private.into() }.into()
        )
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The key will have it's creation date set to `ctime` or the current time
    /// if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // CNG doesn't support EdDSA, use ed25519-dalek instead
        use ed25519_dalek::{PublicKey, SecretKey};

        let private = SecretKey::from_bytes(private_key).map_err(|e| {
            Error::InvalidKey(e.to_string())
        })?;

        // Mark MPI as compressed point with 0x40 prefix. See
        // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07#section-13.2.
        let mut public = [0u8; 1 + CURVE25519_SIZE];
        public[0] = 0x40;
        public[1..].copy_from_slice(Into::<PublicKey>::into(&private).as_bytes());

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: mpi::MPI::new(&public)
            },
            mpi::SecretKeyMaterial::EdDSA {
                scalar: mpi::MPI::new(&private_key).into(),
            }.into()
        )
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// Like import_secret_rsa but uses the given public exponent `e`.
    ///
    /// Note that import_secret_rsa computes e such that ed == 1 mod phi(n), but
    /// most standards (e.g. RFC3447, referenced by RFC4880 as ultimate
    /// authority for PKCS#1) dictate ed == 1 mod lambda(n).
    pub fn import_secret_rsa_unchecked_e<T>(
        e: &[u8], d: &[u8], p: &[u8], q: &[u8], ctime: T
    ) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // RFC 4880: `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };

        // CNG can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x: BigInt| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(e),
                n: mpi::MPI::new(&n.to_bytes_be()),
            },
            mpi::SecretKeyMaterial::RSA {
                d: mpi::MPI::new(d).into(),
                p: mpi::MPI::new(p).into(),
                q: mpi::MPI::new(q).into(),
                u: mpi::MPI::new(&u.to_bytes_be()).into(),
            }.into()
        )
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
        // RFC 4880: `p < q`
        let (p, q) = crate::crypto::rsa_sort_raw_pq(p, q);

        // CNG can't compute the public key from the private one, so do it ourselves
        let big_p = BigUint::from_bytes_be(p);
        let big_q = BigUint::from_bytes_be(q);
        let n = big_p.clone() * big_q.clone();

        let big_d = BigUint::from_bytes_be(d);
        let big_phi = (big_p.clone() - 1u32) * (big_q.clone() - 1u32);
        let e = big_d.mod_inverse(big_phi) // e ≡ d⁻¹ (mod 𝜙)
            .and_then(|x: BigInt| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `d` and `(p-1)(q-1)` aren't coprime".into()))?;

        let u: BigUint = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x: BigInt| x.to_biguint())
            .ok_or_else(|| Error::MalformedMPI("RSA: `p` and `q` aren't coprime".into()))?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(&e.to_bytes_be()),
                n: mpi::MPI::new(&n.to_bytes_be()),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.to_bytes_be().into(),
            }.into()
        )
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        use win_crypto_ng::asymmetric::{AsymmetricKey, Rsa};

        let blob = AsymmetricKey::builder(Rsa)
            .key_bits(bits as u32)
            .build()?
            .export_full()?;

        let public = mpi::PublicKey::RSA {
            e: mpi::MPI::new(blob.pub_exp()).into(),
            n: mpi::MPI::new(blob.modulus()).into(),
        };

        let p = mpi::ProtectedMPI::from(blob.prime1());
        let q = mpi::ProtectedMPI::from(blob.prime2());
        // RSA prime generation in CNG returns them in arbitrary order but
        // RFC 4880 expects `p < q`
        let (p, q) = rsa_sort_pq(p, q);
        // CNG `coeff` is `prime1`^-1 mod `prime2` so adjust for possible p,q reorder
        let big_p = BigUint::from_bytes_be(p.value());
        let big_q = BigUint::from_bytes_be(q.value());
        let u = big_p.mod_inverse(big_q) // RFC 4880: u ≡ p⁻¹ (mod q)
            .and_then(|x: BigInt| x.to_biguint())
            .expect("CNG to generate a valid RSA key (where p, q are coprime)");

        let private = mpi::SecretKeyMaterial::RSA {
            p: p,
            q: q,
            d: blob.priv_exp().into(),
            u: u.to_bytes_be().into(),
        };

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            public,
            private.into()
        )
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true`
    /// and `curve == Cv25519` will produce an error.  Similar for
    /// `for_signing == false` and `curve == Ed25519`.
    /// signing/encryption
    pub(crate) fn generate_ecc_backend(for_signing: bool, curve: Curve)
                                       -> Result<(PublicKeyAlgorithm,
                                                  mpi::PublicKey,
                                                  mpi::SecretKeyMaterial)>
    {
        use cng::asymmetric::{ecc, Export};
        use cng::asymmetric::{AsymmetricKey, AsymmetricAlgorithmId};

        match (curve.clone(), for_signing) {
            (Curve::Ed25519, true) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::Cv25519, false) =>
                unreachable!("handled in Key4::generate_ecc"),

            (Curve::NistP256, ..) | (Curve::NistP384, ..) | (Curve::NistP521, ..) => {
                let cng_curve = match curve {
                    Curve::NistP256 => ecc::NamedCurve::NistP256,
                    Curve::NistP384 => ecc::NamedCurve::NistP384,
                    Curve::NistP521 => ecc::NamedCurve::NistP521,
                    _ => unreachable!()
                };

                let ecc_algo = if for_signing {
                    AsymmetricAlgorithmId::Ecdsa(cng_curve)
                } else {
                    AsymmetricAlgorithmId::Ecdh(cng_curve)
                };

                let blob = AsymmetricKey::builder(ecc_algo).build()?.export()?;
                let blob = match blob.try_into::<cng::key_blob::EccKeyPrivateBlob>() {
                    Ok(blob) => blob,
                    // Dynamic algorithm specified is either ECDSA or ECDH so
                    // exported blob should be of appropriate type
                    Err(..) => unreachable!()
                };
                let field_sz = cng_curve.key_bits() as usize;

                let q = mpi::MPI::new_point(blob.x(), blob.y(), field_sz);
                let scalar = mpi::ProtectedMPI::from(blob.d());

                if for_signing {
                    Ok((
                        PublicKeyAlgorithm::ECDSA,
                        mpi::PublicKey::ECDSA { curve, q },
                        mpi::SecretKeyMaterial::ECDSA { scalar },
                    ))
                } else {
                    let hash =
                        crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
                    let sym =
                        crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);

                    Ok((
                        PublicKeyAlgorithm::ECDH,
                        mpi::PublicKey::ECDH { curve, q, hash, sym },
                        mpi::SecretKeyMaterial::ECDH { scalar },
                    ))
                }
            },

            _ => Err(Error::UnsupportedEllipticCurve(curve).into()),
        }
    }
}

/// Rounds `n` up to the next multiple of `m`.
fn round_up_to_multiple_of(n: usize, m: usize) -> usize {
    ((n + m - 1) / m) * m
}

/// Given the secret prime values `p` and `q`, returns the pair of
/// primes so that the smaller one comes first.
///
/// Section 5.5.3 of RFC4880 demands that `p < q`.  This function can
/// be used to order `p` and `q` accordingly.
///
/// Note: even though this function seems trivial, we introduce it as
/// explicit abstraction.  The reason is that the function's
/// expression also "works" (as in it compiles) for byte slices, but
/// does the wrong thing, see [`crate::crypto::rsa_sort_raw_pq`].
fn rsa_sort_pq(p: mpi::ProtectedMPI, q: mpi::ProtectedMPI)
               -> (mpi::ProtectedMPI, mpi::ProtectedMPI)
{
    if p < q {
        (p, q)
    } else {
        (q, p)
    }
}

#[cfg(test)]
mod tests {
    quickcheck! {
        fn round_up_to_multiple_of(n: usize, m: usize) -> bool {
            if n.checked_add(m).is_none() {
                // cannot round up because it overflows
                return true;
            }

            if m == 0 {
                // avoid dividing by zero
                return true;
            }

            let rounded_up = super::round_up_to_multiple_of(n, m);
            assert!(rounded_up >= n);
            assert!(rounded_up - n < m);
            assert_eq!(rounded_up % m, 0);
            true
        }
    }
}
