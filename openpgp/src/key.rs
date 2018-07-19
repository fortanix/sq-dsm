use std::fmt;
use time;

use mpis::MPIs;
use Tag;
use Key;
use Packet;
use PublicKeyAlgorithm;
use SymmetricAlgorithm;
use s2k::S2K;
use Result;

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &self.fingerprint())
            .field("version", &self.version)
            .field("creation_time", &format!("{}", self.creation_time.rfc3339()))
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .field("secret", &self.secret)
            .finish()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl Default for Key {
    fn default() -> Self {
        Key {
            common: Default::default(),
            version: 4,
            creation_time: time::now(),
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            mpis: MPIs::empty(),
            secret: None,
        }
    }
}

impl Key {
    /// Returns a new `Key` packet.  This can be used to hold either a
    /// public key, a public key, a private key, or a private subkey.
    pub fn new(pk_algo: PublicKeyAlgorithm) -> Result<Self> {
        use nettle::{
            rsa,
            Yarrow,
            ed25519,ed25519::ED25519_KEY_SIZE,
            curve25519,curve25519::CURVE25519_SIZE,
        };
        use mpis::MPI;
        use constants::{HashAlgorithm, SymmetricAlgorithm, Curve};
        use PublicKeyAlgorithm::*;
        use Error;

        let (mpis, secret) = match pk_algo {
            RSASign | RSAEncrypt | RSAEncryptSign => {
                let mut rng = Yarrow::default();
                let (public,private) = rsa::generate_keypair(&mut rng, 3072)?;
                let (p,q,u) = private.as_rfc4880();
                let public_mpis = MPIs::RSAPublicKey{
                    e: MPI::new(&*public.e()),
                    n: MPI::new(&*public.n()),
                };
                let private_mpis = MPIs::RSASecretKey{
                    d: MPI::new(&*private.d()),
                    p: MPI::new(&*p),
                    q: MPI::new(&*q),
                    u: MPI::new(&*u),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis
                });

                (public_mpis, sec)
            }

            EdDSA => {
                let mut rng = Yarrow::default();
                let mut public = [0u8; ED25519_KEY_SIZE];
                let mut private = [0u8; ED25519_KEY_SIZE];

                rng.random(&mut private);
                ed25519::public_key(&mut public, &private)?;

                let public_mpis = MPIs::EdDSAPublicKey{
                    curve: Curve::Ed25519,
                    q: MPI::new(&public),
                };
                let private_mpis = MPIs::EdDSASecretKey{
                    scalar: MPI::new(&private),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis,
                });

                (public_mpis, sec)
            }

            ECDH => {
                let mut rng = Yarrow::default();
                let mut public = [0u8; CURVE25519_SIZE];
                let mut private = [0u8; CURVE25519_SIZE];

                rng.random(&mut private);
                curve25519::mul_g(&mut public, &private)?;

                let public_mpis = MPIs::ECDHPublicKey{
                    curve: Curve::Cv25519,
                    q: MPI::new(&public),
                    hash: HashAlgorithm::SHA256,
                    sym: SymmetricAlgorithm::AES256,
                };
                let private_mpis = MPIs::ECDHSecretKey{
                    scalar: MPI::new(&private),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis,
                });

                (public_mpis, sec)
            }

            pk => {
                return Err(Error::UnsupportedPublicKeyAlgorithm(pk).into());
            }
        };

        Ok(Key {
            common: Default::default(),
            version: 4,
            creation_time: time::now(),
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Sets the literal packet's date field using a Unix timestamp.
    ///
    /// A Unix timestamp is the number of seconds since the Unix
    /// epoch.
    pub fn creation_time(mut self, timestamp: time::Tm) -> Self {
        self.creation_time = timestamp;
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, pk_algo: PublicKeyAlgorithm) -> Self {
        self.pk_algo = pk_algo;
        self
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn to_packet(self, tag: Tag) -> Packet {
        match tag {
            Tag::PublicKey => Packet::PublicKey(self),
            Tag::PublicSubkey => Packet::PublicSubkey(self),
            Tag::SecretKey => Packet::SecretKey(self),
            Tag::SecretSubkey => Packet::SecretSubkey(self),
            _ => panic!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag),
        }
    }
}

/// Holds the secret potion of a OpenPGP secret key or secret subkey packet.
///
/// This type allows postponing the decryption of the secret key until we need to use it.
#[derive(PartialEq, Clone, Debug)]
pub enum SecretKey {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted {
        /// MPIs of the secret key. Must be a *SecretKey enum variant.
        mpis: MPIs
    },
    /// The secret key is encrypted with a password.
    Encrypted {
        /// Key derivation mechanism to use.
        s2k: S2K,
        /// Symmetric algorithm used for encryption the secret key.
        algorithm: SymmetricAlgorithm,
        /// Encrypted MPIs prefixed with the IV.
        ciphertext: Box<[u8]>,
    },
}

impl SecretKey {
    /// Decrypts this secret key using `password`. The SecretKey type
    /// does not know what kind of key it is, so `pk_algo` is needed
    /// to parse the correct number of MPIs.
    pub fn decrypt(&mut self, pk_algo: PublicKeyAlgorithm, password: &[u8])
                   -> Result<()> {
        use std::io::{Cursor, Read};
        use symmetric::Decryptor;

        let new = match &*self {
            &SecretKey::Unencrypted { .. } => None,
            &SecretKey::Encrypted { ref s2k, algorithm, ref ciphertext } => {
                let key = s2k.derive_key(password, algorithm.key_size()?)?
                    .into_boxed_slice();
                let mut cur = Cursor::new(ciphertext);
                let mut dec = Decryptor::new(algorithm, &key, cur)?;
                let mut trash = vec![0u8; algorithm.block_size()?];

                dec.read_exact(&mut trash)?;
                let mpis = MPIs::parse_chksumd_secret_key(pk_algo, &mut dec)?;

                Some(SecretKey::Unencrypted{ mpis: mpis })
            }
        };

        if let Some(new) = new {
            *self = new;
        }

        Ok(())
    }

    /// Returns true if this secret key is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            &SecretKey::Encrypted { .. } => true,
            &SecretKey::Unencrypted { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use mpis::MPIs;
    use TPK;
    use SecretKey;
    use std::path::PathBuf;

    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "keys", artifact]
            .iter().collect()
    }

    #[test]
    fn encrypted_rsa_key() {
        let mut tpk = TPK::from_file(
            path_to("testy-new-encrypted-with-123.pgp")).unwrap();
        let pair = tpk.primary_mut();
        let secret = pair.secret.as_mut().unwrap();

        assert!(secret.is_encrypted());
        secret.decrypt(pair.pk_algo, &b"123"[..]).unwrap();
        assert!(!secret.is_encrypted());

        match secret {
            &mut SecretKey::Unencrypted { mpis: MPIs::RSASecretKey { .. } } =>
                {}
            _ => { unreachable!() }
        }
    }
}
