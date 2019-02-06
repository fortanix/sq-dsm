//! Public key, public subkey, private key and private subkey packets.

use std::fmt;
use std::mem;
use std::cmp::Ordering;
use time;

use Error;
use crypto::{mpis, KeyPair, SessionKey};
use packet::Tag;
use packet;
use Packet;
use PublicKeyAlgorithm;
use SymmetricAlgorithm;
use HashAlgorithm;
use constants::Curve;
use crypto::s2k::S2K;
use Result;
use conversions::Time;
use crypto::Password;

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Key {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Version of the key packet. Must be 4.
    version: u8,
    /// When the key was created.
    creation_time: time::Tm,
    /// Public key algorithm of this signature.
    pk_algo: PublicKeyAlgorithm,
    /// Public key MPIs.
    mpis: mpis::PublicKey,
    /// Optional secret part of the key.
    secret: Option<SecretKey>,
}


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

impl Key {
    /// Compares the public bits of two keys.
    ///
    /// This returns Ordering::Equal if the public MPIs, version,
    /// creation time and algorithm of the two `Key`s match.  This
    /// does not consider the packet's encoding, packet's tag or the
    /// secret key material.
    pub fn public_cmp(a: &Self, b: &Self) -> Ordering {
        match a.mpis.cmp(&b.mpis) {
            Ordering::Equal => (),
            o => return o,
        }

        match a.version.cmp(&b.version) {
            Ordering::Equal => (),
            o => return o,
        }

        match a.creation_time.cmp(&b.creation_time) {
            Ordering::Equal => (),
            o => return o,
        }

        a.pk_algo.cmp(&b.pk_algo)
    }
}

impl Key {
    pub(crate) fn new_(creation_time: time::Tm,pk_algo: PublicKeyAlgorithm,
                       mpis: mpis::PublicKey, secret: Option<SecretKey>)
                       -> Result<Key>
    {
        Ok(Key {
            common: Default::default(),
            version: 4,
            creation_time: creation_time,
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Creates a new OpenPGP public key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric algorithm `sym`. If one or both
    /// are `None` secure defaults will be used. The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_public_cv25519<H,S,T>(public_key: &[u8], hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<time::Tm>>
    {
        let mut point = Vec::from(public_key);
        point.insert(0, 0x40);

        Ok(Key{
            common: Default::default(),
            version: 4,
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::ECDH,
            mpis: mpis::PublicKey::ECDH{
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or(HashAlgorithm::SHA512),
                sym: sym.into().unwrap_or(SymmetricAlgorithm::AES256),
                q: mpis::MPI::new(&point),
            },
            secret: None,
        })
    }

    /// Returns a new `Key` packet.  This can be used to hold either a
    /// public key, a public subkey, a private key, or a private subkey.
    pub fn new(pk_algo: PublicKeyAlgorithm) -> Result<Self> {
        use nettle::{
            rsa,
            Yarrow,
            ed25519,ed25519::ED25519_KEY_SIZE,
            curve25519,curve25519::CURVE25519_SIZE,
        };
        use crypto::mpis::{self, MPI, PublicKey};
        use constants::{HashAlgorithm, SymmetricAlgorithm, Curve};
        use PublicKeyAlgorithm::*;
        use Error;

        #[allow(deprecated)]
        let (mpis, secret) = match pk_algo {
            RSASign | RSAEncrypt | RSAEncryptSign => {
                let mut rng = Yarrow::default();
                let (public,private) = rsa::generate_keypair(&mut rng, 3072)?;
                let (p,q,u) = private.as_rfc4880();
                let public_mpis = PublicKey::RSA {
                    e: MPI::new(&*public.e()),
                    n: MPI::new(&*public.n()),
                };
                let private_mpis = mpis::SecretKey::RSA {
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
                let mut public = [0u8; ED25519_KEY_SIZE + 1];
                let mut private: SessionKey = ed25519::private_key().into();

                public[0] = 0x40;
                ed25519::public_key(&mut public[1..], &private)?;

                let public_mpis = PublicKey::EdDSA {
                    curve: Curve::Ed25519,
                    q: MPI::new(&public),
                };
                let private_mpis = mpis::SecretKey::EdDSA {
                    scalar: MPI::new(&private),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis,
                });

                (public_mpis, sec)
            }

            ECDH => {
                let mut public = [0u8; CURVE25519_SIZE + 1];
                let mut private: SessionKey = curve25519::secret_key().into();

                public[0] = 0x40;

                curve25519::mul_g(&mut public[1..], &private)?;

                // Reverse the scalar.  See
                // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
                private.reverse();

                let public_mpis = PublicKey::ECDH {
                    curve: Curve::Cv25519,
                    q: MPI::new(&public),
                    hash: HashAlgorithm::SHA256,
                    sym: SymmetricAlgorithm::AES256,
                };
                let private_mpis = mpis::SecretKey::ECDH {
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
            creation_time: time::now().canonicalize(),
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Gets the key packet's version field.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the key packet's creation time field.
    pub fn creation_time(&self) -> &time::Tm {
        &self.creation_time
    }

    /// Sets the key packet's creation time field.
    pub fn set_creation_time(&mut self, timestamp: time::Tm) {
        self.creation_time = timestamp.canonicalize();
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm) {
        self.pk_algo = pk_algo;
    }

    /// Gets the key packet's MPIs.
    pub fn mpis(&self) -> &mpis::PublicKey {
        &self.mpis
    }

    /// Gets a mutable reference to the key packet's MPIs.
    pub fn mpis_mut(&mut self) -> &mut mpis::PublicKey {
        &mut self.mpis
    }

    /// Sets the key packet's MPIs.
    pub fn set_mpis(&mut self, mpis: mpis::PublicKey) {
        self.mpis = mpis;
    }

    /// Gets the key packet's SecretKey.
    pub fn secret(&self) -> Option<&SecretKey> {
        self.secret.as_ref()
    }

    /// Gets a mutable reference to the key packet's SecretKey.
    pub fn secret_mut(&mut self) -> Option<&mut SecretKey> {
        self.secret.as_mut()
    }

    /// Sets the key packet's SecretKey.
    ///
    /// Returns the old value.
    pub fn set_secret(&mut self, secret: Option<SecretKey>)
        -> Option<SecretKey>
    {
        mem::replace(&mut self.secret, secret)
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn to_packet(self, tag: Tag) -> Result<Packet> {
        match tag {
            Tag::PublicKey => Ok(Packet::PublicKey(self)),
            Tag::PublicSubkey => Ok(Packet::PublicSubkey(self)),
            Tag::SecretKey => Ok(Packet::SecretKey(self)),
            Tag::SecretSubkey => Ok(Packet::SecretSubkey(self)),
            _ => Err(Error::InvalidArgument(
                format!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag)).into()),
        }
    }

    /// Creates a new key pair from a Key packet with an unencrypted
    /// secret key.
    ///
    /// # Errors
    ///
    /// Fails if the secret key is missing, or encrypted.
    pub fn into_keypair(mut self) -> Result<KeyPair> {
        use packet::key::SecretKey;
        let secret = match self.set_secret(None) {
            Some(SecretKey::Unencrypted { mpis }) => mpis,
            Some(SecretKey::Encrypted { .. }) =>
                return Err(Error::InvalidArgument(
                    "secret key is encrypted".into()).into()),
            None =>
                return Err(Error::InvalidArgument(
                    "no secret key".into()).into()),
        };

        KeyPair::new(self, secret)
    }
}

/// Holds the secret potion of a OpenPGP secret key or secret subkey packet.
///
/// This type allows postponing the decryption of the secret key until we need to use it.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SecretKey {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted {
        /// MPIs of the secret key.
        mpis: mpis::SecretKey,
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
    /// Decrypts this secret key using `password`.
    ///
    /// The SecretKey type does not know what kind of key it is, so
    /// `pk_algo` is needed to parse the correct number of MPIs.
    pub fn decrypt(&self, pk_algo: PublicKeyAlgorithm, password: &Password)
                   -> Result<mpis::SecretKey> {
        use std::io::{Cursor, Read};
        use crypto::symmetric::Decryptor;

        match self {
            &SecretKey::Unencrypted { .. } =>
                Err(Error::InvalidOperation("Key is not encrypted".into())
                    .into()),
            &SecretKey::Encrypted { ref s2k, algorithm, ref ciphertext } => {
                let key = s2k.derive_key(password, algorithm.key_size()?)?;
                let mut cur = Cursor::new(ciphertext);
                let mut dec = Decryptor::new(algorithm, &key, cur)?;
                let mut trash = vec![0u8; algorithm.block_size()?];

                dec.read_exact(&mut trash)?;
                mpis::SecretKey::parse_chksumd(pk_algo, &mut dec)
            }
        }
    }

    /// Decrypts this secret key using `password`.
    ///
    /// The SecretKey type does not know what kind of key it is, so
    /// `pk_algo` is needed to parse the correct number of MPIs.
    pub fn decrypt_in_place(&mut self, pk_algo: PublicKeyAlgorithm,
                            password: &Password)
                            -> Result<()> {
        if self.is_encrypted() {
            *self = SecretKey::Unencrypted {
                mpis: self.decrypt(pk_algo, password)?,
            };
        }

        Ok(())
    }

    /// Encrypts this secret key using `password`.
    pub fn encrypt(&self, password: &Password)
                   -> Result<(S2K, SymmetricAlgorithm, Box<[u8]>)> {
        use std::io::Write;
        use crypto::symmetric::Encryptor;
        use nettle::Yarrow;

        match self {
            &SecretKey::Encrypted { .. } =>
                Err(Error::InvalidOperation("Key is already encrypted".into())
                    .into()),
            &SecretKey::Unencrypted { ref mpis } => {
                let s2k = S2K::default();
                let cipher = SymmetricAlgorithm::AES256;
                let key = s2k.derive_key(password, cipher.key_size()?)?;

                // Ciphertext is preceded by a random block.
                let mut trash = vec![0u8; cipher.block_size()?];
                Yarrow::default().random(&mut trash);

                let mut esk = Vec::new();
                {
                    let mut encryptor = Encryptor::new(cipher, &key, &mut esk)?;
                    encryptor.write_all(&trash)?;
                    mpis.serialize_chksumd(&mut encryptor)?;
                }

                Ok((s2k, cipher, esk.into_boxed_slice()))
            },
        }
    }

    /// Encrypts this secret key using `password`.
    pub fn encrypt_in_place(&mut self, password: &Password) -> Result<()> {
        let (s2k, cipher, esk) = self.encrypt(password)?;
        *self = SecretKey::Encrypted {
            s2k: s2k,
            algorithm: cipher,
            ciphertext: esk,
        };

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
    use packet::Tag;
    use TPK;
    use packet::key::SecretKey;
    use std::path::PathBuf;
    use super::*;
    use PacketPile;
    use serialize::SerializeKey;
    use parse::Parse;

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
        secret.decrypt_in_place(pair.pk_algo, &"123".into()).unwrap();
        assert!(!secret.is_encrypted());

        match secret {
            &mut SecretKey::Unencrypted { mpis: mpis::SecretKey::RSA { .. } } =>
                {}
            _ => { unreachable!() }
        }
    }

    #[test]
    fn eq() {
        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::EdDSA,
                          PublicKeyAlgorithm::ECDH] {
            let key = Key::new(pk_algo).unwrap();
            let clone = key.clone();
            assert_eq!(key, clone);
        }
    }

    #[test]
    fn roundtrip() {
        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::EdDSA,
                          PublicKeyAlgorithm::ECDH] {
            let mut key = Key::new(pk_algo).unwrap();

            let mut b = Vec::new();
            key.serialize(&mut b, Tag::SecretKey).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::SecretKey(ref parsed_key)) = pp.path_ref(&[0]) {
                assert_eq!(key.common, parsed_key.common);
                assert_eq!(key.version, parsed_key.version);
                assert_eq!(key.creation_time, parsed_key.creation_time);
                assert_eq!(key.pk_algo, parsed_key.pk_algo);
                assert_eq!(key.mpis, parsed_key.mpis);
                assert_eq!(key.secret, parsed_key.secret);

                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }

            let mut b = Vec::new();
            key.serialize(&mut b, Tag::PublicKey).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::PublicKey(ref parsed_key)) = pp.path_ref(&[0]) {
                assert!(parsed_key.secret().is_none());

                key.set_secret(None);
                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }
        }
    }

    #[test]
    fn encryption_roundtrip() {
        use packet::key::SecretKey;
        use crypto::SessionKey;
        use packet::PKESK;

        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::ECDH] {
            let key = Key::new(pk_algo).unwrap();
            let secret =
                if let Some(SecretKey::Unencrypted {
                    ref mpis,
                }) = key.secret() {
                    mpis.clone()
                } else {
                    unreachable!()
                };

            let cipher = SymmetricAlgorithm::AES256;
            let sk = SessionKey::new(&mut Default::default(),
                                     cipher.key_size().unwrap());

            let pkesk = PKESK::new(cipher, &sk, &key).unwrap();
            let (cipher_, sk_) = pkesk.decrypt(&key, &secret).unwrap();

            assert_eq!(cipher, cipher_);
            assert_eq!(sk, sk_);
        }
    }

    #[test]
    fn secret_encryption_roundtrip() {
        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::EdDSA,
                          PublicKeyAlgorithm::ECDH] {
            let key = Key::new(pk_algo).unwrap();
            assert!(! key.secret().unwrap().is_encrypted());

            let password = Password::from("foobarbaz");
            let mut encrypted_key = key.clone();

            encrypted_key.secret_mut().unwrap()
                .encrypt_in_place(&password).unwrap();
            assert!(encrypted_key.secret().unwrap().is_encrypted());

            encrypted_key.secret_mut().unwrap()
                .decrypt_in_place(pk_algo, &password).unwrap();
            assert!(! key.secret().unwrap().is_encrypted());
            assert_eq!(key, encrypted_key);
            assert_eq!(key.secret(), encrypted_key.secret());
        }
    }

    #[test]
    fn import_cv25519() {
        use crypto::{ecdh, SessionKey};
        use self::mpis::{MPI, Ciphertext};
        use time::{at, Timespec};

        // X25519 key
        let ctime = at(Timespec::new(0x5c487129,0));
        let public = b"\xed\x59\x0a\x15\x08\x95\xe9\x92\xd2\x2c\x14\x01\xb3\xe9\x3b\x7f\xff\xe6\x6f\x22\x65\xec\x69\xd9\xb8\xda\x24\x2c\x64\x84\x44\x11";
        let key = Key::import_public_cv25519(&public[..], HashAlgorithm::SHA256, SymmetricAlgorithm::AES128, ctime).unwrap();

        // PKESK
        let eph_pubkey: &[u8; 33] = b"\x40\xda\x1c\x69\xc4\xe3\xb6\x9c\x6e\xd4\xc6\x69\x6c\x89\xc7\x09\xe9\xf8\x6a\xf1\xe3\x8d\xb6\xaa\xb5\xf7\x29\xae\xa6\xe7\xdd\xfe\x38";
        let ciphertext = Ciphertext::ECDH{
            e: MPI::new(&eph_pubkey[..]),
            key: Vec::from(&b"\x45\x8b\xd8\x4d\x88\xb3\xd2\x16\xb6\xc2\x3b\x99\x33\xd1\x23\x4b\x10\x15\x8e\x04\x16\xc5\x7c\x94\x88\xf6\x63\xf2\x68\x37\x08\x66\xfd\x5a\x7b\x40\x58\x21\x6b\x2c\xc0\xf4\xdc\x91\xd3\x48\xed\xc1"[..]).into_boxed_slice()
        };
        let shared_sec: &[u8; 32] = b"\x44\x0C\x99\x27\xF7\xD6\x1E\xAD\xD1\x1E\x9E\xC8\x22\x2C\x5D\x43\xCE\xB0\xE5\x45\x94\xEC\xAF\x67\xD9\x35\x1D\xA1\xA3\xA8\x10\x0B";

        // Session key
        let dek = b"\x09\x0D\xDC\x40\xC5\x71\x51\x88\xAC\xBD\x45\x56\xD4\x2A\xDF\x77\xCD\xF4\x82\xA2\x1B\x8F\x2E\x48\x3B\xCA\xBF\xD3\xE8\x6D\x0A\x7C\xDF\x10\xe6";
        let sk = SessionKey::from(Vec::from(&dek[..]));

       // Expected
       let got_enc = ecdh::wrap_session_key_deterministic(&key, &sk, eph_pubkey, shared_sec).unwrap();

       assert_eq!(ciphertext, got_enc);
    }
}
