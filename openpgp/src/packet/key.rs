//! Public key, public subkey, private key and private subkey packets.

use std::fmt;
use std::cmp::Ordering;
use time;

use crate::Error;
use crate::crypto::{self, mem::{self, Protected}, mpis, hash::Hash};
use crate::packet::Tag;
use crate::packet;
use crate::Packet;
use crate::PublicKeyAlgorithm;
use crate::SymmetricAlgorithm;
use crate::HashAlgorithm;
use crate::constants::Curve;
use crate::crypto::s2k::S2K;
use crate::Result;
use crate::conversions::Time;
use crate::crypto::Password;
use crate::KeyID;
use crate::Fingerprint;

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Key4 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// When the key was created.
    creation_time: time::Tm,
    /// Public key algorithm of this signature.
    pk_algo: PublicKeyAlgorithm,
    /// Public key MPIs.
    mpis: mpis::PublicKey,
    /// Optional secret part of the key.
    secret: Option<SecretKeyMaterial>,
}


impl fmt::Debug for Key4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key4")
            .field("fingerprint", &self.fingerprint())
            .field("creation_time", &format!("{}", self.creation_time.rfc3339()))
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .field("secret", &self.secret)
            .finish()
    }
}

impl fmt::Display for Key4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl Key4 {
    /// Compares the public bits of two keys.
    ///
    /// This returns Ordering::Equal if the public MPIs,
    /// creation time and algorithm of the two `Key4`s match.  This
    /// does not consider the packet's encoding, packet's tag or the
    /// secret key material.
    pub fn public_cmp(a: &Self, b: &Self) -> Ordering {
        match a.mpis.cmp(&b.mpis) {
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

impl Key4 {
    /// Creates a new OpenPGP key packet.
    pub fn new(creation_time: time::Tm, pk_algo: PublicKeyAlgorithm,
               mpis: mpis::PublicKey, secret: Option<SecretKeyMaterial>)
               -> Result<Self>
    {
        Ok(Key4 {
            common: Default::default(),
            creation_time: creation_time,
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Creates a new OpenPGP public key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_public_cv25519<H, S, T>(public_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<time::Tm>>
    {
        let mut point = Vec::from(public_key);
        point.insert(0, 0x40);

        Ok(Key4 {
            common: Default::default(),
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

    /// Creates a new OpenPGP secret key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_cv25519<H, S, T>(private_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<time::Tm>>
    {
        use nettle::curve25519::{self, CURVE25519_SIZE};

        let mut public_key = [0x40u8; CURVE25519_SIZE + 1];
        curve25519::mul_g(&mut public_key[1..], private_key).unwrap();

        let mut private_key = Vec::from(private_key);
        private_key.reverse();

        Ok(Key4 {
            common: Default::default(),
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::ECDH,
            mpis: mpis::PublicKey::ECDH{
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or(HashAlgorithm::SHA512),
                sym: sym.into().unwrap_or(SymmetricAlgorithm::AES256),
                q: mpis::MPI::new(&public_key),
            },
            secret: Some(mpis::SecretKeyMaterial::ECDH {
                scalar: private_key.into(),
            }.into()),
        })
    }

    /// Creates a new OpenPGP public key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_public_ed25519<T>(public_key: &[u8], ctime: T) -> Result<Self>
        where  T: Into<Option<time::Tm>>
    {
        let mut point = Vec::from(public_key);
        point.insert(0, 0x40);

        Ok(Key4 {
            common: Default::default(),
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::EdDSA,
            mpis: mpis::PublicKey::EdDSA{
                curve: Curve::Ed25519,
                q: mpis::MPI::new(&point),
            },
            secret: None,
        })
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<time::Tm>>
    {
        use nettle::ed25519::{self, ED25519_KEY_SIZE};

        let mut public_key = [0x40u8; ED25519_KEY_SIZE + 1];
        ed25519::public_key(&mut public_key[1..], private_key).unwrap();

        Ok(Key4 {
            common: Default::default(),
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::EdDSA,
            mpis: mpis::PublicKey::EdDSA{
                curve: Curve::Ed25519,
                q: mpis::MPI::new(&public_key),
            },
            secret: Some(mpis::SecretKeyMaterial::EdDSA {
                scalar: mpis::MPI::new(private_key).into(),
            }.into()),
        })
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    pub fn import_public_rsa<T>(e: &[u8], n: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<time::Tm>>
    {
        Ok(Key4 {
            common: Default::default(),
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::RSAEncryptSign,
            mpis: mpis::PublicKey::RSA{
                e: mpis::MPI::new(e),
                n: mpis::MPI::new(n),
            },
            secret: None,
        })
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<time::Tm>>
    {
        use nettle::rsa;

        let sec = rsa::PrivateKey::new(d, p, q, None)?;
        let key = sec.public_key()?;
        let (a, b, c) = sec.as_rfc4880();

        Ok(Key4 {
            common: Default::default(),
            creation_time: ctime.into().unwrap_or(time::now()),
            pk_algo: PublicKeyAlgorithm::RSAEncryptSign,
            mpis: mpis::PublicKey::RSA{
                e: mpis::MPI::new(&key.e()[..]),
                n: mpis::MPI::new(&key.n()[..]),
            },
            secret: Some(mpis::SecretKeyMaterial::RSA {
                d: mpis::MPI::new(d).into(),
                p: mpis::MPI::new(&a[..]).into(),
                q: mpis::MPI::new(&b[..]).into(),
                u: mpis::MPI::new(&c[..]).into(),
            }.into()),
        })
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        use nettle::{rsa, Yarrow};
        use crate::crypto::mpis::{MPI, PublicKey};

        let mut rng = Yarrow::default();
        let (public, private) = rsa::generate_keypair(&mut rng, bits as u32)?;
        let (p, q, u) = private.as_rfc4880();
        let public_mpis = PublicKey::RSA {
            e: MPI::new(&*public.e()).into(),
            n: MPI::new(&*public.n()).into(),
        };
        let private_mpis = mpis::SecretKeyMaterial::RSA {
            d: MPI::new(&*private.d()).into(),
            p: MPI::new(&*p).into(),
            q: MPI::new(&*q).into(),
            u: MPI::new(&*u).into(),
        };
        let sec = Some(private_mpis.into());

        Ok(Key4 {
            common: Default::default(),
            creation_time: time::now().canonicalize(),
            pk_algo: PublicKeyAlgorithm::RSAEncryptSign,
            mpis: public_mpis,
            secret: sec,
        })
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true`
    /// and `curve == Cv25519` will produce an error.  Similar for
    /// `for_signing == false` and `curve == Ed25519`.
    /// signing/encryption
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        use nettle::{
            Yarrow,
            ed25519, ed25519::ED25519_KEY_SIZE,
            curve25519, curve25519::CURVE25519_SIZE,
            ecc, ecdh, ecdsa,
        };
        use crate::crypto::mpis::{MPI, PublicKey};
        use crate::PublicKeyAlgorithm::*;

        let mut rng = Yarrow::default();

        let (mpis, secret, pk_algo) = match (curve.clone(), for_signing) {
            (Curve::Ed25519, true) => {
                let mut public = [0u8; ED25519_KEY_SIZE + 1];
                let private: Protected =
                    ed25519::private_key(&mut rng).into();

                public[0] = 0x40;
                ed25519::public_key(&mut public[1..], &private)?;

                let public_mpis = PublicKey::EdDSA {
                    curve: Curve::Ed25519,
                    q: MPI::new(&public),
                };
                let private_mpis = mpis::SecretKeyMaterial::EdDSA {
                    scalar: private.into(),
                };
                let sec = Some(private_mpis.into());

                (public_mpis, sec, EdDSA)
            }

            (Curve::Cv25519, false) => {
                let mut public = [0u8; CURVE25519_SIZE + 1];
                let mut private: Protected =
                    curve25519::private_key(&mut rng).into();

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
                let private_mpis = mpis::SecretKeyMaterial::ECDH {
                    scalar: private.into(),
                };
                let sec = Some(private_mpis.into());

                (public_mpis, sec, ECDH)
            }

            (Curve::NistP256, true)  | (Curve::NistP384, true)
            | (Curve::NistP521, true) => {
                let (public, private, field_sz) = match curve {
                    Curve::NistP256 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp256r1, _>(&mut rng)?;
                        (pu, sec, 256)
                    }
                    Curve::NistP384 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp384r1, _>(&mut rng)?;
                        (pu, sec, 384)
                    }
                    Curve::NistP521 => {
                        let (pu, sec) =
                            ecdsa::generate_keypair::<ecc::Secp521r1, _>(&mut rng)?;
                        (pu, sec, 521)
                    }
                    _ => unreachable!(),
                };
                let (pub_x, pub_y) = public.as_bytes();
                let public_mpis =  mpis::PublicKey::ECDSA{
                    curve: curve,
                    q: MPI::new_weierstrass(&pub_x, &pub_y, field_sz),
                };
                let private_mpis = mpis::SecretKeyMaterial::ECDSA{
                    scalar: MPI::new(&private.as_bytes()).into(),
                };
                let sec = Some(private_mpis.into());

                (public_mpis, sec, ECDSA)
            }

            (Curve::NistP256, false)  | (Curve::NistP384, false)
            | (Curve::NistP521, false) => {
                    let (private, hash, field_sz) = match curve {
                        Curve::NistP256 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp256r1, _>(&mut rng);

                            (pv, HashAlgorithm::SHA256, 256)
                        }
                        Curve::NistP384 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp384r1, _>(&mut rng);

                            (pv, HashAlgorithm::SHA384, 384)
                        }
                        Curve::NistP521 => {
                            let pv =
                                ecc::Scalar::new_random::<ecc::Secp521r1, _>(&mut rng);

                            (pv, HashAlgorithm::SHA512, 521)
                        }
                        _ => unreachable!(),
                    };
                    let public = ecdh::point_mul_g(&private);
                    let (pub_x, pub_y) = public.as_bytes();
                    let public_mpis = mpis::PublicKey::ECDH{
                        curve: curve,
                        q: MPI::new_weierstrass(&pub_x, &pub_y, field_sz),
                        hash: hash,
                        sym: SymmetricAlgorithm::AES256,
                    };
                    let private_mpis = mpis::SecretKeyMaterial::ECDH{
                        scalar: MPI::new(&private.as_bytes()).into(),
                    };
                    let sec = Some(private_mpis.into());

                    (public_mpis, sec, ECDH)
                }

            (cv, _) => {
                return Err(Error::UnsupportedEllipticCurve(cv).into());
            }
        };

        Ok(Key4 {
            common: Default::default(),
            creation_time: time::now().canonicalize(),
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Gets the key packet's creation time field.
    pub fn creation_time(&self) -> &time::Tm {
        &self.creation_time
    }

    /// Sets the key packet's creation time field.
    pub fn set_creation_time(&mut self, timestamp: time::Tm) -> time::Tm {
        ::std::mem::replace(&mut self.creation_time, timestamp.canonicalize())
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm) -> PublicKeyAlgorithm {
        ::std::mem::replace(&mut self.pk_algo, pk_algo)
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
    pub fn set_mpis(&mut self, mpis: mpis::PublicKey) -> mpis::PublicKey {
        ::std::mem::replace(&mut self.mpis, mpis)
    }

    /// Gets the key packet's `SecretKeyMaterial`.
    pub fn secret(&self) -> Option<&SecretKeyMaterial> {
        self.secret.as_ref()
    }

    /// Gets a mutable reference to the key packet's `SecretKeyMaterial`.
    pub fn secret_mut(&mut self) -> Option<&mut SecretKeyMaterial> {
        self.secret.as_mut()
    }

    /// Sets the key packet's `SecretKeyMaterial`.
    ///
    /// Returns the old value.
    pub fn set_secret(&mut self, secret: Option<SecretKeyMaterial>)
        -> Option<SecretKeyMaterial>
    {
        std::mem::replace(&mut self.secret, secret)
    }

    /// Computes and returns the key's fingerprint as per Section 12.2
    /// of RFC 4880.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut h = HashAlgorithm::SHA1.context().unwrap();

        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Fingerprint::from_bytes(digest.as_slice())
    }

    /// Computes and returns the key's key ID as per Section 12.2 of
    /// RFC 4880.
    pub fn keyid(&self) -> KeyID {
        self.fingerprint().to_keyid()
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn into_packet(self, tag: Tag) -> Result<Packet> {
        match tag {
            Tag::PublicKey => Ok(Packet::PublicKey(self.into())),
            Tag::PublicSubkey => Ok(Packet::PublicSubkey(self.into())),
            Tag::SecretKey => Ok(Packet::SecretKey(self.into())),
            Tag::SecretSubkey => Ok(Packet::SecretSubkey(self.into())),
            _ => Err(Error::InvalidArgument(
                format!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag)).into()),
        }
    }
}

impl From<Key4> for super::Key {
    fn from(p: Key4) -> Self {
        super::Key::V4(p)
    }
}

/// Holds the secret potion of a OpenPGP secret key or secret subkey packet.
///
/// This type allows postponing the decryption of the secret key until we need to use it.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SecretKeyMaterial {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted(Unencrypted),
    /// The secret key is encrypted with a password.
    Encrypted(Encrypted),
}

impl From<mpis::SecretKeyMaterial> for SecretKeyMaterial {
    fn from(mpis: mpis::SecretKeyMaterial) -> Self {
        SecretKeyMaterial::Unencrypted(mpis.into())
    }
}

impl From<Unencrypted> for SecretKeyMaterial {
    fn from(key: Unencrypted) -> Self {
        SecretKeyMaterial::Unencrypted(key)
    }
}

impl From<Encrypted> for SecretKeyMaterial {
    fn from(key: Encrypted) -> Self {
        SecretKeyMaterial::Encrypted(key)
    }
}

impl SecretKeyMaterial {
    /// Decrypts this secret key using `password`.
    ///
    /// The `SecretKeyMaterial` type does not know what kind of key it is, so
    /// `pk_algo` is needed to parse the correct number of MPIs.
    pub fn decrypt_in_place(&mut self, pk_algo: PublicKeyAlgorithm,
                            password: &Password)
                            -> Result<()> {
        let new = match self {
            SecretKeyMaterial::Encrypted(ref e) =>
                Some(e.decrypt(pk_algo, password)?.into()),
            SecretKeyMaterial::Unencrypted(_) => None,
        };

        if let Some(v) = new {
            *self = v;
        }

        Ok(())
    }

    /// Encrypts this secret key using `password`.
    pub fn encrypt_in_place(&mut self, password: &Password) -> Result<()> {
        let new = match self {
            SecretKeyMaterial::Unencrypted(ref u) =>
                Some(u.encrypt(password)?.into()),
            SecretKeyMaterial::Encrypted(_) => None,
        };

        if let Some(v) = new {
            *self = v;
        }

        Ok(())
    }

    /// Returns true if this secret key is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretKeyMaterial::Encrypted(_) => true,
            SecretKeyMaterial::Unencrypted(_) => false,
        }
    }
}

/// Unencrypted secret key. Can be used as-is.
#[derive(Eq, Hash, Clone, Debug)]
pub struct Unencrypted {
    /// MPIs of the secret key.
    mpis: mem::Encrypted,
}

impl PartialEq for Unencrypted {
    fn eq(&self, other: &Self) -> bool {
        self.map(|a| other.map(|b| a == b))
    }
}

impl From<mpis::SecretKeyMaterial> for Unencrypted {
    fn from(mpis: mpis::SecretKeyMaterial) -> Self {
        use crate::serialize::Serialize;
        let mut plaintext = Vec::new();
        // We need to store the type.
        plaintext.push(
            mpis.algo().unwrap_or(PublicKeyAlgorithm::Unknown(0)).into());
        mpis.serialize(&mut plaintext)
            .expect("MPI serialization to vec failed");
        Unencrypted { mpis: mem::Encrypted::new(plaintext.into()), }
    }
}

impl Unencrypted {
    /// Maps the given function over the secret.
    pub fn map<F, T>(&self, mut fun: F) -> T
        where F: FnMut(&mpis::SecretKeyMaterial) -> T
    {
        self.mpis.map(|plaintext| {
            let algo: PublicKeyAlgorithm = plaintext[0].into();
            let mpis = mpis::SecretKeyMaterial::parse(algo, &plaintext[1..])
                .expect("Decrypted secret key is malformed");
            fun(&mpis)
        })
    }

    /// Encrypts this secret key using `password`.
    pub fn encrypt(&self, password: &Password)
                   -> Result<Encrypted> {
        use std::io::Write;
        use crate::crypto::symmetric::Encryptor;

        let s2k = S2K::default();
        let algo = SymmetricAlgorithm::AES256;
        let key = s2k.derive_key(password, algo.key_size()?)?;

        // Ciphertext is preceded by a random block.
        let mut trash = vec![0u8; algo.block_size()?];
        crypto::random(&mut trash);

        let mut esk = Vec::new();
        {
            let mut encryptor = Encryptor::new(algo, &key, &mut esk)?;
            encryptor.write_all(&trash)?;
            self.map(|mpis| mpis.serialize_chksumd(&mut encryptor))?;
        }

        Ok(Encrypted { s2k, algo, ciphertext: esk.into_boxed_slice() })
    }
}

/// The secret key is encrypted with a password.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Encrypted {
    /// Key derivation mechanism to use.
    s2k: S2K,
    /// Symmetric algorithm used for encryption the secret key.
    algo: SymmetricAlgorithm,
    /// Encrypted MPIs prefixed with the IV.
    ciphertext: Box<[u8]>,
}

impl Encrypted {
    /// Creates a new encrypted key object.
    pub fn new(s2k: S2K, algo: SymmetricAlgorithm, ciphertext: Box<[u8]>)
               -> Self {
        Encrypted { s2k, algo, ciphertext }
    }

    /// Returns the key derivation mechanism.
    pub fn s2k(&self) -> &S2K {
        &self.s2k
    }

    /// Returns the symmetric algorithm used for encryption the secret
    /// key.
    pub fn algo(&self) -> SymmetricAlgorithm {
        self.algo
    }

    /// Returns the key derivation mechanism.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Decrypts this secret key using `password`.
    ///
    /// The `Encrypted` key does not know what kind of key it is, so
    /// `pk_algo` is needed to parse the correct number of MPIs.
    pub fn decrypt(&self, pk_algo: PublicKeyAlgorithm, password: &Password)
                   -> Result<Unencrypted> {
        use std::io::{Cursor, Read};
        use crate::crypto::symmetric::Decryptor;

        let key = self.s2k.derive_key(password, self.algo.key_size()?)?;
        let cur = Cursor::new(&self.ciphertext);
        let mut dec = Decryptor::new(self.algo, &key, cur)?;

        // Consume the first block.
        let mut trash = vec![0u8; self.algo.block_size()?];
        dec.read_exact(&mut trash)?;

        mpis::SecretKeyMaterial::parse_chksumd(pk_algo, &mut dec).map(|m| m.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::Key;
    use crate::TPK;
    use crate::packet::pkesk::PKESK3;
    use crate::packet::key::SecretKeyMaterial;
    use super::*;
    use crate::PacketPile;
    use crate::serialize::Serialize;
    use crate::parse::Parse;

    #[test]
    fn encrypted_rsa_key() {
        let mut tpk = TPK::from_bytes(
            crate::tests::key("testy-new-encrypted-with-123.pgp")).unwrap();
        let pair = tpk.primary_mut();
        let pk_algo = pair.pk_algo();
        let secret = pair.secret.as_mut().unwrap();

        assert!(secret.is_encrypted());
        secret.decrypt_in_place(pk_algo, &"123".into()).unwrap();
        assert!(!secret.is_encrypted());

        match secret {
            SecretKeyMaterial::Unencrypted(ref u) => u.map(|mpis| match mpis {
                mpis::SecretKeyMaterial::RSA { .. } => (),
                _ => panic!(),
            }),
            _ => panic!(),
        }
    }

    #[test]
    fn eq() {
        use crate::constants::Curve::*;

        for curve in vec![NistP256, NistP384, NistP521] {
            let sign_key = Key4::generate_ecc(true, curve.clone()).unwrap();
            let enc_key = Key4::generate_ecc(false, curve).unwrap();
            let sign_clone = sign_key.clone();
            let enc_clone = enc_key.clone();

            assert_eq!(sign_key, sign_clone);
            assert_eq!(enc_key, enc_clone);
        }

        for bits in vec![1024, 2048, 3072, 4096] {
            let key = Key4::generate_rsa(bits).unwrap();
            let clone = key.clone();
            assert_eq!(key, clone);
        }
    }

    #[test]
    fn roundtrip() {
        use crate::constants::Curve::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter().flat_map(|cv| {
            let sign_key = Key4::generate_ecc(true, cv.clone()).unwrap();
            let enc_key = Key4::generate_ecc(false, cv).unwrap();

            vec![sign_key, enc_key]
        }).chain(vec![1024, 2048, 3072, 4096].into_iter().map(|b| {
            Key4::generate_rsa(b).unwrap()
        }));

        for mut key in keys {
            let mut b = Vec::new();
            Packet::SecretKey(key.clone().into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::SecretKey(Key::V4(ref parsed_key))) =
                pp.path_ref(&[0])
            {
                assert_eq!(key.common, parsed_key.common);
                assert_eq!(key.creation_time, parsed_key.creation_time);
                assert_eq!(key.pk_algo, parsed_key.pk_algo);
                assert_eq!(key.mpis, parsed_key.mpis);
                assert_eq!(key.secret, parsed_key.secret);

                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }

            let mut b = Vec::new();
            Packet::PublicKey(key.clone().into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::PublicKey(Key::V4(ref parsed_key))) =
                pp.path_ref(&[0])
            {
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
        use crate::crypto::SessionKey;
        use crate::constants::Curve::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter().map(|cv| {
            Key4::generate_ecc(false, cv).unwrap()
        }).chain(vec![1024, 2048, 3072, 4096].into_iter().map(|b| {
            Key4::generate_rsa(b).unwrap()
        }));

        for key in keys.into_iter() {
            let key = Key::from(key);
            let mut keypair = key.clone().into_keypair().unwrap();
            let cipher = SymmetricAlgorithm::AES256;
            let sk = SessionKey::new(cipher.key_size().unwrap());

            let pkesk = PKESK3::for_recipient(cipher, &sk, &key).unwrap();
            let (cipher_, sk_) = pkesk.decrypt(&mut keypair).unwrap();

            assert_eq!(cipher, cipher_);
            assert_eq!(sk, sk_);
        }
    }

    #[test]
    fn secret_encryption_roundtrip() {
        use crate::constants::Curve::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter().map(|cv| {
            Key4::generate_ecc(false, cv).unwrap()
        }).chain(vec![1024, 2048, 3072, 4096].into_iter().map(|b| {
            Key4::generate_rsa(b).unwrap()
        }));

        for key in keys {
            assert!(! key.secret().unwrap().is_encrypted());

            let password = Password::from("foobarbaz");
            let mut encrypted_key = key.clone();

            encrypted_key.secret_mut().unwrap()
                .encrypt_in_place(&password).unwrap();
            assert!(encrypted_key.secret().unwrap().is_encrypted());

            encrypted_key.secret_mut().unwrap()
                .decrypt_in_place(key.pk_algo, &password).unwrap();
            assert!(! key.secret().unwrap().is_encrypted());
            assert_eq!(key, encrypted_key);
            assert_eq!(key.secret(), encrypted_key.secret());
        }
    }

    #[test]
    fn import_cv25519() {
        use crate::crypto::{ecdh, mem, SessionKey};
        use self::mpis::{MPI, Ciphertext};
        use time::{at, Timespec};

        // X25519 key
        let ctime = at(Timespec::new(0x5c487129,0));
        let public = b"\xed\x59\x0a\x15\x08\x95\xe9\x92\xd2\x2c\x14\x01\xb3\xe9\x3b\x7f\xff\xe6\x6f\x22\x65\xec\x69\xd9\xb8\xda\x24\x2c\x64\x84\x44\x11";
        let key = Key4::import_public_cv25519(&public[..],
                                              HashAlgorithm::SHA256,
                                              SymmetricAlgorithm::AES128,
                                              ctime).unwrap().into();

        // PKESK
        let eph_pubkey = MPI::new(&b"\x40\xda\x1c\x69\xc4\xe3\xb6\x9c\x6e\xd4\xc6\x69\x6c\x89\xc7\x09\xe9\xf8\x6a\xf1\xe3\x8d\xb6\xaa\xb5\xf7\x29\xae\xa6\xe7\xdd\xfe\x38"[..]);
        let ciphertext = Ciphertext::ECDH{
            e: eph_pubkey.clone(),
            key: Vec::from(&b"\x45\x8b\xd8\x4d\x88\xb3\xd2\x16\xb6\xc2\x3b\x99\x33\xd1\x23\x4b\x10\x15\x8e\x04\x16\xc5\x7c\x94\x88\xf6\x63\xf2\x68\x37\x08\x66\xfd\x5a\x7b\x40\x58\x21\x6b\x2c\xc0\xf4\xdc\x91\xd3\x48\xed\xc1"[..]).into_boxed_slice()
        };
        let shared_sec: mem::Protected = b"\x44\x0C\x99\x27\xF7\xD6\x1E\xAD\xD1\x1E\x9E\xC8\x22\x2C\x5D\x43\xCE\xB0\xE5\x45\x94\xEC\xAF\x67\xD9\x35\x1D\xA1\xA3\xA8\x10\x0B"[..].into();

        // Session key
        let dek = b"\x09\x0D\xDC\x40\xC5\x71\x51\x88\xAC\xBD\x45\x56\xD4\x2A\xDF\x77\xCD\xF4\x82\xA2\x1B\x8F\x2E\x48\x3B\xCA\xBF\xD3\xE8\x6D\x0A\x7C\xDF\x10\xe6";
        let sk = SessionKey::from(Vec::from(&dek[..]));

        // Expected
        let got_enc = ecdh::encrypt_shared(&key, &sk, eph_pubkey, &shared_sec)
            .unwrap();

        assert_eq!(ciphertext, got_enc);
    }

    #[test]
    fn import_cv25519_sec() {
        use crate::crypto::ecdh;
        use self::mpis::{MPI, Ciphertext};
        use time::{at, Timespec};

        // X25519 key
        let ctime = at(Timespec::new(0x5c487129,0));
        let public = b"\xed\x59\x0a\x15\x08\x95\xe9\x92\xd2\x2c\x14\x01\xb3\xe9\x3b\x7f\xff\xe6\x6f\x22\x65\xec\x69\xd9\xb8\xda\x24\x2c\x64\x84\x44\x11";
        let secret = b"\xa0\x27\x13\x99\xc9\xe3\x2e\xd2\x47\xf6\xd6\x63\x9d\xe6\xec\xcb\x57\x0b\x92\xbb\x17\xfe\xb8\xf1\xc4\x1f\x06\x7c\x55\xfc\xdd\x58";
        let key: Key = Key4::import_secret_cv25519(&secret[..],
                                                   HashAlgorithm::SHA256,
                                                   SymmetricAlgorithm::AES128,
                                                   ctime).unwrap().into();
        match key.mpis {
            self::mpis::PublicKey::ECDH{ ref q,.. } =>
                assert_eq!(&q.value()[1..], &public[..]),
            _ => unreachable!(),
        }

        // PKESK
        let eph_pubkey: &[u8; 33] = b"\x40\xda\x1c\x69\xc4\xe3\xb6\x9c\x6e\xd4\xc6\x69\x6c\x89\xc7\x09\xe9\xf8\x6a\xf1\xe3\x8d\xb6\xaa\xb5\xf7\x29\xae\xa6\xe7\xdd\xfe\x38";
        let ciphertext = Ciphertext::ECDH{
            e: MPI::new(&eph_pubkey[..]),
            key: Vec::from(&b"\x45\x8b\xd8\x4d\x88\xb3\xd2\x16\xb6\xc2\x3b\x99\x33\xd1\x23\x4b\x10\x15\x8e\x04\x16\xc5\x7c\x94\x88\xf6\x63\xf2\x68\x37\x08\x66\xfd\x5a\x7b\x40\x58\x21\x6b\x2c\xc0\xf4\xdc\x91\xd3\x48\xed\xc1"[..]).into_boxed_slice()
        };

        // Session key
        let dek = b"\x09\x0D\xDC\x40\xC5\x71\x51\x88\xAC\xBD\x45\x56\xD4\x2A\xDF\x77\xCD\xF4\x82\xA2\x1B\x8F\x2E\x48\x3B\xCA\xBF\xD3\xE8\x6D\x0A\x7C\xDF\x10\xe6";

        let got_dek = match key.secret() {
            Some(SecretKeyMaterial::Unencrypted(ref u)) => u.map(|mpis| {
                ecdh::decrypt(&key, mpis, &ciphertext).unwrap()
            }),
            _ => unreachable!(),
        };

        assert_eq!(&dek[..], &got_dek[..]);
    }

    #[test]
    fn import_rsa() {
        use crate::crypto::SessionKey;
        use self::mpis::{MPI, Ciphertext};
        use time::{at, Timespec};

        // RSA key
        let ctime = at(Timespec::new(1548950502,0));
        let d = b"\x14\xC4\x3A\x0C\x3A\x79\xA4\xF7\x63\x0D\x89\x93\x63\x8B\x56\x9C\x29\x2E\xCD\xCF\xBF\xB0\xEC\x66\x52\xC3\x70\x1B\x19\x21\x73\xDE\x8B\xAC\x0E\xF2\xE1\x28\x42\x66\x56\x55\x00\x3B\xFD\x50\xC4\x7C\xBC\x9D\xEB\x7D\xF4\x81\xFC\xC3\xBF\xF7\xFF\xD0\x41\x3E\x50\x3B\x5F\x5D\x5F\x56\x67\x5E\x00\xCE\xA4\x53\xB8\x59\xA0\x40\xC8\x96\x6D\x12\x09\x27\xBE\x1D\xF1\xC2\x68\xFC\xF0\x14\xD6\x52\x77\x07\xC8\x12\x36\x9C\x9A\x5C\xAF\x43\xCC\x95\x20\xBB\x0A\x44\x94\xDD\xB4\x4F\x45\x4E\x3A\x1A\x30\x0D\x66\x40\xAC\x68\xE8\xB0\xFD\xCD\x6C\x6B\x6C\xB5\xF7\xE4\x36\x95\xC2\x96\x98\xFD\xCA\x39\x6C\x1A\x2E\x55\xAD\xB6\xE0\xF8\x2C\xFF\xBC\xD3\x32\x15\x52\x39\xB3\x92\x35\xDB\x8B\x68\xAF\x2D\x4A\x6E\x64\xB8\x28\x63\xC4\x24\x94\x2D\xA9\xDB\x93\x56\xE3\xBC\xD0\xB6\x38\x84\x04\xA4\xC6\x18\x48\xFE\xB2\xF8\xE1\x60\x37\x52\x96\x41\xA5\x79\xF6\x3D\xB7\x2A\x71\x5B\x7A\x75\xBF\x7F\xA2\x5A\xC8\xA1\x38\xF2\x5A\xBD\x14\xFC\xAF\xB4\x54\x83\xA4\xBD\x49\xA2\x8B\x91\xB0\xE0\x4A\x1B\x21\x54\x07\x19\x70\x64\x7C\x3E\x9F\x8D\x8B\xE4\x70\xD1\xE7\xBE\x4E\x5C\xCE\xF1";
        let p = b"\xC8\x32\xD1\x17\x41\x4D\x8F\x37\x09\x18\x32\x4C\x4C\xF4\xA2\x15\x27\x43\x3D\xBB\xB5\xF6\x1F\xCF\xD2\xE4\x43\x61\x07\x0E\x9E\x35\x1F\x0A\x5D\xFB\x3A\x45\x74\x61\x73\x73\x7B\x5F\x1F\x87\xFB\x54\x8D\xA8\x85\x3E\xB0\xB7\xC7\xF5\xC9\x13\x99\x8D\x40\xE6\xA6\xD0\x71\x3A\xE3\x2D\x4A\xC3\xA3\xFF\xF7\x72\x82\x14\x52\xA4\xBA\x63\x0E\x17\xCA\xCA\x18\xC4\x3A\x40\x79\xF1\x86\xB3\x10\x4B\x9F\xB2\xAE\x2E\x13\x38\x8D\x2C\xF9\x88\x4C\x25\x53\xEF\xF9\xD1\x8B\x1A\x7C\xE7\xF6\x4B\x73\x51\x31\xFA\x44\x1D\x36\x65\x71\xDA\xFC\x6F";
        let q = b"\xCC\x30\xE9\xCC\xCB\x31\x28\xB5\x90\xFF\x06\x62\x42\x5B\x24\x0E\x00\xFE\xE2\x37\xC4\xAC\xBB\x3B\x8F\xF2\x0E\x3F\x78\xCF\x6B\x7C\xE8\x75\x57\x7C\x15\x9D\x1A\x66\xF2\x0A\xE5\xD3\x0B\xE7\x40\xF7\xE7\x00\xB6\x86\xB5\xD9\x20\x67\xE0\x4A\xC0\x90\xA4\x13\x4D\xC9\xB0\x12\xC5\xCD\x4C\xEB\xA1\x91\x2D\x43\x58\x6E\xB6\x75\xA0\x93\xF0\x5B\xC5\x31\xCA\xB7\xC6\x22\x0C\xD3\xEC\x84\xC5\x91\xA1\x5F\x2C\x8E\x07\x5D\xA1\x98\x67\xC5\x7A\x58\x16\x71\x3D\xED\x91\x03\x0D\xD4\x25\x07\x89\x9B\x33\x98\xA3\x70\xD9\xE7\xC8\x17\xA3\xD9";
        let key: Key = Key4::import_secret_rsa(&d[..], &p[..], &q[..], ctime)
            .unwrap().into();

        // PKESK
        let c = b"\x8A\x1A\xD4\x82\x91\x6B\xBF\xA1\x65\xD3\x82\x8C\x97\xAB\xD0\x91\xE4\xB4\xC4\x9D\x08\xD8\x8B\xB7\xE6\x13\x3F\x6F\x52\x14\xED\xC4\x77\xB7\x31\x00\xC1\x43\xF9\x62\x53\xBF\x21\x21\x52\x74\x35\xD8\xC7\xA2\x11\x89\xA5\xD5\x21\x98\x6D\x3C\x9F\xF0\xED\xDB\xD7\x0F\xAC\x3C\x15\x25\x34\x52\xC7\x7C\x82\x07\x5A\x99\xC1\xC6\xF6\xF2\x6D\x46\xC8\x56\x59\xE7\xC6\x34\x0C\xCA\x37\x70\xB4\x97\xDA\x18\x14\xC4\x03\x0A\xCB\xE5\x0C\x41\x43\x61\xBA\x32\xB6\x9A\xF3\xDF\x0C\xB0\xCE\xBD\xFE\x72\x6C\xCC\xC1\xE8\xF0\x05\x97\x61\xEA\x30\x10\xB9\x43\xC4\x9A\x41\xED\x72\x27\xA4\xD5\xE7\x08\x41\x6C\x57\x80\xF3\x64\xF0\x45\x70\x27\x36\xBD\x64\x59\x74\xCF\xCD\x39\xE6\xEB\x7C\x62\xC8\x38\x23\xF8\x4C\xB7\x30\x9F\xF1\x40\x4A\xE9\x72\x66\x99\xF7\x2A\x47\x1C\xE7\x12\x20\x58\xBA\x87\x00\xB8\xFC\x54\xBC\xA5\x1D\x7D\x8B\x50\xA4\x4B\xB3\xD7\x44\xC7\x68\x5E\x2D\xBB\xE9\x6E\xC4\xD0\x31\xB0\xD0\xB6\x02\xD1\x74\x6B\xC9\x3D\x19\x32\x3B\xF1\x0E\x74\xF6\x12\x13\xE6\x40\x8F\xA6\x97\xAD\x83\xB0\x84\xD6\xD9\xE5\x25\x8E\x57\x0B\x7A\x7B\xD0\x5C\x29\x96\xED\x29\xED";
        let ciphertext = Ciphertext::RSA{
            c: MPI::new(&c[..]),
        };
        let pkesk = PKESK3::new(key.keyid(), PublicKeyAlgorithm::RSAEncryptSign,
                                ciphertext).unwrap();

        // Session key
        let dek = b"\xA5\x58\x3A\x04\x35\x8B\xC7\x3F\x4A\xEF\x0C\x5A\xEB\xED\x59\xCA\xFD\x96\xB5\x32\x23\x26\x0C\x91\x78\xD1\x31\x12\xF0\x41\x42\x9D";
        let sk = SessionKey::from(Vec::from(&dek[..]));

        // Expected
        let mut decryptor = key.into_keypair().unwrap();
        let got_sk = pkesk.decrypt(&mut decryptor).unwrap();

        assert_eq!(got_sk.1, sk);
    }

    #[test]
    fn import_ed25519() {
        use time::{at, Timespec};
        use crate::{Fingerprint, KeyID};
        use crate::constants::SignatureType;
        use crate::packet::signature::Signature4;
        use crate::packet::signature::subpacket::{
            Subpacket, SubpacketValue, SubpacketArea};

        // Ed25519 key
        let ctime = at(Timespec::new(1548249630,0));
        let q = b"\x57\x15\x45\x1B\x68\xA5\x13\xA2\x20\x0F\x71\x9D\xE3\x05\x3B\xED\xA2\x21\xDE\x61\x5A\xF5\x67\x45\xBB\x97\x99\x43\x53\x59\x7C\x3F";
        let key: Key = Key4::import_public_ed25519(q, ctime).unwrap().into();

        let mut hashed = SubpacketArea::empty();
        let mut unhashed = SubpacketArea::empty();
        let fpr = Fingerprint::from_hex("D81A 5DC0 DEBF EE5F 9AC8  20EB 6769 5DB9 920D 4FAC").unwrap();
        let kid = KeyID::from_hex("6769 5DB9 920D 4FAC").unwrap();
        let ctime = at(Timespec::new(1549460479,0));
        let r = b"\x5A\xF9\xC7\x42\x70\x24\x73\xFF\x7F\x27\xF9\x20\x9D\x20\x0F\xE3\x8F\x71\x3C\x5F\x97\xFD\x60\x80\x39\x29\xC2\x14\xFD\xC2\x4D\x70";
        let s = b"\x6E\x68\x74\x11\x72\xF4\x9C\xE1\x99\x99\x1F\x67\xFC\x3A\x68\x33\xF9\x3F\x3A\xB9\x1A\xA5\x72\x4E\x78\xD4\x81\xCB\x7B\xA5\xE5\x0A";

        hashed.add(Subpacket::new(SubpacketValue::IssuerFingerprint(fpr), false).unwrap()).unwrap();
        hashed.add(Subpacket::new(SubpacketValue::SignatureCreationTime(ctime), false).unwrap()).unwrap();
        unhashed.add(Subpacket::new(SubpacketValue::Issuer(kid), false).unwrap()).unwrap();

        eprintln!("fpr: {}", key.fingerprint());
        let sig = Signature4::new(SignatureType::Binary, PublicKeyAlgorithm::EdDSA,
                                  HashAlgorithm::SHA256, hashed, unhashed,
                                  [0xa7,0x19],
                                  mpis::Signature::EdDSA{
                                      r: mpis::MPI::new(r), s: mpis::MPI::new(s)
                                  });
        assert_eq!(sig.verify_message(&key, b"Hello, World\n").ok(), Some(true));
    }

    #[test]
    fn fingerprint_test() {
        let pile =
            PacketPile::from_bytes(crate::tests::key("public-key.gpg")).unwrap();

        // The blob contains a public key and a three subkeys.
        let mut pki = 0;
        let mut ski = 0;

        let pks = [ "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9" ];
        let sks = [ "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528",
                    "50E6 D924 308D BF22 3CFB  510A C2B8 1905 6C65 2598",
                    "2DC5 0AB5 5BE2 F3B0 4C2D  2CF8 A350 6AFB 820A BD08"];

        for p in pile.descendants() {
            if let &Packet::PublicKey(ref p) = p {
                let fp = p.fingerprint().to_string();
                // eprintln!("PK: {:?}", fp);

                assert!(pki < pks.len());
                assert_eq!(fp, pks[pki]);
                pki += 1;
            }

            if let &Packet::PublicSubkey(ref p) = p {
                let fp = p.fingerprint().to_string();
                // eprintln!("SK: {:?}", fp);

                assert!(ski < sks.len());
                assert_eq!(fp, sks[ski]);
                ski += 1;
            }
        }
        assert!(pki == pks.len() && ski == sks.len());
    }
}
