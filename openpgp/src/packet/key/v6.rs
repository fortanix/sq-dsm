//! OpenPGP v6 key packet.

use std::fmt;
use std::cmp::Ordering;
use std::hash::Hasher;
use std::time;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::crypto::{mpi, hash::Hash, mem::Protected, KeyPair};
use crate::packet::key::{
    KeyParts,
    KeyRole,
    KeyRoleRT,
    PublicParts,
    SecretParts,
    UnspecifiedParts,
};
use crate::packet::prelude::*;
use crate::PublicKeyAlgorithm;
use crate::HashAlgorithm;
use crate::types::Timestamp;
use crate::Result;
use crate::crypto::Password;
use crate::KeyID;
use crate::Fingerprint;
use crate::KeyHandle;
use crate::policy::HashAlgoSecurity;

/// Holds a public key, public subkey, private key or private subkey
/// packet.
///
/// Use [`Key6::generate_rsa`] or [`Key6::generate_ecc`] to create a
/// new key.
///
/// Existing key material can be turned into an OpenPGP key using
/// [`Key6::new`], [`Key6::with_secret`], [`Key6::import_public_x25519`],
/// [`Key6::import_public_ed25519`], [`Key6::import_public_rsa`],
/// [`Key6::import_secret_x25519`], [`Key6::import_secret_ed25519`],
/// and [`Key6::import_secret_rsa`].
///
/// Whether you create a new key or import existing key material, you
/// still need to create a binding signature, and, for signing keys, a
/// back signature before integrating the key into a certificate.
///
/// Normally, you won't directly use `Key6`, but [`Key`], which is a
/// relatively thin wrapper around `Key6`.
///
/// See [Section 5.5 of RFC 9580] and [the documentation for `Key`]
/// for more details.
///
/// [Section 5.5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5
/// [the documentation for `Key`]: super::Key
/// [`Key`]: super::Key
#[derive(PartialEq, Eq, Hash)]
pub struct Key6<P: KeyParts, R: KeyRole> {
    pub(crate) common: Key4<P, R>,
}

// derive(Clone) doesn't work as expected with generic type parameters
// that don't implement clone: it adds a trait bound on Clone to P and
// R in the Clone implementation.  Happily, we don't need P or R to
// implement Clone: they are just marker traits, which we can clone
// manually.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<P, R> Clone for Key6<P, R>
    where P: KeyParts, R: KeyRole
{
    fn clone(&self) -> Self {
        Key6 {
            common: self.common.clone(),
        }
    }
}

impl<P, R> fmt::Debug for Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key6")
            .field("fingerprint", &self.fingerprint())
            .field("creation_time", &self.creation_time())
            .field("pk_algo", &self.pk_algo())
            .field("mpis", &self.mpis())
            .field("secret", &self.optional_secret())
            .finish()
    }
}

impl<P, R> fmt::Display for Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl<P, R> Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    /// The security requirements of the hash algorithm for
    /// self-signatures.
    ///
    /// A cryptographic hash algorithm usually has [three security
    /// properties]: pre-image resistance, second pre-image
    /// resistance, and collision resistance.  If an attacker can
    /// influence the signed data, then the hash algorithm needs to
    /// have both second pre-image resistance, and collision
    /// resistance.  If not, second pre-image resistance is
    /// sufficient.
    ///
    ///   [three security properties]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Properties
    ///
    /// In general, an attacker may be able to influence third-party
    /// signatures.  But direct key signatures, and binding signatures
    /// are only over data fully determined by signer.  And, an
    /// attacker's control over self signatures over User IDs is
    /// limited due to their structure.
    ///
    /// These observations can be used to extend the life of a hash
    /// algorithm after its collision resistance has been partially
    /// compromised, but not completely broken.  For more details,
    /// please refer to the documentation for [HashAlgoSecurity].
    ///
    ///   [HashAlgoSecurity]: crate::policy::HashAlgoSecurity
    pub fn hash_algo_security(&self) -> HashAlgoSecurity {
        HashAlgoSecurity::SecondPreImageResistance
    }

    /// Compares the public bits of two keys.
    ///
    /// This returns `Ordering::Equal` if the public MPIs, creation
    /// time, and algorithm of the two `Key6`s match.  This does not
    /// consider the packets' encodings, packets' tags or their secret
    /// key material.
    pub fn public_cmp<PB, RB>(&self, b: &Key6<PB, RB>) -> Ordering
    where PB: KeyParts,
          RB: KeyRole,
    {
        self.mpis().cmp(b.mpis())
            .then_with(|| self.creation_time().cmp(&b.creation_time()))
            .then_with(|| self.pk_algo().cmp(&b.pk_algo()))
    }

    /// Tests whether two keys are equal modulo their secret key
    /// material.
    ///
    /// This returns true if the public MPIs, creation time and
    /// algorithm of the two `Key6`s match.  This does not consider
    /// the packets' encodings, packets' tags or their secret key
    /// material.
    pub fn public_eq<PB, RB>(&self, b: &Key6<PB, RB>) -> bool
    where PB: KeyParts,
          RB: KeyRole,
    {
        self.public_cmp(b) == Ordering::Equal
    }

    /// Hashes everything but any secret key material into state.
    ///
    /// This is an alternate implementation of [`Hash`], which never
    /// hashes the secret key material.
    ///
    ///   [`Hash`]: std::hash::Hash
    pub fn public_hash<H>(&self, state: &mut H)
    where H: Hasher
    {
        self.common.public_hash(state);
    }
}

impl<P, R> Key6<P, R>
where
    P: KeyParts,
    R: KeyRole,
{
    /// Gets the `Key`'s creation time.
    pub fn creation_time(&self) -> time::SystemTime {
        self.common.creation_time()
    }

    /// Gets the `Key`'s creation time without converting it to a
    /// system time.
    ///
    /// This conversion may truncate the time to signed 32-bit time_t.
    pub(crate) fn creation_time_raw(&self) -> Timestamp {
        self.common.creation_time_raw()
    }

    /// Sets the `Key`'s creation time.
    ///
    /// `timestamp` is converted to OpenPGP's internal format,
    /// [`Timestamp`]: a 32-bit quantity containing the number of
    /// seconds since the Unix epoch.
    ///
    /// `timestamp` is silently rounded to match the internal
    /// resolution.  An error is returned if `timestamp` is out of
    /// range.
    ///
    /// [`Timestamp`]: crate::types::Timestamp
    pub fn set_creation_time<T>(&mut self, timestamp: T)
                                -> Result<time::SystemTime>
    where T: Into<time::SystemTime>
    {
        self.common.set_creation_time(timestamp)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.common.pk_algo()
    }

    /// Sets the public key algorithm.
    ///
    /// Returns the old public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm)
                       -> PublicKeyAlgorithm
    {
        self.common.set_pk_algo(pk_algo)
    }

    /// Returns a reference to the `Key`'s MPIs.
    pub fn mpis(&self) -> &mpi::PublicKey {
        self.common.mpis()
    }

    /// Returns a mutable reference to the `Key`'s MPIs.
    pub fn mpis_mut(&mut self) -> &mut mpi::PublicKey {
        self.common.mpis_mut()
    }

    /// Sets the `Key`'s MPIs.
    ///
    /// This function returns the old MPIs, if any.
    pub fn set_mpis(&mut self, mpis: mpi::PublicKey) -> mpi::PublicKey {
        self.common.set_mpis(mpis)
    }

    /// Returns whether the `Key` contains secret key material.
    pub fn has_secret(&self) -> bool {
        self.common.has_secret()
    }

    /// Returns whether the `Key` contains unencrypted secret key
    /// material.
    ///
    /// This returns false if the `Key` doesn't contain any secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool {
        self.common.has_unencrypted_secret()
    }

    /// Returns `Key`'s secret key material, if any.
    pub fn optional_secret(&self) -> Option<&SecretKeyMaterial> {
        self.common.optional_secret()
    }

    /// Computes and returns the `Key`'s `Fingerprint` and returns it as
    /// a `KeyHandle`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn key_handle(&self) -> KeyHandle {
        self.fingerprint().into()
    }

    /// Computes and returns the `Key`'s `Fingerprint`.
    ///
    /// See [Key IDs and Fingerprints].
    ///
    /// [Key IDs and Fingerprints]: https://www.rfc-editor.org/rfc/rfc9580.html#key-ids-fingerprints
    pub fn fingerprint(&self) -> Fingerprint {
        let fp = self.common.fingerprint.get_or_init(|| {
            let mut h = HashAlgorithm::SHA256.context()
                .expect("SHA256 is MTI for RFC9580")
            // v6 fingerprints are computed the same way a key is
            // hashed for v6 signatures.
                .for_signature(6);

            self.hash(&mut h).expect("v6 key hashing is infallible");

            let mut digest = [0u8; 32];
            let _ = h.digest(&mut digest);
            Fingerprint::V6(digest)
        });

        // Currently, it could happen that a Key4 has its fingerprint
        // computed, and is then converted to a Key6.  That is only
        // possible within this crate, and should not happen.  Assert
        // that.  The better way to handle this is to have a CommonKey
        // struct which both Key4 and Key6 use, so that a Key6 does
        // not start out as a Key4, preventing this issue.
        debug_assert!(matches!(fp, Fingerprint::V6(_)));

        fp.clone()
    }

    /// Computes and returns the `Key`'s `Key ID`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn keyid(&self) -> KeyID {
        self.fingerprint().into()
    }

    /// Creates a v6 key from a v4 key.  Used internally in
    /// constructors.
    pub(crate) fn from_common(common: Key4<P, R>) -> Self {
        Key6 { common }
    }

    /// Creates an OpenPGP public key from the specified key material.
    ///
    /// This is an internal version for parse.rs that avoids going
    /// through SystemTime.
    pub(crate) fn make(creation_time: Timestamp,
                       pk_algo: PublicKeyAlgorithm,
                       mpis: mpi::PublicKey,
                       secret: Option<SecretKeyMaterial>)
                       -> Result<Self>
    where
    {
        Ok(Key6 {
            common: Key4::make(creation_time, pk_algo, mpis, secret)?,
        })
    }

    pub(crate) fn role(&self) -> KeyRoleRT {
        self.common.role()
    }

    pub(crate) fn set_role(&mut self, role: KeyRoleRT) {
        self.common.set_role(role);
    }
}

impl<R> Key6<key::PublicParts, R>
where R: KeyRole,
{
    /// Creates an OpenPGP public key from the specified key material.
    pub fn new<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                  mpis: mpi::PublicKey)
                  -> Result<Self>
    where T: Into<time::SystemTime>
    {
        Ok(Key6 {
            common: Key4::new(creation_time, pk_algo, mpis)?,
        })
    }

    /// Creates an OpenPGP public key packet from existing X25519 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_x25519<T>(public_key: &[u8], ctime: T)
                                   -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::X25519,
                              mpi::PublicKey::X25519 {
                                  u: public_key.try_into()?,
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing X448 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_x448<T>(public_key: &[u8], ctime: T)
                                 -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::X448,
                              mpi::PublicKey::X448 {
                                  u: Box::new(public_key.try_into()?),
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing Ed25519 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_ed25519<T>(public_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::Ed25519,
                              mpi::PublicKey::Ed25519 {
                                  a: public_key.try_into()?,
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing Ed448 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_ed448<T>(public_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::Ed448,
                              mpi::PublicKey::Ed448 {
                                  a: Box::new(public_key.try_into()?),
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing RSA key
    /// material.
    ///
    /// The RSA key will use the public exponent `e` and the modulo
    /// `n`. The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_rsa<T>(e: &[u8], n: &[u8], ctime: T)
                                -> Result<Self> where T: Into<Option<time::SystemTime>>
    {
        Ok(Key6 {
            common: Key4::import_public_rsa(e, n, ctime)?,
        })
    }
}

impl<R> Key6<SecretParts, R>
where R: KeyRole,
{
    /// Creates an OpenPGP key packet from the specified secret key
    /// material.
    pub fn with_secret<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                          mpis: mpi::PublicKey,
                          secret: SecretKeyMaterial)
                          -> Result<Self>
    where T: Into<time::SystemTime>
    {
        Ok(Key6 {
            common: Key4::with_secret(creation_time, pk_algo, mpis, secret)?,
        })
    }

    /// Creates a new OpenPGP secret key packet for an existing X25519
    /// key.
    ///
    /// The given `private_key` is expected to be in the native X25519
    /// representation, i.e. as opaque byte string of length 32.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_x25519<T>(private_key: &[u8],
                                   ctime: T)
                                   -> Result<Self>
    where
        T: Into<Option<std::time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::x25519_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::X25519,
            mpi::PublicKey::X25519 {
                u: public_key,
            },
            mpi::SecretKeyMaterial::X25519 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing X448
    /// key.
    ///
    /// The given `private_key` is expected to be in the native X448
    /// representation, i.e. as opaque byte string of length 32.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_x448<T>(private_key: &[u8],
                                 ctime: T)
                                 -> Result<Self>
    where
        T: Into<Option<std::time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::x448_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::X448,
            mpi::PublicKey::X448 {
                u: Box::new(public_key),
            },
            mpi::SecretKeyMaterial::X448 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing
    /// Ed25519 key.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
                                    -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::ed25519_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::Ed25519,
            mpi::PublicKey::Ed25519 {
                a: public_key,
            },
            mpi::SecretKeyMaterial::Ed25519 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing
    /// Ed448 key.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_ed448<T>(private_key: &[u8], ctime: T)
                                  -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::ed448_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::Ed448,
            mpi::PublicKey::Ed448 {
                a: Box::new(public_key),
            },
            mpi::SecretKeyMaterial::Ed448 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new key pair from a secret `Key` with an unencrypted
    /// secret key.
    ///
    /// # Errors
    ///
    /// Fails if the secret key is encrypted.  You can use
    /// [`Key::decrypt_secret`] to decrypt a key.
    pub fn into_keypair(self) -> Result<KeyPair> {
        let (key, secret) = self.take_secret();
        let secret = match secret {
            SecretKeyMaterial::Unencrypted(secret) => secret,
            SecretKeyMaterial::Encrypted(_) =>
                return Err(Error::InvalidArgument(
                    "secret key material is encrypted".into()).into()),
        };

        KeyPair::new(key.role_into_unspecified().into(), secret)
    }
}

macro_rules! impl_common_secret_functions_v6 {
    ($t: ident) => {
        /// Secret key material handling.
        impl<R> Key6<$t, R>
        where R: KeyRole,
        {
            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn take_secret(mut self)
                               -> (Key6<PublicParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.common.secret, None);
                (self.parts_into_public(), old)
            }

            /// Adds the secret key material to the `Key`, returning
            /// the old secret key material, if any.
            pub fn add_secret(mut self, secret: SecretKeyMaterial)
                              -> (Key6<SecretParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.common.secret, Some(secret));
                (self.parts_into_secret().expect("secret just set"), old)
            }

            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn steal_secret(&mut self) -> Option<SecretKeyMaterial>
            {
                std::mem::replace(&mut self.common.secret, None)
            }
        }
    }
}
impl_common_secret_functions_v6!(PublicParts);
impl_common_secret_functions_v6!(UnspecifiedParts);

/// Secret key handling.
impl<R> Key6<SecretParts, R>
where R: KeyRole,
{
    /// Gets the `Key`'s `SecretKeyMaterial`.
    pub fn secret(&self) -> &SecretKeyMaterial {
        self.common.secret()
    }

    /// Gets a mutable reference to the `Key`'s `SecretKeyMaterial`.
    pub fn secret_mut(&mut self) -> &mut SecretKeyMaterial {
        self.common.secret_mut()
    }

    /// Takes the `Key`'s `SecretKeyMaterial`.
    pub fn take_secret(mut self)
                       -> (Key6<PublicParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.common.secret, None);
        (self.parts_into_public(),
         old.expect("Key<SecretParts, _> has a secret key material"))
    }

    /// Adds `SecretKeyMaterial` to the `Key`.
    ///
    /// This function returns the old secret key material, if any.
    pub fn add_secret(mut self, secret: SecretKeyMaterial)
                      -> (Key6<SecretParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.common.secret, Some(secret));
        (self.parts_into_secret().expect("secret just set"),
         old.expect("Key<SecretParts, _> has a secret key material"))
    }

    /// Decrypts the secret key material using `password`.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// Refer to the documentation of [`Key::decrypt_secret`] for
    /// details.
    ///
    /// This function returns an error if the secret key material is
    /// not encrypted or the password is incorrect.
    ///
    /// [protected with a password]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3
    /// [KDF]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7
    /// [`Key::decrypt_secret`]: super::Key::decrypt_secret()
    pub fn decrypt_secret(self, password: &Password) -> Result<Self> {
        let (key, mut secret) = self.take_secret();
        // Note: Key version is authenticated.
        let key = Key::V6(key);
        secret.decrypt_in_place(&key, password)?;
        let key = if let Key::V6(k) = key { k } else { unreachable!() };
        Ok(key.add_secret(secret).0)
    }

    /// Encrypts the secret key material using `password`.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// Refer to the documentation of [`Key::encrypt_secret`] for
    /// details.
    ///
    /// This returns an error if the secret key material is already
    /// encrypted.
    ///
    /// [protected with a password]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3
    /// [KDF]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7
    /// [`Key::encrypt_secret`]: super::Key::encrypt_secret()
    pub fn encrypt_secret(self, password: &Password)
                          -> Result<Key6<SecretParts, R>>
    {
        let (key, mut secret) = self.take_secret();
        // Note: Key version is authenticated.
        let key = Key::V6(key);
        secret.encrypt_in_place(&key, password)?;
        let key = if let Key::V6(k) = key { k } else { unreachable!() };
        Ok(key.add_secret(secret).0)
    }
}

impl<P, R> From<Key6<P, R>> for super::Key<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn from(p: Key6<P, R>) -> Self {
        super::Key::V6(p)
    }
}

#[cfg(test)]
use crate::packet::key::{
    PrimaryRole,
    SubordinateRole,
    UnspecifiedRole,
};

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, UnspecifiedRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<SecretParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<SecretParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use crate::crypto::S2K;
    use crate::packet::Key;
    use crate::packet::key;
    use crate::packet::Packet;
    use super::*;
    use crate::PacketPile;
    use crate::serialize::Serialize;
    use crate::types::*;
    use crate::parse::Parse;

    #[test]
    fn primary_key_encrypt_decrypt() -> Result<()> {
        key_encrypt_decrypt::<PrimaryRole>()
    }

    #[test]
    fn subkey_encrypt_decrypt() -> Result<()> {
        key_encrypt_decrypt::<SubordinateRole>()
    }

    fn key_encrypt_decrypt<R>() -> Result<()>
    where
        R: KeyRole + PartialEq,
    {
        let mut g = quickcheck::Gen::new(256);
        let p: Password = Vec::<u8>::arbitrary(&mut g).into();

        let check = |key: Key6<SecretParts, R>| -> Result<()> {
            let key: Key<_, _> = key.into();
            let encrypted = key.clone().encrypt_secret(&p)?;
            let decrypted = encrypted.decrypt_secret(&p)?;
            assert_eq!(key, decrypted);
            Ok(())
        };

        use crate::types::Curve::*;
        for curve in vec![NistP256, NistP384, NistP521, Ed25519] {
            if ! curve.is_supported() {
                eprintln!("Skipping unsupported {}", curve);
                continue;
            }

            let key: Key6<_, R>
                = Key6::generate_ecc(true, curve.clone())?;
            check(key)?;
        }

        for bits in vec![2048, 3072] {
            if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
                eprintln!("Skipping unsupported RSA");
                continue;
            }

            let key: Key6<_, R>
                = Key6::generate_rsa(bits)?;
            check(key)?;
        }

        Ok(())
    }

    #[test]
    fn eq() {
        use crate::types::Curve::*;

        for curve in vec![NistP256, NistP384, NistP521] {
            if ! curve.is_supported() {
                eprintln!("Skipping unsupported {}", curve);
                continue;
            }

            let sign_key : Key6<_, key::UnspecifiedRole>
                = Key6::generate_ecc(true, curve.clone()).unwrap();
            let enc_key : Key6<_, key::UnspecifiedRole>
                = Key6::generate_ecc(false, curve).unwrap();
            let sign_clone = sign_key.clone();
            let enc_clone = enc_key.clone();

            assert_eq!(sign_key, sign_clone);
            assert_eq!(enc_key, enc_clone);
        }

        for bits in vec![1024, 2048, 3072, 4096] {
            if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
                eprintln!("Skipping unsupported RSA");
                continue;
            }

            let key : Key6<_, key::UnspecifiedRole>
                = Key6::generate_rsa(bits).unwrap();
            let clone = key.clone();
            assert_eq!(key, clone);
        }
    }

    #[test]
    fn generate_roundtrip() {
        use crate::types::Curve::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter().flat_map(|cv|
        {
            if ! cv.is_supported() {
                eprintln!("Skipping unsupported {}", cv);
                return Vec::new();
            }

            let sign_key : Key6<key::SecretParts, key::PrimaryRole>
                = Key6::generate_ecc(true, cv.clone()).unwrap();
            let enc_key = Key6::generate_ecc(false, cv).unwrap();

            vec![sign_key, enc_key]
        }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
            Key6::generate_rsa(b).ok()
        }));

        for key in keys {
            let mut b = Vec::new();
            Packet::SecretKey(key.clone().into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::SecretKey(Key::V6(ref parsed_key))) =
                pp.path_ref(&[0])
            {
                assert_eq!(key.creation_time(), parsed_key.creation_time());
                assert_eq!(key.pk_algo(), parsed_key.pk_algo());
                assert_eq!(key.mpis(), parsed_key.mpis());
                assert_eq!(key.secret(), parsed_key.secret());

                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }

            let mut b = Vec::new();
            let pk4 : Key6<PublicParts, PrimaryRole> = key.clone().into();
            Packet::PublicKey(pk4.into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::PublicKey(Key::V6(ref parsed_key))) =
                pp.path_ref(&[0])
            {
                assert!(! parsed_key.has_secret());

                let key = key.take_secret().0;
                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }
        }
    }

    #[test]
    fn encryption_roundtrip() {
        use crate::crypto::SessionKey;
        use crate::types::Curve::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter()
            .filter_map(|cv| {
                Key6::generate_ecc(false, cv).ok()
            }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key6::generate_rsa(b).ok()
            }));

        for key in keys.into_iter() {
            let key: Key<key::SecretParts, key::UnspecifiedRole> = key.into();
            let mut keypair = key.clone().into_keypair().unwrap();
            let cipher = SymmetricAlgorithm::AES256;
            let sk = SessionKey::new(cipher.key_size().unwrap()).unwrap();

            let pkesk = PKESK6::for_recipient(&sk, &key).unwrap();
            let sk_ = pkesk.decrypt(&mut keypair, None)
                .expect("keypair should be able to decrypt PKESK");
            assert_eq!(sk, sk_);

            let sk_ =
                pkesk.decrypt(&mut keypair, Some(cipher)).unwrap();
            assert_eq!(sk, sk_);
        }
    }

    #[test]
    fn signature_roundtrip() {
        use crate::types::{Curve::*, SignatureType};

        let keys = vec![NistP256, NistP384, NistP521].into_iter()
            .filter_map(|cv| {
                Key6::generate_ecc(true, cv).ok()
            }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key6::generate_rsa(b).ok()
            }));

        for key in keys.into_iter() {
            let key: Key<key::SecretParts, key::UnspecifiedRole> = key.into();
            let mut keypair = key.clone().into_keypair().unwrap();
            let hash = HashAlgorithm::default();

            // Sign.
            let ctx = hash.context().unwrap().for_signature(key.version());
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .sign_hash(&mut keypair, ctx).unwrap();

            // Verify.
            let ctx = hash.context().unwrap().for_signature(key.version());
            sig.verify_hash(&key, ctx).unwrap();
        }
    }

    #[test]
    fn secret_encryption_roundtrip() {
        use crate::types::Curve::*;
        use crate::types::SymmetricAlgorithm::*;
        use crate::types::AEADAlgorithm::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter()
            .filter_map(|cv| -> Option<Key<key::SecretParts, key::PrimaryRole>> {
                Key6::generate_ecc(false, cv).map(Into::into).ok()
            }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key6::generate_rsa(b).map(Into::into).ok()
            }));

        for key in keys {
          for (symm, aead) in [(AES128, None),
                               (AES128, Some(OCB)),
                               (AES256, Some(EAX))] {
            if ! aead.map(|a| a.is_supported()).unwrap_or(true) {
                continue;
            }
            assert!(! key.secret().is_encrypted());

            let password = Password::from("foobarbaz");
            let mut encrypted_key = key.clone();

            encrypted_key.secret_mut()
                .encrypt_in_place_with(&key, S2K::default(), symm, aead,
                                       &password).unwrap();
            assert!(encrypted_key.secret().is_encrypted());

            encrypted_key.secret_mut()
                .decrypt_in_place(&key, &password).unwrap();
            assert!(! key.secret().is_encrypted());
            assert_eq!(key, encrypted_key);
            assert_eq!(key.secret(), encrypted_key.secret());
          }
        }
    }

    #[test]
    fn encrypt_huge_plaintext() -> Result<()> {
        let sk = crate::crypto::SessionKey::new(256).unwrap();

        if PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
            let rsa2k: Key<SecretParts, UnspecifiedRole> =
                Key6::generate_rsa(2048)?.into();
            assert!(matches!(
                rsa2k.encrypt(&sk).unwrap_err().downcast().unwrap(),
                crate::Error::InvalidArgument(_)
            ));
        }

        Ok(())
    }

    #[test]
    fn issue_1016() {
        // The fingerprint is a function of the creation time,
        // algorithm, and public MPIs.  When we change them make sure
        // the fingerprint also changes.

        let mut g = quickcheck::Gen::new(256);

        let mut key = Key6::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        if key.creation_time() == UNIX_EPOCH {
            key.set_creation_time(UNIX_EPOCH + Duration::new(1, 0)).expect("ok");
        } else {
            key.set_creation_time(UNIX_EPOCH).expect("ok");
        }
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key6::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        key.set_pk_algo(PublicKeyAlgorithm::from(u8::from(key.pk_algo()) + 1));
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key6::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        loop {
            let mpis2 = mpi::PublicKey::arbitrary(&mut g);
            if key.mpis() != &mpis2 {
                *key.mpis_mut() = mpis2;
                break;
            }
        }
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key6::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        loop {
            let mpis2 = mpi::PublicKey::arbitrary(&mut g);
            if key.mpis() != &mpis2 {
                key.set_mpis(mpis2);
                break;
            }
        }
        assert_ne!(fpr1, key.fingerprint());
    }

    /// Smoke test for ECC key creation, signing and verification, and
    /// encryption and decryption.
    #[test]
    fn ecc_support() -> Result<()> {
        for for_signing in [true, false] {
            for curve in Curve::variants()
                .filter(Curve::is_supported)
            {
                match curve {
                    Curve::Cv25519 if for_signing => continue,
                    Curve::Ed25519 if ! for_signing => continue,
                    _ => (),
                }

                eprintln!("curve {}, for signing {:?}", curve, for_signing);
                let key: Key<SecretParts, UnspecifiedRole> =
                    Key6::generate_ecc(for_signing, curve.clone())?.into();
                let mut pair = key.into_keypair()?;

                if for_signing {
                    use crate::crypto::Signer;
                    let hash = HashAlgorithm::default();
                    let digest = hash.context()?
                        .for_signature(pair.public().version())
                        .into_digest()?;
                    let sig = pair.sign(hash, &digest)?;
                    pair.public().verify(&sig, hash, &digest)?;
                } else {
                    use crate::crypto::{SessionKey, Decryptor};
                    let sk = SessionKey::new(32).unwrap();
                    let ciphertext = pair.public().encrypt(&sk)?;
                    assert_eq!(pair.decrypt(&ciphertext, Some(sk.len()))?, sk);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn ecc_encoding() -> Result<()> {
        for for_signing in [true, false] {
            for curve in Curve::variants()
                .filter(Curve::is_supported)
            {
                match curve {
                    Curve::Cv25519 if for_signing => continue,
                    Curve::Ed25519 if ! for_signing => continue,
                    _ => (),
                }

                use crate::crypto::mpi::{Ciphertext, MPI, PublicKey};
                eprintln!("curve {}, for signing {:?}", curve, for_signing);

                let key: Key<SecretParts, UnspecifiedRole> =
                    Key6::generate_ecc(for_signing, curve.clone())?.into();

                let uncompressed = |mpi: &MPI| mpi.value()[0] == 0x04;

                match key.mpis() {
                    PublicKey::X25519 { .. } if ! for_signing => (),
                    PublicKey::X448 { .. } if ! for_signing => (),
                    PublicKey::Ed25519 { .. } if for_signing => (),
                    PublicKey::Ed448 { .. } if for_signing => (),
                    PublicKey::ECDSA { curve: c, q } if for_signing => {
                        assert!(c == &curve);
                        assert!(c != &Curve::Ed25519);
                        assert!(uncompressed(q));
                    },
                    PublicKey::ECDH { curve: c, q, .. } if ! for_signing => {
                        assert!(c == &curve);
                        assert!(c != &Curve::Cv25519);
                        assert!(uncompressed(q));

                        use crate::crypto::SessionKey;
                        let sk = SessionKey::new(32).unwrap();
                        let ciphertext = key.encrypt(&sk)?;
                        if let Ciphertext::ECDH { e, .. } = &ciphertext {
                            assert!(uncompressed(e));
                        } else {
                            panic!("unexpected ciphertext: {:?}", ciphertext);
                        }
                    },
                    mpi => unreachable!(
                        "curve {}, mpi {:?}, for signing {:?}",
                        curve, mpi, for_signing),
                }
            }
        }
        Ok(())
    }


    #[test]
    fn v6_key_fingerprint() -> Result<()> {
        let p = Packet::from_bytes("-----BEGIN PGP ARMORED FILE-----

xjcGY4d/4xYAAAAtCSsGAQQB2kcPAQEHQPlNp7tI1gph5WdwamWH0DMZmbudiRoI
JC6thFQ9+JWj
=SgmS
-----END PGP ARMORED FILE-----")?;
        let k: &Key<PublicParts, PrimaryRole> = p.downcast_ref().unwrap();
        assert_eq!(k.fingerprint().to_string(),
                   "4EADF309C6BC874AE04702451548F93F\
                    96FA7A01D0A33B5AF7D4E379E0F9F8EE".to_string());
        Ok(())
    }
}
