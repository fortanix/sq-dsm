//! OpenPGP v4 key packet.

use std::fmt;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::hash::Hasher;
use std::time;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::crypto::{mem::Protected, mpi, hash::Hash, KeyPair};
use crate::packet;
use crate::packet::prelude::*;
use crate::PublicKeyAlgorithm;
use crate::SymmetricAlgorithm;
use crate::HashAlgorithm;
use crate::types::{
    Curve,
    Timestamp,
};
use crate::Result;
use crate::crypto::Password;
use crate::KeyID;
use crate::Fingerprint;
use crate::KeyHandle;
use crate::packet::key::{
    self,
    KeyParts,
    KeyRole,
    KeyRoleRT,
    PublicParts,
    SecretParts,
    UnspecifiedParts,
};
use crate::policy::HashAlgoSecurity;


/// Holds a public key, public subkey, private key or private subkey
/// packet.
///
/// Use [`Key4::generate_rsa`] or [`Key4::generate_ecc`] to create a
/// new key.
///
/// Existing key material can be turned into an OpenPGP key using
/// [`Key4::new`], [`Key4::with_secret`], [`Key4::import_public_cv25519`],
/// [`Key4::import_public_ed25519`], [`Key4::import_public_rsa`],
/// [`Key4::import_secret_cv25519`], [`Key4::import_secret_ed25519`],
/// and [`Key4::import_secret_rsa`].
///
/// Whether you create a new key or import existing key material, you
/// still need to create a binding signature, and, for signing keys, a
/// back signature before integrating the key into a certificate.
///
/// Normally, you won't directly use `Key4`, but [`Key`], which is a
/// relatively thin wrapper around `Key4`.
///
/// See [Section 5.5 of RFC 9580] and [the documentation for `Key`]
/// for more details.
///
/// [Section 5.5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5
/// [the documentation for `Key`]: super::Key
/// [`Key`]: super::Key
pub struct Key4<P, R>
    where P: KeyParts, R: KeyRole
{
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// When the key was created.
    pub(crate) creation_time: Timestamp,
    /// Public key algorithm of this signature.
    pk_algo: PublicKeyAlgorithm,
    /// Public key MPIs.
    mpis: mpi::PublicKey,
    /// Optional secret part of the key.
    pub(crate) secret: Option<SecretKeyMaterial>,

    pub(crate) fingerprint: std::sync::OnceLock<Fingerprint>,

    /// The key role tracked at run time.
    role: KeyRoleRT,

    p: std::marker::PhantomData<P>,
    r: std::marker::PhantomData<R>,
}

// derive(Clone) doesn't work as expected with generic type parameters
// that don't implement clone: it adds a trait bound on Clone to P and
// R in the Clone implementation.  Happily, we don't need P or R to
// implement Clone: they are just marker traits, which we can clone
// manually.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<P, R> Clone for Key4<P, R>
    where P: KeyParts, R: KeyRole
{
    fn clone(&self) -> Self {
        Key4 {
            common: self.common.clone(),
            creation_time: self.creation_time.clone(),
            pk_algo: self.pk_algo.clone(),
            mpis: self.mpis.clone(),
            secret: self.secret.clone(),
            fingerprint: self.fingerprint.get()
                .map(|fp| fp.clone().into())
                .unwrap_or_default(),
            role: self.role,
            p: std::marker::PhantomData,
            r: std::marker::PhantomData,
        }
    }
}

assert_send_and_sync!(Key4<P, R> where P: KeyParts, R: KeyRole);

impl<P: KeyParts, R: KeyRole> PartialEq for Key4<P, R> {
    fn eq(&self, other: &Key4<P, R>) -> bool {
        self.creation_time == other.creation_time
            && self.pk_algo == other.pk_algo
            && self.mpis == other.mpis
            && (! P::significant_secrets() || self.secret == other.secret)
    }
}

impl<P: KeyParts, R: KeyRole> Eq for Key4<P, R> {}

impl<P: KeyParts, R: KeyRole> std::hash::Hash for Key4<P, R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.creation_time, state);
        std::hash::Hash::hash(&self.pk_algo, state);
        std::hash::Hash::hash(&self.mpis, state);
        if P::significant_secrets() {
            std::hash::Hash::hash(&self.secret, state);
        }
    }
}

impl<P, R> fmt::Debug for Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key4")
            .field("fingerprint", &self.fingerprint())
            .field("creation_time", &self.creation_time)
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .field("secret", &self.secret)
            .finish()
    }
}

impl<P, R> fmt::Display for Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl<P, R> Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
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
    /// time, and algorithm of the two `Key4`s match.  This does not
    /// consider the packets' encodings, packets' tags or their secret
    /// key material.
    pub fn public_cmp<PB, RB>(&self, b: &Key4<PB, RB>) -> Ordering
        where PB: key::KeyParts,
              RB: key::KeyRole,
    {
        self.mpis.cmp(&b.mpis)
            .then_with(|| self.creation_time.cmp(&b.creation_time))
            .then_with(|| self.pk_algo.cmp(&b.pk_algo))
    }

    /// Tests whether two keys are equal modulo their secret key
    /// material.
    ///
    /// This returns true if the public MPIs, creation time and
    /// algorithm of the two `Key4`s match.  This does not consider
    /// the packets' encodings, packets' tags or their secret key
    /// material.
    pub fn public_eq<PB, RB>(&self, b: &Key4<PB, RB>) -> bool
        where PB: key::KeyParts,
              RB: key::KeyRole,
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
        use std::hash::Hash;

        self.common.hash(state);
        self.creation_time.hash(state);
        self.pk_algo.hash(state);
        Hash::hash(&self.mpis(), state);
    }
}

impl<P, R> Key4<P, R>
     where P: key::KeyParts,
           R: key::KeyRole,
{
    /// Gets the `Key`'s creation time.
    pub fn creation_time(&self) -> time::SystemTime {
        self.creation_time.into()
    }

    /// Gets the `Key`'s creation time without converting it to a
    /// system time.
    ///
    /// This conversion may truncate the time to signed 32-bit time_t.
    pub(crate) fn creation_time_raw(&self) -> Timestamp {
        self.creation_time
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
        // Clear the cache.
        self.fingerprint = Default::default();

        Ok(std::mem::replace(&mut self.creation_time,
                             timestamp.into().try_into()?)
           .into())
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    ///
    /// Returns the old public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm)
        -> PublicKeyAlgorithm
    {
        // Clear the cache.
        self.fingerprint = Default::default();

        ::std::mem::replace(&mut self.pk_algo, pk_algo)
    }

    /// Returns a reference to the `Key`'s MPIs.
    pub fn mpis(&self) -> &mpi::PublicKey {
        &self.mpis
    }

    /// Returns a mutable reference to the `Key`'s MPIs.
    pub fn mpis_mut(&mut self) -> &mut mpi::PublicKey {
        // Clear the cache.
        self.fingerprint = Default::default();

        &mut self.mpis
    }

    /// Sets the `Key`'s MPIs.
    ///
    /// This function returns the old MPIs, if any.
    pub fn set_mpis(&mut self, mpis: mpi::PublicKey) -> mpi::PublicKey {
        // Clear the cache.
        self.fingerprint = Default::default();

        ::std::mem::replace(&mut self.mpis, mpis)
    }

    /// Returns whether the `Key` contains secret key material.
    pub fn has_secret(&self) -> bool {
        self.secret.is_some()
    }

    /// Returns whether the `Key` contains unencrypted secret key
    /// material.
    ///
    /// This returns false if the `Key` doesn't contain any secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool {
        matches!(self.secret, Some(SecretKeyMaterial::Unencrypted { .. }))
    }

    /// Returns `Key`'s secret key material, if any.
    pub fn optional_secret(&self) -> Option<&SecretKeyMaterial> {
        self.secret.as_ref()
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
        self.fingerprint.get_or_init(|| {
            let mut h = HashAlgorithm::SHA1.context()
                .expect("SHA1 is MTI for RFC4880")
            // v4 fingerprints are computed the same way a key is
            // hashed for v4 signatures.
                .for_signature(4);

            self.hash(&mut h).expect("v4 key hashing is infallible");

            let mut digest = [0u8; 20];
            let _ = h.digest(&mut digest);
            Fingerprint::V4(digest)
        }).clone()
    }

    /// Computes and returns the `Key`'s `Key ID`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn keyid(&self) -> KeyID {
        self.fingerprint().into()
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
    {
        Ok(Key4 {
            common: Default::default(),
            creation_time,
            pk_algo,
            mpis,
            secret,
            fingerprint: Default::default(),
            role: R::role(),
            p: std::marker::PhantomData,
            r: std::marker::PhantomData,
        })
    }

    pub(crate) fn role(&self) -> KeyRoleRT {
        self.role
    }

    pub(crate) fn set_role(&mut self, role: KeyRoleRT) {
        self.role = role;
    }
}

impl<R> Key4<key::PublicParts, R>
    where R: key::KeyRole,
{
    /// Creates an OpenPGP public key from the specified key material.
    pub fn new<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                  mpis: mpi::PublicKey)
                  -> Result<Self>
        where T: Into<time::SystemTime>
    {
        Ok(Key4 {
            common: Default::default(),
            creation_time: creation_time.into().try_into()?,
            pk_algo,
            mpis,
            secret: None,
            fingerprint: Default::default(),
            role: R::role(),
            p: std::marker::PhantomData,
            r: std::marker::PhantomData,
        })
    }

    /// Creates an OpenPGP public key packet from existing X25519 key
    /// material.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have its creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_public_cv25519<H, S, T>(public_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<time::SystemTime>>
    {
        let mut point = Vec::from(public_key);
        point.insert(0, 0x40);

        use crate::crypto::ecdh;
        Self::new(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or_else(
                    || ecdh::default_ecdh_kdf_hash(&Curve::Cv25519)),
                sym: sym.into().unwrap_or_else(
                    || ecdh::default_ecdh_kek_cipher(&Curve::Cv25519)),
                q: mpi::MPI::new(&point),
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
        Ok(Key4::new(ctime.into().unwrap_or_else(crate::now),
                     PublicKeyAlgorithm::X25519,
                     mpi::PublicKey::X25519 {
                         u: public_key.try_into()?,
                     })?)
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
        Ok(Key4::new(ctime.into().unwrap_or_else(crate::now),
                     PublicKeyAlgorithm::X448,
                     mpi::PublicKey::X448 {
                         u: Box::new(public_key.try_into()?),
                     })?)
    }

    /// Creates an OpenPGP public key packet from existing Ed25519 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_ed25519<T>(public_key: &[u8], ctime: T) -> Result<Self>
        where  T: Into<Option<time::SystemTime>>
    {
        let mut point = Vec::from(public_key);
        point.insert(0, 0x40);

        Self::new(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: mpi::MPI::new(&point),
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
        Ok(Key4::new(ctime.into().unwrap_or_else(crate::now),
                     PublicKeyAlgorithm::Ed448,
                     mpi::PublicKey::Ed448 {
                         a: Box::new(public_key.try_into()?),
                     })?)
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
        Self::new(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: mpi::MPI::new(e),
                n: mpi::MPI::new(n),
            })
    }
}

impl<R> Key4<SecretParts, R>
    where R: key::KeyRole,
{
    /// Creates an OpenPGP key packet from the specified secret key
    /// material.
    pub fn with_secret<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                          mpis: mpi::PublicKey,
                          secret: SecretKeyMaterial)
                          -> Result<Self>
        where T: Into<time::SystemTime>
    {
        Ok(Key4 {
            common: Default::default(),
            creation_time: creation_time.into().try_into()?,
            pk_algo,
            mpis,
            secret: Some(secret),
            fingerprint: Default::default(),
            role: R::role(),
            p: std::marker::PhantomData,
            r: std::marker::PhantomData,
        })
    }

    /// Creates a new OpenPGP secret key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have its creation date set to
    /// `ctime` or the current time if `None` is given.
    ///
    /// The given `private_key` is expected to be in the native X25519
    /// representation, i.e. as opaque byte string of length 32.  It
    /// is transformed into OpenPGP's representation during import.
    pub fn import_secret_cv25519<H, S, T>(private_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<std::time::SystemTime>>
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let mut private_key = Protected::from(private_key);
        let public_key = Backend::x25519_derive_public(&private_key)?;

        // Clamp the X25519 secret key scalar.
        //
        // X25519 does the clamping implicitly, but OpenPGP's ECDH
        // over Curve25519 requires the secret to be clamped.  To
        // increase compatibility with OpenPGP implementations that do
        // not implicitly clamp the secrets before use, we do that
        // before we store the secrets in OpenPGP data structures.
        Backend::x25519_clamp_secret(&mut private_key);

        // Reverse the scalar.
        //
        // X25519 stores the secret as opaque byte string representing
        // a little-endian scalar.  OpenPGP's ECDH over Curve25519 on
        // the other hand stores it as big-endian scalar, as was
        // customary in OpenPGP.  See
        // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
        private_key.reverse();

        use crate::crypto::ecdh;
        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash.into().unwrap_or_else(
                    || ecdh::default_ecdh_kdf_hash(&Curve::Cv25519)),
                sym: sym.into().unwrap_or_else(
                    || ecdh::default_ecdh_kek_cipher(&Curve::Cv25519)),
                q: mpi::MPI::new_compressed_point(&public_key),
            },
            mpi::SecretKeyMaterial::ECDH {
                scalar: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The key will have its creation date set to `ctime` or the current
    /// time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<time::SystemTime>>
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::ed25519_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: mpi::MPI::new_compressed_point(&public_key),
            },
            mpi::SecretKeyMaterial::EdDSA {
                scalar: private_key.into(),
            }.into())
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (pk_algo, public, secret) = match (curve, for_signing) {
            (Curve::Ed25519, true) => {
                let (secret, public) = Backend::ed25519_generate_key()?;

                (
                    PublicKeyAlgorithm::EdDSA,
                    mpi::PublicKey::EdDSA {
                        curve: Curve::Ed25519,
                        q: mpi::MPI::new_compressed_point(&public),
                    },
                    mpi::SecretKeyMaterial::EdDSA {
                        scalar: secret.into(),
                    },
                )
            },

            (Curve::Cv25519, false) => {
                let (mut secret, public) = Backend::x25519_generate_key()?;

                // Clamp the X25519 secret key scalar.
                //
                // X25519 does the clamping implicitly, but OpenPGP's ECDH over
                // Curve25519 requires the secret to be clamped.  To increase
                // compatibility with OpenPGP implementations that do not
                // implicitly clamp the secrets before use, we do that before we
                // store the secrets in OpenPGP data structures.
                Backend::x25519_clamp_secret(&mut secret);

                // Reverse the scalar.
                //
                // X25519 stores the secret as opaque byte string
                // representing a little-endian scalar.  OpenPGP's
                // ECDH over Curve25519 on the other hand stores it as
                // big-endian scalar, as was customary in OpenPGP.
                // See
                // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
                secret.reverse();

                (
                    PublicKeyAlgorithm::ECDH,
                    mpi::PublicKey::ECDH {
                        curve: Curve::Cv25519,
                        q: mpi::MPI::new_compressed_point(&public),
                        hash: crate::crypto::ecdh::default_ecdh_kdf_hash(
                            &Curve::Cv25519),
                        sym: crate::crypto::ecdh::default_ecdh_kek_cipher(
                            &Curve::Cv25519),
                    },
                    mpi::SecretKeyMaterial::ECDH {
                        scalar: secret.into(),
                    },
                )
            },

            (curve, for_signing) =>
                Self::generate_ecc_backend(for_signing, curve)?,
        };

        Self::with_secret(crate::now(), pk_algo, public, secret.into())
    }

    /// Generates a new DSA key with a public modulus of size `p_bits`.
    ///
    /// Note: In order to comply with FIPS 186-4, and to increase
    /// compatibility with implementations, you SHOULD only generate
    /// keys with moduli of size `2048` or `3072` bits.
    pub fn generate_dsa(p_bits: usize) -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (p, q, g, y, x) = Backend::dsa_generate_key(p_bits)?;
        let public_mpis = mpi::PublicKey::DSA { p, q, g, y };
        let private_mpis = mpi::SecretKeyMaterial::DSA { x };

        Self::with_secret(
            crate::now(),
            #[allow(deprecated)]
            PublicKeyAlgorithm::DSA,
            public_mpis,
            private_mpis.into())
    }

    /// Generates a new ElGamal key with a public modulus of size `p_bits`.
    ///
    /// Note: ElGamal is no longer well-supported in cryptographic
    /// libraries and should be avoided.
    pub fn generate_elgamal(p_bits: usize) -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (p, g, y, x) = Backend::elgamal_generate_key(p_bits)?;
        let public_mpis = mpi::PublicKey::ElGamal { p, g, y };
        let private_mpis = mpi::SecretKeyMaterial::ElGamal { x };

        Self::with_secret(
            crate::now(),
            #[allow(deprecated)]
            PublicKeyAlgorithm::ElGamalEncrypt,
            public_mpis,
            private_mpis.into())
    }

    /// Generates a new X25519 key.
    pub fn generate_x25519() -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (private, public) = Backend::x25519_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::X25519,
            mpi::PublicKey::X25519 {
                u: public,
            },
            mpi::SecretKeyMaterial::X25519 {
                x: private,
            }.into())
    }

    /// Generates a new X448 key.
    pub fn generate_x448() -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (private, public) = Backend::x448_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::X448,
            mpi::PublicKey::X448 {
                u: Box::new(public),
            },
            mpi::SecretKeyMaterial::X448 {
                x: private,
            }.into())
    }

    /// Generates a new Ed25519 key.
    pub fn generate_ed25519() -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (private, public) = Backend::ed25519_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::Ed25519,
            mpi::PublicKey::Ed25519 {
                a: public,
            },
            mpi::SecretKeyMaterial::Ed25519 {
                x: private,
            }.into())
    }

    /// Generates a new Ed448 key.
    pub fn generate_ed448() -> Result<Self> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (private, public) = Backend::ed448_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::Ed448,
            mpi::PublicKey::Ed448 {
                a: Box::new(public),
            },
            mpi::SecretKeyMaterial::Ed448 {
                x: private,
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

macro_rules! impl_common_secret_functions {
    ($t: ident) => {
        /// Secret key material handling.
        impl<R> Key4<$t, R>
            where R: key::KeyRole,
        {
            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn take_secret(mut self)
                               -> (Key4<PublicParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.secret, None);
                (self.parts_into_public(), old)
            }

            /// Adds the secret key material to the `Key`, returning
            /// the old secret key material, if any.
            pub fn add_secret(mut self, secret: SecretKeyMaterial)
                              -> (Key4<SecretParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.secret, Some(secret));
                (self.parts_into_secret().expect("secret just set"), old)
            }

            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn steal_secret(&mut self) -> Option<SecretKeyMaterial>
            {
                std::mem::replace(&mut self.secret, None)
            }
        }
    }
}
impl_common_secret_functions!(PublicParts);
impl_common_secret_functions!(UnspecifiedParts);

/// Secret key handling.
impl<R> Key4<SecretParts, R>
    where R: key::KeyRole,
{
    /// Gets the `Key`'s `SecretKeyMaterial`.
    pub fn secret(&self) -> &SecretKeyMaterial {
        self.secret.as_ref().expect("has secret")
    }

    /// Gets a mutable reference to the `Key`'s `SecretKeyMaterial`.
    pub fn secret_mut(&mut self) -> &mut SecretKeyMaterial {
        self.secret.as_mut().expect("has secret")
    }

    /// Takes the `Key`'s `SecretKeyMaterial`.
    pub fn take_secret(mut self)
                       -> (Key4<PublicParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.secret, None);
        (self.parts_into_public(),
         old.expect("Key<SecretParts, _> has a secret key material"))
    }

    /// Adds `SecretKeyMaterial` to the `Key`.
    ///
    /// This function returns the old secret key material, if any.
    pub fn add_secret(mut self, secret: SecretKeyMaterial)
                      -> (Key4<SecretParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.secret, Some(secret));
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
        let key = Key::V4(key);
        secret.decrypt_in_place(&key, password)?;
        let key = if let Key::V4(k) = key { k } else { unreachable!() };
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
        -> Result<Key4<SecretParts, R>>
    {
        let (key, mut secret) = self.take_secret();
        let key = Key::V4(key);
        secret.encrypt_in_place(&key, password)?;
        let key = if let Key::V4(k) = key { k } else { unreachable!() };
        Ok(key.add_secret(secret).0)
    }
}

impl<P, R> From<Key4<P, R>> for super::Key<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn from(p: Key4<P, R>) -> Self {
        super::Key::V4(p)
    }
}

#[cfg(test)]
use crate::packet::key::{
    PrimaryRole,
    SubordinateRole,
    UnspecifiedRole,
};

#[cfg(test)]
impl Arbitrary for Key4<PublicParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key4::<PublicParts, UnspecifiedRole>::arbitrary(g).into()
    }
}

#[cfg(test)]
impl Arbitrary for Key4<PublicParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key4::<PublicParts, UnspecifiedRole>::arbitrary(g).into()
    }
}

#[cfg(test)]
impl Arbitrary for Key4<PublicParts, UnspecifiedRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        let mpis = mpi::PublicKey::arbitrary(g);
        Key4 {
            common: Arbitrary::arbitrary(g),
            creation_time: Arbitrary::arbitrary(g),
            pk_algo: mpis.algo()
                .expect("mpi::PublicKey::arbitrary only uses known algos"),
            mpis,
            secret: None,
            fingerprint: Default::default(),
            role: UnspecifiedRole::role(),
            p: std::marker::PhantomData,
            r: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
impl Arbitrary for Key4<SecretParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key4::<SecretParts, PrimaryRole>::arbitrary_secret_key(g)
    }
}

#[cfg(test)]
impl Arbitrary for Key4<SecretParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key4::<SecretParts, SubordinateRole>::arbitrary_secret_key(g)
    }
}

#[cfg(test)]
impl<R> Key4<SecretParts, R>
where
    R: KeyRole,
    Key4::<PublicParts, R>: Arbitrary,
{
    fn arbitrary_secret_key(g: &mut Gen) -> Self {
        let key = Key::V4(Key4::<PublicParts, R>::arbitrary(g));
        let mut secret: SecretKeyMaterial =
            mpi::SecretKeyMaterial::arbitrary_for(g, key.pk_algo())
            .expect("only known algos used")
            .into();

        if <bool>::arbitrary(g) {
            secret.encrypt_in_place(&key, &Password::from(Vec::arbitrary(g)))
                .unwrap();
        }

        let key = if let Key::V4(k) = key { k } else { unreachable!() };
        Key4::<PublicParts, R>::add_secret(key, secret).0
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use crate::crypto::S2K;
    use crate::packet::Key;
    use crate::Cert;
    use crate::packet::pkesk::PKESK3;
    use crate::packet::key;
    use crate::packet::key::SecretKeyMaterial;
    use crate::packet::Packet;
    use super::*;
    use crate::PacketPile;
    use crate::serialize::Serialize;
    use crate::parse::Parse;

    #[test]
    fn encrypted_rsa_key() {
        let cert = Cert::from_bytes(
            crate::tests::key("testy-new-encrypted-with-123.pgp")).unwrap();
        let key = cert.primary_key().key().clone();
        let (key, secret) = key.take_secret();
        let mut secret = secret.unwrap();

        assert!(secret.is_encrypted());
        secret.decrypt_in_place(&key, &"123".into()).unwrap();
        assert!(!secret.is_encrypted());
        let (pair, _) = key.add_secret(secret);
        assert!(pair.has_unencrypted_secret());

        match pair.secret() {
            SecretKeyMaterial::Unencrypted(ref u) => u.map(|mpis| match mpis {
                mpi::SecretKeyMaterial::RSA { .. } => (),
                _ => panic!(),
            }),
            _ => panic!(),
        }
    }

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

        let check = |key: Key4<SecretParts, R>| -> Result<()> {
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

            let key: Key4<_, R>
                = Key4::generate_ecc(true, curve.clone())?;
            check(key)?;
        }

        for bits in vec![2048, 3072] {
            if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
                eprintln!("Skipping unsupported RSA");
                continue;
            }

            let key: Key4<_, R>
                = Key4::generate_rsa(bits)?;
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

            let sign_key : Key4<_, key::UnspecifiedRole>
                = Key4::generate_ecc(true, curve.clone()).unwrap();
            let enc_key : Key4<_, key::UnspecifiedRole>
                = Key4::generate_ecc(false, curve).unwrap();
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

            let key : Key4<_, key::UnspecifiedRole>
                = Key4::generate_rsa(bits).unwrap();
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

            let sign_key : Key4<key::SecretParts, key::PrimaryRole>
                = Key4::generate_ecc(true, cv.clone()).unwrap();
            let enc_key = Key4::generate_ecc(false, cv).unwrap();

            vec![sign_key, enc_key]
        }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
            Key4::generate_rsa(b).ok()
        }));

        for key in keys {
            let mut b = Vec::new();
            Packet::SecretKey(key.clone().into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::SecretKey(Key::V4(ref parsed_key))) =
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
            let pk4 : Key4<PublicParts, PrimaryRole> = key.clone().into();
            Packet::PublicKey(pk4.into()).serialize(&mut b).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::PublicKey(Key::V4(ref parsed_key))) =
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
                Key4::generate_ecc(false, cv).ok()
            }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key4::generate_rsa(b).ok()
            })).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key4::generate_elgamal(b).ok()
            }));

        for key in keys.into_iter() {
            let key: Key<key::SecretParts, key::UnspecifiedRole> = key.into();
            let mut keypair = key.clone().into_keypair().unwrap();
            let cipher = SymmetricAlgorithm::AES256;
            let sk = SessionKey::new(cipher.key_size().unwrap()).unwrap();

            let pkesk = PKESK3::for_recipient(cipher, &sk, &key).unwrap();
            let (cipher_, sk_) = pkesk.decrypt(&mut keypair, None)
                .expect("keypair should be able to decrypt PKESK");

            assert_eq!(cipher, cipher_);
            assert_eq!(sk, sk_);

            let (cipher_, sk_) =
                pkesk.decrypt(&mut keypair, Some(cipher)).unwrap();

            assert_eq!(cipher, cipher_);
            assert_eq!(sk, sk_);
        }
    }

    #[test]
    fn secret_encryption_roundtrip() {
        use crate::types::Curve::*;
        use crate::types::SymmetricAlgorithm::*;
        use crate::types::AEADAlgorithm::*;

        let keys = vec![NistP256, NistP384, NistP521].into_iter()
            .filter_map(|cv| -> Option<Key<key::SecretParts, key::PrimaryRole>> {
                Key4::generate_ecc(false, cv).map(Into::into).ok()
            }).chain(vec![1024, 2048, 3072, 4096].into_iter().filter_map(|b| {
                Key4::generate_rsa(b).map(Into::into).ok()
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
    fn import_cv25519() {
        use crate::crypto::{ecdh, mem, SessionKey};
        use self::mpi::{MPI, Ciphertext};

        // X25519 key
        let ctime =
            time::UNIX_EPOCH + time::Duration::new(0x5c487129, 0);
        let public = b"\xed\x59\x0a\x15\x08\x95\xe9\x92\xd2\x2c\x14\x01\xb3\xe9\x3b\x7f\xff\xe6\x6f\x22\x65\xec\x69\xd9\xb8\xda\x24\x2c\x64\x84\x44\x11";
        let key : Key<_, key::UnspecifiedRole>
            = Key4::import_public_cv25519(&public[..],
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
        let got_enc = ecdh::encrypt_wrap(&key.parts_into_public().role_into_subordinate(),
                                           &sk, eph_pubkey, &shared_sec)
            .unwrap();

        assert_eq!(ciphertext, got_enc);
    }

    #[test]
    fn import_cv25519_sec() -> Result<()> {
        use self::mpi::{MPI, Ciphertext};

        // X25519 key
        let ctime =
            time::UNIX_EPOCH + time::Duration::new(0x5c487129, 0);
        let public = b"\xed\x59\x0a\x15\x08\x95\xe9\x92\xd2\x2c\x14\x01\xb3\xe9\x3b\x7f\xff\xe6\x6f\x22\x65\xec\x69\xd9\xb8\xda\x24\x2c\x64\x84\x44\x11";
        let secret = b"\xa0\x27\x13\x99\xc9\xe3\x2e\xd2\x47\xf6\xd6\x63\x9d\xe6\xec\xcb\x57\x0b\x92\xbb\x17\xfe\xb8\xf1\xc4\x1f\x06\x7c\x55\xfc\xdd\x58";
        let key: Key<_, UnspecifiedRole>
            = Key4::import_secret_cv25519(&secret[..],
                                          HashAlgorithm::SHA256,
                                          SymmetricAlgorithm::AES128,
                                          ctime).unwrap().into();
        match key.mpis() {
            self::mpi::PublicKey::ECDH{ ref q,.. } =>
                assert_eq!(&q.value()[1..], &public[..]),
            _ => unreachable!(),
        }

        // PKESK
        let eph_pubkey: &[u8; 33] = b"\x40\xda\x1c\x69\xc4\xe3\xb6\x9c\x6e\xd4\xc6\x69\x6c\x89\xc7\x09\xe9\xf8\x6a\xf1\xe3\x8d\xb6\xaa\xb5\xf7\x29\xae\xa6\xe7\xdd\xfe\x38";
        let ciphertext = Ciphertext::ECDH{
            e: MPI::new(&eph_pubkey[..]),
            key: Vec::from(&b"\x45\x8b\xd8\x4d\x88\xb3\xd2\x16\xb6\xc2\x3b\x99\x33\xd1\x23\x4b\x10\x15\x8e\x04\x16\xc5\x7c\x94\x88\xf6\x63\xf2\x68\x37\x08\x66\xfd\x5a\x7b\x40\x58\x21\x6b\x2c\xc0\xf4\xdc\x91\xd3\x48\xed\xc1"[..]).into_boxed_slice()
        };
        let pkesk =
            PKESK3::new(None, PublicKeyAlgorithm::ECDH, ciphertext)?;

        // Session key
        let dek = b"\x0D\xDC\x40\xC5\x71\x51\x88\xAC\xBD\x45\x56\xD4\x2A\xDF\x77\xCD\xF4\x82\xA2\x1B\x8F\x2E\x48\x3B\xCA\xBF\xD3\xE8\x6D\x0A\x7C\xDF";

        let key = key.parts_into_secret().unwrap();
        let mut keypair = key.into_keypair()?;
        let (sym, got_dek) = pkesk.decrypt(&mut keypair, None).unwrap();

        assert_eq!(sym, SymmetricAlgorithm::AES256);
        assert_eq!(&dek[..], &got_dek[..]);
        Ok(())
    }

    #[test]
    fn import_rsa() -> Result<()> {
        use crate::crypto::SessionKey;
        use self::mpi::{MPI, Ciphertext};

        // RSA key
        let ctime =
            time::UNIX_EPOCH + time::Duration::new(1548950502, 0);
        let d = b"\x14\xC4\x3A\x0C\x3A\x79\xA4\xF7\x63\x0D\x89\x93\x63\x8B\x56\x9C\x29\x2E\xCD\xCF\xBF\xB0\xEC\x66\x52\xC3\x70\x1B\x19\x21\x73\xDE\x8B\xAC\x0E\xF2\xE1\x28\x42\x66\x56\x55\x00\x3B\xFD\x50\xC4\x7C\xBC\x9D\xEB\x7D\xF4\x81\xFC\xC3\xBF\xF7\xFF\xD0\x41\x3E\x50\x3B\x5F\x5D\x5F\x56\x67\x5E\x00\xCE\xA4\x53\xB8\x59\xA0\x40\xC8\x96\x6D\x12\x09\x27\xBE\x1D\xF1\xC2\x68\xFC\xF0\x14\xD6\x52\x77\x07\xC8\x12\x36\x9C\x9A\x5C\xAF\x43\xCC\x95\x20\xBB\x0A\x44\x94\xDD\xB4\x4F\x45\x4E\x3A\x1A\x30\x0D\x66\x40\xAC\x68\xE8\xB0\xFD\xCD\x6C\x6B\x6C\xB5\xF7\xE4\x36\x95\xC2\x96\x98\xFD\xCA\x39\x6C\x1A\x2E\x55\xAD\xB6\xE0\xF8\x2C\xFF\xBC\xD3\x32\x15\x52\x39\xB3\x92\x35\xDB\x8B\x68\xAF\x2D\x4A\x6E\x64\xB8\x28\x63\xC4\x24\x94\x2D\xA9\xDB\x93\x56\xE3\xBC\xD0\xB6\x38\x84\x04\xA4\xC6\x18\x48\xFE\xB2\xF8\xE1\x60\x37\x52\x96\x41\xA5\x79\xF6\x3D\xB7\x2A\x71\x5B\x7A\x75\xBF\x7F\xA2\x5A\xC8\xA1\x38\xF2\x5A\xBD\x14\xFC\xAF\xB4\x54\x83\xA4\xBD\x49\xA2\x8B\x91\xB0\xE0\x4A\x1B\x21\x54\x07\x19\x70\x64\x7C\x3E\x9F\x8D\x8B\xE4\x70\xD1\xE7\xBE\x4E\x5C\xCE\xF1";
        let p = b"\xC8\x32\xD1\x17\x41\x4D\x8F\x37\x09\x18\x32\x4C\x4C\xF4\xA2\x15\x27\x43\x3D\xBB\xB5\xF6\x1F\xCF\xD2\xE4\x43\x61\x07\x0E\x9E\x35\x1F\x0A\x5D\xFB\x3A\x45\x74\x61\x73\x73\x7B\x5F\x1F\x87\xFB\x54\x8D\xA8\x85\x3E\xB0\xB7\xC7\xF5\xC9\x13\x99\x8D\x40\xE6\xA6\xD0\x71\x3A\xE3\x2D\x4A\xC3\xA3\xFF\xF7\x72\x82\x14\x52\xA4\xBA\x63\x0E\x17\xCA\xCA\x18\xC4\x3A\x40\x79\xF1\x86\xB3\x10\x4B\x9F\xB2\xAE\x2E\x13\x38\x8D\x2C\xF9\x88\x4C\x25\x53\xEF\xF9\xD1\x8B\x1A\x7C\xE7\xF6\x4B\x73\x51\x31\xFA\x44\x1D\x36\x65\x71\xDA\xFC\x6F";
        let q = b"\xCC\x30\xE9\xCC\xCB\x31\x28\xB5\x90\xFF\x06\x62\x42\x5B\x24\x0E\x00\xFE\xE2\x37\xC4\xAC\xBB\x3B\x8F\xF2\x0E\x3F\x78\xCF\x6B\x7C\xE8\x75\x57\x7C\x15\x9D\x1A\x66\xF2\x0A\xE5\xD3\x0B\xE7\x40\xF7\xE7\x00\xB6\x86\xB5\xD9\x20\x67\xE0\x4A\xC0\x90\xA4\x13\x4D\xC9\xB0\x12\xC5\xCD\x4C\xEB\xA1\x91\x2D\x43\x58\x6E\xB6\x75\xA0\x93\xF0\x5B\xC5\x31\xCA\xB7\xC6\x22\x0C\xD3\xEC\x84\xC5\x91\xA1\x5F\x2C\x8E\x07\x5D\xA1\x98\x67\xC5\x7A\x58\x16\x71\x3D\xED\x91\x03\x0D\xD4\x25\x07\x89\x9B\x33\x98\xA3\x70\xD9\xE7\xC8\x17\xA3\xD9";

        let reference_key = Packet::from_bytes(b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----

xcLYBFxTG+YBCACfrr78JBmS/7rxsQg7y1IialuUqqbXmpMXz8mmd/tYKB1kymnK
kciCvYJ3CKq/3c3AlTlV7x4qKcXIL5XSuONdq9xHHpFyxjMJLAYMNn+PR6BgyLJG
J9MThBxELQGw7MEL+/7iFT6N92eu8PTyUnQwdDXA6JV5M49fbYCiG/2sCXSyVtJJ
DcQWkWQSZasC82PmFX4C/5QqunZ6nXRLkx79ErHwCzqO9GqY7rgPErmV0Hd2LXUt
AesCmSBFiR3Ole1MwNwp67hzQmFILqoBRKmJoEOfhjOiTCMET4SP7IE2pcpGKJyP
yJHwlfsG8SKTXBOsu9NUizX4HvSZ4ohXU6cXABEBAAEAB/0UxDoMOnmk92MNiZNj
i1acKS7Nz7+w7GZSw3AbGSFz3ousDvLhKEJmVlUAO/1QxHy8net99IH8w7/3/9BB
PlA7X11fVmdeAM6kU7hZoEDIlm0SCSe+HfHCaPzwFNZSdwfIEjacmlyvQ8yVILsK
RJTdtE9FTjoaMA1mQKxo6LD9zWxrbLX35DaVwpaY/co5bBouVa224Pgs/7zTMhVS
ObOSNduLaK8tSm5kuChjxCSULanbk1bjvNC2OIQEpMYYSP6y+OFgN1KWQaV59j23
KnFbenW/f6JayKE48lq9FPyvtFSDpL1JoouRsOBKGyFUBxlwZHw+n42L5HDR575O
XM7xBADIMtEXQU2PNwkYMkxM9KIVJ0M9u7X2H8/S5ENhBw6eNR8KXfs6RXRhc3N7
Xx+H+1SNqIU+sLfH9ckTmY1A5qbQcTrjLUrDo//3coIUUqS6Yw4XysoYxDpAefGG
sxBLn7KuLhM4jSz5iEwlU+/50YsafOf2S3NRMfpEHTZlcdr8bwQAzDDpzMsxKLWQ
/wZiQlskDgD+4jfErLs7j/IOP3jPa3zodVd8FZ0aZvIK5dML50D35wC2hrXZIGfg
SsCQpBNNybASxc1M66GRLUNYbrZ1oJPwW8UxyrfGIgzT7ITFkaFfLI4HXaGYZ8V6
WBZxPe2RAw3UJQeJmzOYo3DZ58gXo9kD/jLU2VpxpU/3BKrRO5AyvfMUKWlKXleT
pogdwcu0hHYntKr4mce7tBlRQRhtUv4dzRQ8OJ75oyvtl9mNfWaIOB/Jv5UOxeXh
jh20P23NClrtoM+5lYiaLEx0ZfD8xq85AKqrhMwcw4jH0lhJebTYOEeKrfD6SPbL
bzBv85X5WCw7RQ8=
=hd62
-----END PGP PRIVATE KEY BLOCK-----
")?;

        // PKESK
        let c = b"\x8A\x1A\xD4\x82\x91\x6B\xBF\xA1\x65\xD3\x82\x8C\x97\xAB\xD0\x91\xE4\xB4\xC4\x9D\x08\xD8\x8B\xB7\xE6\x13\x3F\x6F\x52\x14\xED\xC4\x77\xB7\x31\x00\xC1\x43\xF9\x62\x53\xBF\x21\x21\x52\x74\x35\xD8\xC7\xA2\x11\x89\xA5\xD5\x21\x98\x6D\x3C\x9F\xF0\xED\xDB\xD7\x0F\xAC\x3C\x15\x25\x34\x52\xC7\x7C\x82\x07\x5A\x99\xC1\xC6\xF6\xF2\x6D\x46\xC8\x56\x59\xE7\xC6\x34\x0C\xCA\x37\x70\xB4\x97\xDA\x18\x14\xC4\x03\x0A\xCB\xE5\x0C\x41\x43\x61\xBA\x32\xB6\x9A\xF3\xDF\x0C\xB0\xCE\xBD\xFE\x72\x6C\xCC\xC1\xE8\xF0\x05\x97\x61\xEA\x30\x10\xB9\x43\xC4\x9A\x41\xED\x72\x27\xA4\xD5\xE7\x08\x41\x6C\x57\x80\xF3\x64\xF0\x45\x70\x27\x36\xBD\x64\x59\x74\xCF\xCD\x39\xE6\xEB\x7C\x62\xC8\x38\x23\xF8\x4C\xB7\x30\x9F\xF1\x40\x4A\xE9\x72\x66\x99\xF7\x2A\x47\x1C\xE7\x12\x20\x58\xBA\x87\x00\xB8\xFC\x54\xBC\xA5\x1D\x7D\x8B\x50\xA4\x4B\xB3\xD7\x44\xC7\x68\x5E\x2D\xBB\xE9\x6E\xC4\xD0\x31\xB0\xD0\xB6\x02\xD1\x74\x6B\xC9\x3D\x19\x32\x3B\xF1\x0E\x74\xF6\x12\x13\xE6\x40\x8F\xA6\x97\xAD\x83\xB0\x84\xD6\xD9\xE5\x25\x8E\x57\x0B\x7A\x7B\xD0\x5C\x29\x96\xED\x29\xED";
        let ciphertext = Ciphertext::RSA{
            c: MPI::new(&c[..]),
        };
        let pkesk = PKESK3::new(None,
                                PublicKeyAlgorithm::RSAEncryptSign,
                                ciphertext).unwrap();

        // Session key
        let dek = b"\xA5\x58\x3A\x04\x35\x8B\xC7\x3F\x4A\xEF\x0C\x5A\xEB\xED\x59\xCA\xFD\x96\xB5\x32\x23\x26\x0C\x91\x78\xD1\x31\x12\xF0\x41\x42\x9D";
        let sk = SessionKey::from(Vec::from(&dek[..]));

        let test = |d: &[u8], p: &[u8], q: &[u8]| -> Result<()> {
            let key: key::SecretKey
                = Key4::import_secret_rsa(d, p, q, ctime)?.into();
            assert_eq!(Packet::from(key.clone()), reference_key);
            let mut decryptor = key.into_keypair()?;
            let got_sk = pkesk.decrypt(&mut decryptor, None).unwrap();
            assert_eq!(got_sk.1, sk);
            Ok(())
        };

        test(d, p, q)?;
        test(d, q, p)?;
        Ok(())
    }

    #[test]
    fn import_ed25519() {
        use crate::types::SignatureType;
        use crate::packet::signature::Signature4;
        use crate::packet::signature::subpacket::{
            Subpacket, SubpacketValue, SubpacketArea};

        // Ed25519 key
        let ctime =
            time::UNIX_EPOCH + time::Duration::new(1548249630, 0);
        let q = b"\x57\x15\x45\x1B\x68\xA5\x13\xA2\x20\x0F\x71\x9D\xE3\x05\x3B\xED\xA2\x21\xDE\x61\x5A\xF5\x67\x45\xBB\x97\x99\x43\x53\x59\x7C\x3F";
        let key: key::PublicKey
            = Key4::import_public_ed25519(q, ctime).unwrap().into();

        let mut hashed = SubpacketArea::default();
        let mut unhashed = SubpacketArea::default();
        let fpr = "D81A 5DC0 DEBF EE5F 9AC8  20EB 6769 5DB9 920D 4FAC"
            .parse().unwrap();
        let kid = "6769 5DB9 920D 4FAC".parse().unwrap();
        let ctime = 1549460479.into();
        let r = b"\x5A\xF9\xC7\x42\x70\x24\x73\xFF\x7F\x27\xF9\x20\x9D\x20\x0F\xE3\x8F\x71\x3C\x5F\x97\xFD\x60\x80\x39\x29\xC2\x14\xFD\xC2\x4D\x70";
        let s = b"\x6E\x68\x74\x11\x72\xF4\x9C\xE1\x99\x99\x1F\x67\xFC\x3A\x68\x33\xF9\x3F\x3A\xB9\x1A\xA5\x72\x4E\x78\xD4\x81\xCB\x7B\xA5\xE5\x0A";

        hashed.add(Subpacket::new(SubpacketValue::IssuerFingerprint(fpr), false).unwrap()).unwrap();
        hashed.add(Subpacket::new(SubpacketValue::SignatureCreationTime(ctime), false).unwrap()).unwrap();
        unhashed.add(Subpacket::new(SubpacketValue::Issuer(kid), false).unwrap()).unwrap();

        eprintln!("fpr: {}", key.fingerprint());
        let sig = Signature4::new(SignatureType::Binary, PublicKeyAlgorithm::EdDSA,
                                  HashAlgorithm::SHA256, hashed, unhashed,
                                  [0xa7,0x19],
                                  mpi::Signature::EdDSA{
                                      r: mpi::MPI::new(r), s: mpi::MPI::new(s)
                                  });
        let sig: Signature = sig.into();
        sig.verify_message(&key, b"Hello, World\n").unwrap();
    }

    #[test]
    fn fingerprint_test() {
        let pile =
            PacketPile::from_bytes(crate::tests::key("public-key.pgp")).unwrap();

        // The blob contains a public key and three subkeys.
        let mut pki = 0;
        let mut ski = 0;

        let pks = [ "8F17777118A33DDA9BA48E62AACB3243630052D9" ];
        let sks = [ "C03FA6411B03AE12576461187223B56678E02528",
                    "50E6D924308DBF223CFB510AC2B819056C652598",
                    "2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08"];

        for p in pile.descendants() {
            if let &Packet::PublicKey(ref p) = p {
                let fp = p.fingerprint().to_hex();
                // eprintln!("PK: {:?}", fp);

                assert!(pki < pks.len());
                assert_eq!(fp, pks[pki]);
                pki += 1;
            }

            if let &Packet::PublicSubkey(ref p) = p {
                let fp = p.fingerprint().to_hex();
                // eprintln!("SK: {:?}", fp);

                assert!(ski < sks.len());
                assert_eq!(fp, sks[ski]);
                ski += 1;
            }
        }
        assert!(pki == pks.len() && ski == sks.len());
    }

    #[test]
    fn issue_617() -> Result<()> {
        use crate::serialize::MarshalInto;
        let p = Packet::from_bytes(&b"-----BEGIN PGP ARMORED FILE-----

xcClBAAAAMUWBSuBBAAjAPDbS+Z6Ti+PouOV6c5Ypr3jn1w1Ih5GqikN5E29PGz+
CQMIoYc7R4YRiLr/ZJB/MW5M0kuuWyUirUKRkYCotB5omVE8fGtqW5wGCGf79Tzb
rKVmPl25CJdEabIfAOl0WwciipDx1tqNOOYEci/JWSbTEymEyCH9oQPObt2sdDxh
wLcBgsd/CVl3kuqiXFHNYDvWVBmUHeltS/J22Kfy/n1qD3CCBFooHGdc13KwtMLk
UPb5LTTqCk2ihQ7e+5u7EmueLUp1431HJiYa+olaPZ7caRNfQfggtHcfQOJdnWRJ
FN2nTDgLHX0cEOiMboZrS4S9xtjyVRLcRZcCIyeQF0Q889rq0lmxHG38XUeIj/3y
SJJNnZxmJtHNo+SZQ/gXhO9TzeeA6yQm2myQlRkXBtdQEz6mtznphWeWMkWApZpa
FwPoSAbbsLkNS/iNN2MDGAVYvezYn2QZ
=0cxs
-----END PGP ARMORED FILE-----"[..])?;
        let i: usize = 360;
        let mut buf = p.to_vec().unwrap();
        // Avoid first two bytes so that we don't change the
        // type and reduce the chance of changing the length.
        let bit = i.saturating_add(2 * 8) % (buf.len() * 8);
        buf[bit / 8] ^= 1 << (bit % 8);
        match Packet::from_bytes(&buf) {
            Ok(q) => {
                eprintln!("{:?}", p);
                eprintln!("{:?}", q);
                assert!(p != q);
            },
            Err(_) => unreachable!(),
        };
        Ok(())
    }

    #[test]
    fn encrypt_huge_plaintext() -> Result<()> {
        let sk = crate::crypto::SessionKey::new(256).unwrap();

        if PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
            let rsa2k: Key<SecretParts, UnspecifiedRole> =
                Key4::generate_rsa(2048)?.into();
            assert!(matches!(
                rsa2k.encrypt(&sk).unwrap_err().downcast().unwrap(),
                crate::Error::InvalidArgument(_)
            ));
        }

        if PublicKeyAlgorithm::ECDH.is_supported()
            && Curve::Cv25519.is_supported()
        {
            let cv25519: Key<SecretParts, UnspecifiedRole> =
                Key4::generate_ecc(false, Curve::Cv25519)?.into();
            assert!(matches!(
                cv25519.encrypt(&sk).unwrap_err().downcast().unwrap(),
                crate::Error::InvalidArgument(_)
            ));
        }

        Ok(())
    }

    #[test]
    fn cv25519_secret_is_reversed() -> Result<()> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let (mut private_key, _) = Backend::x25519_generate_key()?;
        Backend::x25519_clamp_secret(&mut private_key);

        let key: Key4<_, UnspecifiedRole> =
            Key4::import_secret_cv25519(&private_key, None, None, None)?;
        if let crate::packet::key::SecretKeyMaterial::Unencrypted(key) = key.secret() {
            key.map(|secret| {
                if let mpi::SecretKeyMaterial::ECDH { scalar } = secret {
                    let scalar_reversed = private_key.iter().copied().rev().collect::<Vec<u8>>();
                    let scalar_actual = &*scalar.value_padded(32);
                    assert_eq!(scalar_actual, scalar_reversed);
                } else {
                    unreachable!();
                }
            })
        } else {
            unreachable!();
        }

        Ok(())
    }

    #[test]
    fn ed25519_secret_is_not_reversed() {
        let private_key: &[u8] =
            &crate::crypto::SessionKey::new(32).unwrap();
        let key: Key4<_, UnspecifiedRole> = Key4::import_secret_ed25519(private_key, None).unwrap();
        if let crate::packet::key::SecretKeyMaterial::Unencrypted(key) = key.secret() {
            key.map(|secret| {
                if let mpi::SecretKeyMaterial::EdDSA { scalar } = secret {
                    assert_eq!(&*scalar.value_padded(32), private_key);
                } else {
                    unreachable!();
                }
            })
        } else {
            unreachable!();
        }
    }

    #[test]
    fn issue_1016() {
        // The fingerprint is a function of the creation time,
        // algorithm, and public MPIs.  When we change them make sure
        // the fingerprint also changes.

        let mut g = quickcheck::Gen::new(256);

        let mut key = Key4::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        if key.creation_time() == UNIX_EPOCH {
            key.set_creation_time(UNIX_EPOCH + Duration::new(1, 0)).expect("ok");
        } else {
            key.set_creation_time(UNIX_EPOCH).expect("ok");
        }
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key4::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        key.set_pk_algo(PublicKeyAlgorithm::from(u8::from(key.pk_algo()) + 1));
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key4::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
        let fpr1 = key.fingerprint();
        loop {
            let mpis2 = mpi::PublicKey::arbitrary(&mut g);
            if key.mpis() != &mpis2 {
                *key.mpis_mut() = mpis2;
                break;
            }
        }
        assert_ne!(fpr1, key.fingerprint());

        let mut key = Key4::<PublicParts, UnspecifiedRole>::arbitrary(&mut g);
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
                    Key4::generate_ecc(for_signing, curve.clone())?.into();
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
                    Key4::generate_ecc(for_signing, curve.clone())?.into();

                let compressed = |mpi: &MPI| mpi.value()[0] == 0x40;
                let uncompressed = |mpi: &MPI| mpi.value()[0] == 0x04;

                match key.mpis() {
                    PublicKey::ECDSA { curve: c, q } if for_signing => {
                        assert!(c == &curve);
                        assert!(uncompressed(q));
                    },
                    PublicKey::EdDSA { curve: c, q } if for_signing => {
                        assert!(c == &curve);
                        assert!(compressed(q));
                    },
                    PublicKey::ECDH { curve: c, q, .. } if ! for_signing => {
                        assert!(c == &curve);
                        if curve == Curve::Cv25519 {
                            assert!(compressed(q));
                        } else {
                            assert!(uncompressed(q));
                        }

                        use crate::crypto::SessionKey;
                        let sk = SessionKey::new(32).unwrap();
                        let ciphertext = key.encrypt(&sk)?;
                        if let Ciphertext::ECDH { e, .. } = &ciphertext {
                            if curve == Curve::Cv25519 {
                                assert!(compressed(e));
                            } else {
                                assert!(uncompressed(e));
                            }
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
}
