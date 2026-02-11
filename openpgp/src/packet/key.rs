//! Key-related functionality.
//!
//! # Data Types
//!
//! The main data type is the [`Key`] enum.  This enum abstracts away
//! the differences between the key formats (the current [version 6],
//! the deprecated [version 4], and the legacy [version 3]).
//! Nevertheless, some functionality remains format specific.  For
//! instance, the `Key` enum doesn't provide a mechanism to generate
//! keys.  This functionality depends on the format.
//!
//! This version of Sequoia only supports version 6 and version 4 keys
//! ([`Key6`], and [`Key4`]).  However, future versions may include
//! limited support for version 3 keys to allow working with archived
//! messages.
//!
//! OpenPGP specifies four different types of keys: [public keys],
//! [secret keys], [public subkeys], and [secret subkeys].  These are
//! all represented by the `Key` enum and the `Key4` struct using
//! marker types.  We use marker types rather than an enum, to better
//! exploit the type checking.  For instance, type-specific methods
//! like [`Key4::secret`] are only exposed for those types that
//! actually support them.  See the documentation for [`Key`] for an
//! explanation of how the markers work.
//!
//! The [`SecretKeyMaterial`] data type allows working with secret key
//! material directly.  This enum has two variants: [`Unencrypted`],
//! and [`Encrypted`].  It is not normally necessary to use this data
//! structure directly.  The primary functionality that is of interest
//! to most users is decrypting secret key material.  This is usually
//! more conveniently done using [`Key::decrypt_secret`].
//!
//! [`Key`]: super::Key
//! [version 3]: https://tools.ietf.org/html/rfc1991#section-6.6
//! [version 4]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.2
//! [version 6]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-keys
//! [public keys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.1
//! [secret keys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.3
//! [public subkeys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.2
//! [secret subkeys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.5
//! [`Key::decrypt_secret`]: super::Key::decrypt_secret()
//!
//! # Key Creation
//!
//! Use [`Key6::generate_x25519`], [`Key6::generate_ed25519`],
//! [`Key6::generate_x448`], [`Key6::generate_ed448`],
//! [`Key6::generate_ecc`], or [`Key6::generate_rsa`] to create a new
//! key.
//!
//! Existing key material can be turned into an OpenPGP key using
//! [`Key6::import_public_x25519`], [`Key6::import_public_ed25519`],
//! [`Key6::import_public_x448`], [`Key6::import_public_ed448`],
//! [`Key6::import_public_rsa`], [`Key6::import_secret_x25519`],
//! [`Key6::import_secret_ed25519`], [`Key6::import_secret_x448`],
//! [`Key6::import_secret_ed448`], and [`Key6::import_secret_rsa`].
//!
//! Whether you create a new key or import existing key material, you
//! still need to create a binding signature, and, for signing keys, a
//! back signature for the key to be usable.
//!
//! # In-Memory Protection of Secret Key Material
//!
//! Whether the secret key material is protected on disk or not,
//! Sequoia encrypts unencrypted secret key material ([`Unencrypted`])
//! while it is memory.  This helps protect against [heartbleed]-style
//! attacks where a buffer over-read allows an attacker to read from
//! the process's address space.  This protection is less important
//! for Rust programs, which are memory safe.  However, it is
//! essential when Sequoia is used via its FFI.
//!
//! See [`crypto::mem::Encrypted`] for details.
//!
//! [heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
//! [`crypto::mem::Encrypted`]: super::super::crypto::mem::Encrypted

use std::fmt;
use std::convert::TryInto;
use std::hash::Hasher;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::cert::prelude::*;
use crate::crypto::{self, mem, mpi, KeyPair};
use crate::packet::prelude::*;
use crate::policy::HashAlgoSecurity;
use crate::PublicKeyAlgorithm;
use crate::seal;
use crate::SymmetricAlgorithm;
use crate::HashAlgorithm;
use crate::types::{
    AEADAlgorithm,
    Curve,
};
use crate::crypto::S2K;
use crate::Result;
use crate::crypto::Password;
use crate::crypto::SessionKey;

mod conversions;
mod v6;
pub use v6::Key6;
mod v4;
pub use v4::Key4;

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// The different `Key` packets are described in [Section 5.5 of RFC 9580].
///
///   [Section 5.5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5
///
/// # Key Variants
///
/// There are four different types of keys in OpenPGP: [public keys],
/// [secret keys], [public subkeys], and [secret subkeys].  Although
/// the semantics of each type of key are slightly different, the
/// underlying representation is identical (even a public key and a
/// secret key are the same: the public key variant just contains 0
/// bits of secret key material).
///
/// In Sequoia, we use a single type, `Key`, for all four variants.
/// To improve type safety, we use marker traits rather than an `enum`
/// to distinguish them.  Specifically, we `Key` is generic over two
/// type variables, `P` and `R`.
///
/// `P` and `R` take marker traits, which describe how any secret key
/// material should be treated, and the key's role (primary or
/// subordinate).  The markers also determine the `Key`'s behavior and
/// the exposed functionality.  `P` can be [`key::PublicParts`],
/// [`key::SecretParts`], or [`key::UnspecifiedParts`].  And, `R` can
/// be [`key::PrimaryRole`], [`key::SubordinateRole`], or
/// [`key::UnspecifiedRole`].
///
/// If `P` is `key::PublicParts`, any secret key material that is
/// present is ignored.  For instance, when serializing a key with
/// this marker, any secret key material will be skipped.  This is
/// illutrated in the following example.  If `P` is
/// `key::SecretParts`, then the key definitely contains secret key
/// material (although it is not guaranteed that the secret key
/// material is valid), and methods that require secret key material
/// are available.
///
/// Unlike `P`, `R` does not say anything about the `Key`'s content.
/// But, a key's role does influence's the key's semantics.  For
/// instance, some of a primary key's meta-data is located on the
/// primary User ID whereas a subordinate key's meta-data is located
/// on its binding signature.
///
/// The unspecified variants [`key::UnspecifiedParts`] and
/// [`key::UnspecifiedRole`] exist to simplify type erasure, which is
/// needed to mix different types of keys in a single collection.  For
/// instance, [`Cert::keys`] returns an iterator over the keys in a
/// certificate.  Since the keys have different roles (a primary key
/// and zero or more subkeys), but the `Iterator` has to be over a
/// single, fixed type, the returned keys use the
/// `key::UnspecifiedRole` marker.
///
/// [public keys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.1
/// [secret keys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.3
/// [public subkeys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.2
/// [secret subkeys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.1.5
/// [`Cert::keys`]: crate::Cert::keys
///
/// ## Examples
///
/// Serializing a public key with secret key material drops the secret
/// key material:
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
/// use sequoia_openpgp::parse::Parse;
/// use openpgp::serialize::Serialize;
///
/// # fn main() -> openpgp::Result<()> {
/// // Generate a new certificate.  It has secret key material.
/// let (cert, _) = CertBuilder::new()
///     .generate()?;
///
/// let pk = cert.primary_key().key();
/// assert!(pk.has_secret());
///
/// // Serializing a `Key<key::PublicParts, _>` drops the secret key
/// // material.
/// let mut bytes = Vec::new();
/// Packet::from(pk.clone()).serialize(&mut bytes);
/// let p : Packet = Packet::from_bytes(&bytes)?;
///
/// if let Packet::PublicKey(key) = p {
///     assert!(! key.has_secret());
/// } else {
///     unreachable!();
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Conversions
///
/// Sometimes it is necessary to change a marker.  For instance, to
/// help prevent a user from inadvertently leaking secret key
/// material, the [`Cert`] data structure never returns keys with the
/// [`key::SecretParts`] marker.  This means, to use any secret key
/// material, e.g., when creating a [`Signer`], the user needs to
/// explicitly opt-in by changing the marker using
/// [`Key::parts_into_secret`] or [`Key::parts_as_secret`].
///
/// For `P`, the conversion functions are: [`Key::parts_into_public`],
/// [`Key::parts_as_public`], [`Key::parts_into_secret`],
/// [`Key::parts_as_secret`], [`Key::parts_into_unspecified`], and
/// [`Key::parts_as_unspecified`].  With the exception of converting
/// `P` to `key::SecretParts`, these functions are infallible.
/// Converting `P` to `key::SecretParts` may fail if the key doesn't
/// have any secret key material.  (Note: although the secret key
/// material is required, it is not checked for validity.)
///
/// For `R`, the conversion functions are [`Key::role_into_primary`],
/// [`Key::role_as_primary`], [`Key::role_into_subordinate`],
/// [`Key::role_as_subordinate`], [`Key::role_into_unspecified`], and
/// [`Key::role_as_unspecified`].
///
/// It is also possible to use `From`.
///
/// [`Signer`]: crate::crypto::Signer
/// [`Key::parts_as_secret`]: Key::parts_as_secret()
/// [`Key::parts_into_public`]: Key::parts_into_public()
/// [`Key::parts_as_public`]: Key::parts_as_public()
/// [`Key::parts_into_secret`]: Key::parts_into_secret()
/// [`Key::parts_as_secret`]: Key::parts_as_secret()
/// [`Key::parts_into_unspecified`]: Key::parts_into_unspecified()
/// [`Key::parts_as_unspecified`]: Key::parts_as_unspecified()
/// [`Key::role_into_primary`]: Key::role_into_primary()
/// [`Key::role_as_primary`]: Key::role_as_primary()
/// [`Key::role_into_subordinate`]: Key::role_into_subordinate()
/// [`Key::role_as_subordinate`]: Key::role_as_subordinate()
/// [`Key::role_into_unspecified`]: Key::role_into_unspecified()
/// [`Key::role_as_unspecified`]: Key::role_as_unspecified()
///
/// ## Examples
///
/// Changing a marker:
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
///
/// # fn main() -> openpgp::Result<()> {
/// // Generate a new certificate.  It has secret key material.
/// let (cert, _) = CertBuilder::new()
///     .generate()?;
///
/// let pk: &Key<key::PublicParts, key::PrimaryRole>
///     = cert.primary_key().key();
/// // `has_secret`s is one of the few methods that ignores the
/// // parts type.
/// assert!(pk.has_secret());
///
/// // Treat it like a secret key.  This only works if `pk` really
/// // has secret key material (which it does in this case, see above).
/// let sk = pk.parts_as_secret()?;
/// assert!(sk.has_secret());
///
/// // And back.
/// let pk = sk.parts_as_public();
/// // Yes, the secret key material is still there.
/// assert!(pk.has_secret());
/// # Ok(())
/// # }
/// ```
///
/// The [`Cert`] data structure only returns public keys.  To work
/// with any secret key material, the `Key` first needs to be
/// converted to a secret key.  This is necessary, for instance, when
/// creating a [`Signer`]:
///
/// [`Cert`]: crate::Cert
///
/// ```rust
/// use std::time;
/// use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use openpgp::cert::prelude::*;
/// use openpgp::crypto::KeyPair;
/// use openpgp::policy::StandardPolicy;
///
/// # fn main() -> Result<()> {
/// let p = &StandardPolicy::new();
///
/// let the_past = time::SystemTime::now() - time::Duration::from_secs(1);
/// let (cert, _) = CertBuilder::new()
///     .set_creation_time(the_past)
///     .generate()?;
///
/// // Set the certificate to expire now.  To do this, we need
/// // to create a new self-signature, and sign it using a
/// // certification-capable key.  The primary key is always
/// // certification capable.
/// let mut keypair = cert.primary_key()
///     .key().clone().parts_into_secret()?.into_keypair()?;
/// let sigs = cert.set_expiration_time(p, None, &mut keypair,
///                                     Some(time::SystemTime::now()))?;
///
/// let cert = cert.insert_packets(sigs)?.0;
/// // It's expired now.
/// assert!(cert.with_policy(p, None)?.alive().is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Key Generation
///
/// `Key` is a wrapper around [the different key formats].
/// (Currently, Sequoia only supports version 6 and version 4 keys,
/// however, future versions may add limited support for version 3
/// keys to facilitate working with achieved messages.)  As such, it
/// doesn't provide a mechanism to generate keys or import existing
/// key material.  Instead, use the format-specific functions (e.g.,
/// [`Key6::generate_ecc`]) and then convert the result into a `Key`
/// packet, as the following example demonstrates.
///
/// [the different key formats]: https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-packet-formats
///
/// ## Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::packet::prelude::*;
/// use openpgp::types::Curve;
///
/// # fn main() -> openpgp::Result<()> {
/// let key: Key<key::SecretParts, key::PrimaryRole>
///     = Key::from(Key6::generate_ecc(true, Curve::Ed25519)?);
/// # Ok(())
/// # }
/// ```
///
/// # Password Protection
///
/// OpenPGP provides a mechanism to [password protect keys].  If a key
/// is password protected, you need to decrypt the password using
/// [`Key::decrypt_secret`] before using its secret key material
/// (e.g., to decrypt a message, or to generate a signature).
///
/// [password protect keys]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7
/// [`Key::decrypt_secret`]: Key::decrypt_secret()
///
/// # A note on equality
///
/// The implementation of `Eq` for `Key` compares the serialized form
/// of `Key`s.  Comparing or serializing values of `Key<PublicParts,
/// _>` ignore secret key material, whereas the secret key material is
/// considered and serialized for `Key<SecretParts, _>`, and for
/// `Key<UnspecifiedParts, _>` if present.  To explicitly exclude the
/// secret key material from the comparison, use [`Key::public_cmp`]
/// or [`Key::public_eq`].
///
/// When merging in secret key material from untrusted sources, you
/// need to be very careful: secret key material is not
/// cryptographically protected by the key's self signature.  Thus, an
/// attacker can provide a valid key with a valid self signature, but
/// invalid secret key material.  If naively merged, this could
/// overwrite valid secret key material, and thereby render the key
/// useless.  Unfortunately, the only way to find out that the secret
/// key material is bad is to actually try using it.  But, because the
/// secret key material is usually encrypted, this can't always be
/// done automatically.
///
/// [`Key::public_cmp`]: Key::public_cmp()
/// [`Key::public_eq`]: Key::public_eq()
///
/// Compare:
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
/// use openpgp::packet::key::*;
///
/// # fn main() -> openpgp::Result<()> {
/// // Generate a new certificate.  It has secret key material.
/// let (cert, _) = CertBuilder::new()
///     .generate()?;
///
/// let sk: &Key<PublicParts, _> = cert.primary_key().key();
/// assert!(sk.has_secret());
///
/// // Strip the secret key material.
/// let cert = cert.clone().strip_secret_key_material();
/// let pk: &Key<PublicParts, _> = cert.primary_key().key();
/// assert!(! pk.has_secret());
///
/// // Eq on Key<PublicParts, _> compares only the public bits, so it
/// // considers pk and sk to be equal.
/// assert_eq!(pk, sk);
///
/// // Convert to Key<UnspecifiedParts, _>.
/// let sk: &Key<UnspecifiedParts, _> = sk.parts_as_unspecified();
/// let pk: &Key<UnspecifiedParts, _> = pk.parts_as_unspecified();
///
/// // Eq on Key<UnspecifiedParts, _> compares both the public and the
/// // secret bits, so it considers pk and sk to be different.
/// assert_ne!(pk, sk);
///
/// // In any case, Key::public_eq only compares the public bits,
/// // so it considers them to be equal.
/// assert!(Key::public_eq(pk, sk));
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
#[derive(PartialEq, Eq, Hash, Debug)]
pub enum Key<P: key::KeyParts, R: key::KeyRole> {
    /// A version 4 `Key` packet.
    V4(Key4<P, R>),

    /// A version 6 `Key` packet.
    V6(Key6<P, R>),
}
assert_send_and_sync!(Key<P, R> where P: key::KeyParts, R: key::KeyRole);

// derive(Clone) doesn't work as expected with generic type parameters
// that don't implement clone: it adds a trait bound on Clone to P and
// R in the Clone implementation.  Happily, we don't need P or R to
// implement Clone: they are just marker traits, which we can clone
// manually.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<P, R> Clone for Key<P, R>
    where P: key::KeyParts, R: key::KeyRole
{
    fn clone(&self) -> Self {
        match self {
            Key::V4(key) => Key::V4(key.clone()),
            Key::V6(key) => Key::V6(key.clone()),
        }
    }
}

impl<P: key::KeyParts, R: key::KeyRole> fmt::Display for Key<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::V4(k) => k.fmt(f),
            Key::V6(k) => k.fmt(f),
        }
    }
}

impl From<Key<key::PublicParts, key::PrimaryRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::PublicParts, key::PrimaryRole>) -> Self {
        Packet::PublicKey(k)
    }
}

impl From<Key<key::PublicParts, key::SubordinateRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::PublicParts, key::SubordinateRole>) -> Self {
        Packet::PublicSubkey(k)
    }
}

impl From<Key<key::SecretParts, key::PrimaryRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::SecretParts, key::PrimaryRole>) -> Self {
        Packet::SecretKey(k)
    }
}

impl From<Key<key::SecretParts, key::SubordinateRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::SecretParts, key::SubordinateRole>) -> Self {
        Packet::SecretSubkey(k)
    }
}

impl<R: key::KeyRole> Key<key::SecretParts, R> {
    /// Gets the `Key`'s `SecretKeyMaterial`.
    pub fn secret(&self) -> &SecretKeyMaterial {
        match self {
            Key::V4(k) => k.secret(),
            Key::V6(k) => k.secret(),
        }
    }

    /// Gets a mutable reference to the `Key`'s `SecretKeyMaterial`.
    pub fn secret_mut(&mut self) -> &mut SecretKeyMaterial {
        match self {
            Key::V4(k) => k.secret_mut(),
            Key::V6(k) => k.secret_mut(),
        }
    }

    /// Creates a new key pair from a `Key` with an unencrypted
    /// secret key.
    ///
    /// If the `Key` is password protected, you first need to decrypt
    /// it using [`Key::decrypt_secret`].
    ///
    /// [`Key::decrypt_secret`]: Key::decrypt_secret()
    ///
    /// # Errors
    ///
    /// Fails if the secret key is encrypted.
    ///
    /// # Examples
    ///
    /// Revoke a certificate by signing a new revocation certificate:
    ///
    /// ```rust
    /// use std::time;
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::types::ReasonForRevocation;
    ///
    /// # fn main() -> Result<()> {
    /// // Generate a certificate.
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(Some("Alice Lovelace <alice@example.org>"))
    ///         .generate()?;
    ///
    /// // Use the secret key material to sign a revocation certificate.
    /// let mut keypair = cert.primary_key()
    ///     .key().clone().parts_into_secret()?
    ///     .into_keypair()?;
    /// let rev = cert.revoke(&mut keypair,
    ///                       ReasonForRevocation::KeyCompromised,
    ///                       b"It was the maid :/")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_keypair(self) -> Result<KeyPair> {
        match self {
            Key::V4(k) => k.into_keypair(),
            Key::V6(k) => k.into_keypair(),
        }
    }

    /// Decrypts the secret key material.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// [protected with a password]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3
    /// [KDF]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7
    ///
    /// This function takes ownership of the `Key`, decrypts the
    /// secret key material using the password, and returns a new key
    /// whose secret key material is not password protected.
    ///
    /// If the secret key material is not password protected or if the
    /// password is wrong, this function returns an error.
    ///
    /// # Examples
    ///
    /// Sign a new revocation certificate using a password-protected
    /// key:
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::types::ReasonForRevocation;
    ///
    /// # fn main() -> Result<()> {
    /// // Generate a certificate whose secret key material is
    /// // password protected.
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(Some("Alice Lovelace <alice@example.org>"))
    ///         .set_password(Some("1234".into()))
    ///         .generate()?;
    ///
    /// // Use the secret key material to sign a revocation certificate.
    /// let key = cert.primary_key().key().clone().parts_into_secret()?;
    ///
    /// // We can't turn it into a keypair without decrypting it.
    /// assert!(key.clone().into_keypair().is_err());
    ///
    /// // And, we need to use the right password.
    /// assert!(key.clone()
    ///     .decrypt_secret(&"correct horse battery staple".into())
    ///     .is_err());
    ///
    /// // Let's do it right:
    /// let mut keypair = key.decrypt_secret(&"1234".into())?.into_keypair()?;
    /// let rev = cert.revoke(&mut keypair,
    ///                       ReasonForRevocation::KeyCompromised,
    ///                       b"It was the maid :/")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_secret(self, password: &Password) -> Result<Self>
    {
        match self {
            Key::V4(k) => Ok(Key::V4(k.decrypt_secret(password)?)),
            Key::V6(k) => Ok(Key::V6(k.decrypt_secret(password)?)),
        }
    }

    /// Encrypts the secret key material.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// [protected with a password]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3
    /// [KDF]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7
    ///
    /// This function takes ownership of the `Key`, encrypts the
    /// secret key material using the password, and returns a new key
    /// whose secret key material is protected with the password.
    ///
    /// If the secret key material is already password protected, this
    /// function returns an error.
    ///
    /// # Examples
    ///
    /// This example demonstrates how to encrypt the secret key
    /// material of every key in a certificate.  Decryption can be
    /// done the same way with [`Key::decrypt_secret`].
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::Packet;
    ///
    /// # fn main() -> Result<()> {
    /// // Generate a certificate whose secret key material is
    /// // not password protected.
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(Some("Alice Lovelace <alice@example.org>"))
    ///         .generate()?;
    ///
    /// // Encrypt every key.
    /// let mut encrypted_keys: Vec<Packet> = Vec::new();
    /// for ka in cert.keys().secret() {
    ///     assert!(ka.key().has_unencrypted_secret());
    ///
    ///     // Encrypt the key's secret key material.
    ///     let key = ka.key().clone().encrypt_secret(&"1234".into())?;
    ///     assert!(! key.has_unencrypted_secret());
    ///
    ///     // We cannot merge it right now, because `cert` is borrowed.
    ///     encrypted_keys.push(if ka.primary() {
    ///         key.role_into_primary().into()
    ///     } else {
    ///         key.role_into_subordinate().into()
    ///     });
    /// }
    ///
    /// // Merge the keys into the certificate.  Note: `Cert::insert_packets`
    /// // prefers added versions of keys.  So, the encrypted version
    /// // will override the decrypted version.
    /// let cert = cert.insert_packets(encrypted_keys)?.0;
    ///
    /// // Now the every key's secret key material is encrypted.  We'll
    /// // demonstrate this using the primary key:
    /// let key = cert.primary_key().key().parts_as_secret()?;
    /// assert!(! key.has_unencrypted_secret());
    ///
    /// // We can't turn it into a keypair without decrypting it.
    /// assert!(key.clone().into_keypair().is_err());
    ///
    /// // And, we need to use the right password.
    /// assert!(key.clone()
    ///     .decrypt_secret(&"correct horse battery staple".into())
    ///     .is_err());
    ///
    /// // Let's do it right:
    /// let mut keypair = key.clone()
    ///     .decrypt_secret(&"1234".into())?.into_keypair()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_secret(self, password: &Password) -> Result<Self>
    {
        match self {
            Key::V4(k) => Ok(Key::V4(k.encrypt_secret(password)?)),
            Key::V6(k) => Ok(Key::V6(k.encrypt_secret(password)?)),
        }
    }
}

macro_rules! impl_common_secret_functions {
    ($t: path) => {
        /// Secret key handling.
        impl<R: key::KeyRole> Key<$t, R> {
            /// Takes the key packet's `SecretKeyMaterial`, if any.
            pub fn take_secret(self)
                               -> (Key<key::PublicParts, R>,
                                   Option<key::SecretKeyMaterial>)
            {
                match self {
                    Key::V4(k) => {
                        let (k, s) = k.take_secret();
                        (k.into(), s)
                    },
                    Key::V6(k) => {
                        let (k, s) = k.take_secret();
                        (k.into(), s)
                    },
                }
            }

            /// Adds `SecretKeyMaterial` to the packet, returning the old if
            /// any.
            pub fn add_secret(self, secret: key::SecretKeyMaterial)
                              -> (Key<key::SecretParts, R>,
                                  Option<key::SecretKeyMaterial>)
            {
                match self {
                    Key::V4(k) => {
                        let (k, s) = k.add_secret(secret);
                        (k.into(), s)
                    },
                    Key::V6(k) => {
                        let (k, s) = k.add_secret(secret);
                        (k.into(), s)
                    },
                }
            }

            /// Takes the key packet's `SecretKeyMaterial`, if any.
            pub fn steal_secret(&mut self) -> Option<key::SecretKeyMaterial>
            {
                match self {
                    Key::V4(k) => k.steal_secret(),
                    Key::V6(k) => k.steal_secret(),
                }
            }
        }
    }
}
impl_common_secret_functions!(key::PublicParts);
impl_common_secret_functions!(key::UnspecifiedParts);

/// Secret key handling.
impl<R: key::KeyRole> Key<key::SecretParts, R> {
    /// Takes the key packet's `SecretKeyMaterial`.
    pub fn take_secret(self)
                       -> (Key<key::PublicParts, R>, key::SecretKeyMaterial)
    {
        match self {
            Key::V4(k) => {
                let (k, s) = k.take_secret();
                (k.into(), s)
            },
            Key::V6(k) => {
                let (k, s) = k.take_secret();
                (k.into(), s)
            },
        }
    }

    /// Adds `SecretKeyMaterial` to the packet, returning the old.
    pub fn add_secret(self, secret: key::SecretKeyMaterial)
                      -> (Key<key::SecretParts, R>, key::SecretKeyMaterial)
    {
        match self {
            Key::V4(k) => {
                let (k, s) = k.add_secret(secret);
                (k.into(), s)
            },
            Key::V6(k) => {
                let (k, s) = k.add_secret(secret);
                (k.into(), s)
            },
        }
    }
}

/// Ordering, equality, and hashing on the public parts only.
impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Compares the public bits of two keys.
    ///
    /// This returns `Ordering::Equal` if the public MPIs, creation
    /// time, and algorithm of the two `Key4`s match.  This does not
    /// consider the packets' encodings, packets' tags or their secret
    /// key material.
    pub fn public_cmp<PB, RB>(&self, b: &Key<PB, RB>)
                              -> std::cmp::Ordering
    where
        PB: key::KeyParts,
        RB: key::KeyRole,
    {
        match (self, b) {
            (Key::V4(a), Key::V4(b)) => a.public_cmp(b),
            (Key::V6(a), Key::V6(b)) => a.public_cmp(b),
            // XXX: is that okay?
            (Key::V4(_), Key::V6(_)) => std::cmp::Ordering::Less,
            (Key::V6(_), Key::V4(_)) => std::cmp::Ordering::Greater,
        }
    }

    /// Tests whether two keys are equal modulo their secret key
    /// material.
    ///
    /// This returns true if the public MPIs, creation time and
    /// algorithm of the two `Key4`s match.  This does not consider
    /// the packets' encodings, packets' tags or their secret key
    /// material.
    pub fn public_eq<PB, RB>(&self, b: &Key<PB, RB>)
                             -> bool
    where
        PB: key::KeyParts,
        RB: key::KeyRole,
    {
        self.public_cmp(b) == std::cmp::Ordering::Equal
    }

    /// Hashes everything but any secret key material into state.
    ///
    /// This is an alternate implementation of [`Hash`], which never
    /// hashes the secret key material.
    ///
    ///   [`Hash`]: std::hash::Hash
    pub fn public_hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        use std::hash::Hash;

        match self {
            Key::V4(k) => k.common.hash(state),
            Key::V6(k) => k.common.common.hash(state),
        }
        self.creation_time().hash(state);
        self.pk_algo().hash(state);
        Hash::hash(&self.mpis(), state);
    }
}

/// Immutable key interface.
impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            Key::V4(_) => 4,
            Key::V6(_) => 6,
        }
    }

    /// Gets the `Key`'s creation time.
    pub fn creation_time(&self) -> std::time::SystemTime {
        match self {
            Key::V4(k) => k.creation_time(),
            Key::V6(k) => k.creation_time(),
        }
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
                                -> Result<std::time::SystemTime>
    where
        T: Into<std::time::SystemTime>,
    {
        match self {
            Key::V4(k) => k.set_creation_time(timestamp.into()),
            Key::V6(k) => k.set_creation_time(timestamp.into()),
        }
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        match self {
            Key::V4(k) => k.pk_algo(),
            Key::V6(k) => k.pk_algo(),
        }
    }

    /// Sets the public key algorithm.
    ///
    /// Returns the old public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm)
                       -> PublicKeyAlgorithm
    {
        match self {
            Key::V4(k) => k.set_pk_algo(pk_algo),
            Key::V6(k) => k.set_pk_algo(pk_algo),
        }
    }

    /// Returns a reference to the `Key`'s MPIs.
    pub fn mpis(&self) -> &mpi::PublicKey {
        match self {
            Key::V4(k) => k.mpis(),
            Key::V6(k) => k.mpis(),
        }
    }

    /// Returns a mutable reference to the `Key`'s MPIs.
    pub fn mpis_mut(&mut self) -> &mut mpi::PublicKey {
        match self {
            Key::V4(k) => k.mpis_mut(),
            Key::V6(k) => k.mpis_mut(),
        }
    }

    /// Sets the `Key`'s MPIs.
    ///
    /// This function returns the old MPIs, if any.
    pub fn set_mpis(&mut self, mpis: mpi::PublicKey) -> mpi::PublicKey {
        match self {
            Key::V4(k) => k.set_mpis(mpis),
            Key::V6(k) => k.set_mpis(mpis),
        }
    }

    /// Returns whether the `Key` contains secret key material.
    pub fn has_secret(&self) -> bool {
        match self {
            Key::V4(k) => k.has_secret(),
            Key::V6(k) => k.has_secret(),
        }
    }

    /// Returns whether the `Key` contains unencrypted secret key
    /// material.
    ///
    /// This returns false if the `Key` doesn't contain any secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool {
        match self {
            Key::V4(k) => k.has_unencrypted_secret(),
            Key::V6(k) => k.has_unencrypted_secret(),
        }
    }

    /// Returns `Key`'s secret key material, if any.
    pub fn optional_secret(&self) -> Option<&SecretKeyMaterial> {
        match self {
            Key::V4(k) => k.optional_secret(),
            Key::V6(k) => k.optional_secret(),
        }
    }

    /// Computes and returns the `Key`'s `Fingerprint` and returns it as
    /// a `KeyHandle`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn key_handle(&self) -> crate::KeyHandle {
        match self {
            Key::V4(k) => k.key_handle(),
            Key::V6(k) => k.key_handle(),
        }
    }

    /// Computes and returns the `Key`'s `Fingerprint`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn fingerprint(&self) -> crate::Fingerprint {
        match self {
            Key::V4(k) => k.fingerprint(),
            Key::V6(k) => k.fingerprint(),
        }
    }

    /// Computes and returns the `Key`'s `Key ID`.
    ///
    /// See [Section 5.5.4 of RFC 9580].
    ///
    /// [Section 5.5.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4
    pub fn keyid(&self) -> crate::KeyID {
        match self {
            Key::V4(k) => k.keyid(),
            Key::V6(k) => k.keyid(),
        }
    }

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

    pub(crate) fn role(&self) -> key::KeyRoleRT {
        match self {
            Key::V4(k) => k.role(),
            Key::V6(k) => k.role(),
        }
    }

    pub(crate) fn set_role(&mut self, role: key::KeyRoleRT) {
        match self {
            Key::V4(k) => k.set_role(role),
            Key::V6(k) => k.set_role(role),
        }
    }
}

#[cfg(test)]
impl<P, R> Arbitrary for Key<P, R>
where
    P: KeyParts,
    R: KeyRole,
    Key4<P, R>: Arbitrary,
    Key6<P, R>: Arbitrary,
{
    fn arbitrary(g: &mut Gen) -> Self {
        if <bool>::arbitrary(g) {
            Key4::arbitrary(g).into()
        } else {
            Key6::arbitrary(g).into()
        }
    }
}

/// A marker trait that captures whether a `Key` definitely contains
/// secret key material.
///
/// A [`Key`] can be treated as if it only has public key material
/// ([`key::PublicParts`]) or also has secret key material
/// ([`key::SecretParts`]).  For those cases where the type
/// information needs to be erased (e.g., interfaces like
/// [`Cert::keys`]), we provide the [`key::UnspecifiedParts`] marker.
///
/// Even if a `Key` does not have the `SecretKey` marker, it may still
/// have secret key material.  But, it will generally act as if it
/// didn't.  In particular, when serializing a `Key` without the
/// `SecretKey` marker, secret key material will be ignored.  See the
/// documentation for [`Key`] for a demonstration of this behavior.
///
/// [`Cert::keys`]: crate::cert::Cert::keys()
/// [`Key`]: super::Key
/// [`key::PublicParts`]: PublicParts
/// [`key::SecretParts`]: SecretParts
/// [`key::UnspecifiedParts`]: UnspecifiedParts
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait KeyParts: fmt::Debug + seal::Sealed {
    /// Converts a key with unspecified parts into this kind of key.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key to one with [`key::SecretParts`] only
    /// succeeds if the key actually contains secret key material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    ///
    /// # Examples
    ///
    /// For a less construed example, refer to the [source code]:
    ///
    /// [source code]: https://gitlab.com/search?search=convert_key&project_id=4469613&search_code=true&repository_ref=master
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// fn f<P>(cert: &Cert, mut key: Key<P, key::UnspecifiedRole>)
    ///     -> Result<Key<P, key::UnspecifiedRole>>
    ///     where P: key::KeyParts
    /// {
    ///     // ...
    ///
    /// # let criterium = true;
    ///     if criterium {
    ///         // Cert::primary_key's return type is concrete
    ///         // (Key<key::PublicParts, key::PrimaryRole>).  We need to
    ///         // convert it to the generic type Key<P, key::UnspecifiedRole>.
    ///         // First, we "downcast" it to have unspecified parts and an
    ///         // unspecified role, then we use a method defined by the
    ///         // generic type to perform the conversion to the generic
    ///         // type P.
    ///         key = P::convert_key(
    ///             cert.primary_key().key().clone()
    ///                 .parts_into_unspecified()
    ///                 .role_into_unspecified())?;
    ///     }
    /// #   else { unreachable!() }
    ///
    ///     // ...
    ///
    ///     Ok(key)
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// # f(&cert, cert.primary_key().key().clone().role_into_unspecified())?;
    /// # Ok(())
    /// # }
    /// ```
    fn convert_key<R: KeyRole>(key: Key<UnspecifiedParts, R>)
                               -> Result<Key<Self, R>>
        where Self: Sized;

    /// Converts a key reference with unspecified parts into this kind
    /// of key reference.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key to one with [`key::SecretParts`] only
    /// succeeds if the key actually contains secret key material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    fn convert_key_ref<R: KeyRole>(key: &Key<UnspecifiedParts, R>)
                                   -> Result<&Key<Self, R>>
        where Self: Sized;

    /// Converts a key bundle with unspecified parts into this kind of
    /// key bundle.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key bundle with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key bundle to one with [`key::SecretParts`] only
    /// succeeds if the key bundle actually contains secret key
    /// material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    fn convert_bundle<R: KeyRole>(bundle: KeyBundle<UnspecifiedParts, R>)
                                  -> Result<KeyBundle<Self, R>>
        where Self: Sized;

    /// Converts a key bundle reference with unspecified parts into
    /// this kind of key bundle reference.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key bundle with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key bundle to one with [`key::SecretParts`] only
    /// succeeds if the key bundle actually contains secret key
    /// material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    fn convert_bundle_ref<R: KeyRole>(bundle: &KeyBundle<UnspecifiedParts, R>)
                                      -> Result<&KeyBundle<Self, R>>
        where Self: Sized;

    /// Converts a key amalgamation with unspecified parts into this
    /// kind of key amalgamation.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key amalgamation with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key amalgamation to one with [`key::SecretParts`]
    /// only succeeds if the key amalgamation actually contains secret
    /// key material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    fn convert_key_amalgamation<R: KeyRole>(
        ka: ComponentAmalgamation<Key<UnspecifiedParts, R>>)
        -> Result<ComponentAmalgamation<Key<Self, R>>>
        where Self: Sized;

    /// Converts a key amalgamation reference with unspecified parts
    /// into this kind of key amalgamation reference.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// Converting a key amalgamation with [`key::PublicParts`] or
    /// [`key::UnspecifiedParts`] will always succeed.  However,
    /// converting a key amalgamation to one with [`key::SecretParts`]
    /// only succeeds if the key amalgamation actually contains secret
    /// key material.
    ///
    /// [`key::PublicParts`]: PublicParts
    /// [`key::UnspecifiedParts`]: UnspecifiedParts
    /// [`key::SecretParts`]: SecretParts
    fn convert_key_amalgamation_ref<'a, R: KeyRole>(
        ka: &'a ComponentAmalgamation<'a, Key<UnspecifiedParts, R>>)
        -> Result<&'a ComponentAmalgamation<'a, Key<Self, R>>>
        where Self: Sized;

    /// Indicates that secret key material should be considered when
    /// comparing or hashing this key.
    fn significant_secrets() -> bool;
}

/// A marker trait that captures a `Key`'s role.
///
/// A [`Key`] can either be a primary key ([`key::PrimaryRole`]) or a
/// subordinate key ([`key::SubordinateRole`]).  For those cases where
/// the type information needs to be erased (e.g., interfaces like
/// [`Cert::keys`]), we provide the [`key::UnspecifiedRole`] marker.
///
/// [`Key`]: super::Key
/// [`key::PrimaryRole`]: PrimaryRole
/// [`key::SubordinateRole`]: SubordinateRole
/// [`Cert::keys`]: crate::cert::Cert::keys()
/// [`key::UnspecifiedRole`]: UnspecifiedRole
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait KeyRole: fmt::Debug + seal::Sealed {
    /// Converts a key with an unspecified role into this kind of key.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// fn f<R>(cert: &Cert, mut key: Key<key::UnspecifiedParts, R>)
    ///     -> Result<Key<key::UnspecifiedParts, R>>
    ///     where R: key::KeyRole
    /// {
    ///     // ...
    ///
    /// # let criterium = true;
    ///     if criterium {
    ///         // Cert::primary_key's return type is concrete
    ///         // (Key<key::PublicParts, key::PrimaryRole>).  We need to
    ///         // convert it to the generic type Key<key::UnspecifiedParts, R>.
    ///         // First, we "downcast" it to have unspecified parts and an
    ///         // unspecified role, then we use a method defined by the
    ///         // generic type to perform the conversion to the generic
    ///         // type R.
    ///         key = R::convert_key(
    ///             cert.primary_key().key().clone()
    ///                 .parts_into_unspecified()
    ///                 .role_into_unspecified());
    ///     }
    /// #   else { unreachable!() }
    ///
    ///     // ...
    ///
    ///     Ok(key)
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// # f(&cert, cert.primary_key().key().clone().parts_into_unspecified())?;
    /// # Ok(())
    /// # }
    /// ```
    fn convert_key<P: KeyParts>(key: Key<P, UnspecifiedRole>)
                                -> Key<P, Self>
        where Self: Sized;

    /// Converts a key reference with an unspecified role into this
    /// kind of key reference.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    fn convert_key_ref<P: KeyParts>(key: &Key<P, UnspecifiedRole>)
                                    -> &Key<P, Self>
        where Self: Sized;

    /// Converts a key bundle with an unspecified role into this kind
    /// of key bundle.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    fn convert_bundle<P: KeyParts>(bundle: KeyBundle<P, UnspecifiedRole>)
                                   -> KeyBundle<P, Self>
        where Self: Sized;

    /// Converts a key bundle reference with an unspecified role into
    /// this kind of key bundle reference.
    ///
    /// This function is helpful when you need to convert a concrete
    /// type into a generic type.  Using `From` works, but requires
    /// adding a type bound to the generic type, which is ugly and
    /// invasive.
    fn convert_bundle_ref<P: KeyParts>(bundle: &KeyBundle<P, UnspecifiedRole>)
                                       -> &KeyBundle<P, Self>
        where Self: Sized;

    /// Returns the role as a runtime value.
    fn role() -> KeyRoleRT;
}

/// A marker that indicates that a `Key` should be treated like a
/// public key.
///
/// Note: this doesn't indicate whether the data structure contains
/// secret key material; it indicates whether any secret key material
/// should be ignored.  For instance, when exporting a key with the
/// `PublicParts` marker, secret key material will *not* be exported.
/// See the documentation for [`Key`] for a demonstration.
///
/// Refer to [`KeyParts`] for details.
///
/// [`Key`]: super::Key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicParts;

assert_send_and_sync!(PublicParts);

impl seal::Sealed for PublicParts {}
impl KeyParts for PublicParts {
    fn convert_key<R: KeyRole>(key: Key<UnspecifiedParts, R>)
                               -> Result<Key<Self, R>> {
        Ok(key.into())
    }

    fn convert_key_ref<R: KeyRole>(key: &Key<UnspecifiedParts, R>)
                                   -> Result<&Key<Self, R>> {
        Ok(key.into())
    }

    fn convert_bundle<R: KeyRole>(bundle: KeyBundle<UnspecifiedParts, R>)
                                  -> Result<KeyBundle<Self, R>> {
        Ok(bundle.into())
    }

    fn convert_bundle_ref<R: KeyRole>(bundle: &KeyBundle<UnspecifiedParts, R>)
                                      -> Result<&KeyBundle<Self, R>> {
        Ok(bundle.into())
    }

    fn convert_key_amalgamation<R: KeyRole>(
        ka: ComponentAmalgamation<Key<UnspecifiedParts, R>>)
        -> Result<ComponentAmalgamation<Key<Self, R>>> {
        Ok(ka.into())
    }

    fn convert_key_amalgamation_ref<'a, R: KeyRole>(
        ka: &'a ComponentAmalgamation<'a, Key<UnspecifiedParts, R>>)
        -> Result<&'a ComponentAmalgamation<'a, Key<Self, R>>> {
        Ok(ka.into())
    }

    fn significant_secrets() -> bool {
        false
    }
}

/// A marker that indicates that a `Key` should be treated like a
/// secret key.
///
/// Unlike the [`key::PublicParts`] marker, this marker asserts that
/// the [`Key`] contains secret key material.  Because secret key
/// material is not protected by the self-signature, there is no
/// indication that the secret key material is actually valid.
///
/// Refer to [`KeyParts`] for details.
///
/// [`key::PublicParts`]: PublicParts
/// [`Key`]: super::Key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecretParts;

assert_send_and_sync!(SecretParts);

impl seal::Sealed for SecretParts {}
impl KeyParts for SecretParts {
    fn convert_key<R: KeyRole>(key: Key<UnspecifiedParts, R>)
                               -> Result<Key<Self, R>>{
        key.try_into()
    }

    fn convert_key_ref<R: KeyRole>(key: &Key<UnspecifiedParts, R>)
                                   -> Result<&Key<Self, R>> {
        key.try_into()
    }

    fn convert_bundle<R: KeyRole>(bundle: KeyBundle<UnspecifiedParts, R>)
                                  -> Result<KeyBundle<Self, R>> {
        bundle.try_into()
    }

    fn convert_bundle_ref<R: KeyRole>(bundle: &KeyBundle<UnspecifiedParts, R>)
                                      -> Result<&KeyBundle<Self, R>> {
        bundle.try_into()
    }

    fn convert_key_amalgamation<R: KeyRole>(
        ka: ComponentAmalgamation<Key<UnspecifiedParts, R>>)
        -> Result<ComponentAmalgamation<Key<Self, R>>> {
        ka.try_into()
    }

    fn convert_key_amalgamation_ref<'a, R: KeyRole>(
        ka: &'a ComponentAmalgamation<'a, Key<UnspecifiedParts, R>>)
        -> Result<&'a ComponentAmalgamation<'a, Key<Self, R>>> {
        ka.try_into()
    }

    fn significant_secrets() -> bool {
        true
    }
}

/// A marker that indicates that a `Key`'s parts are unspecified.
///
/// Neither public key-specific nor secret key-specific operations are
/// allowed on these types of keys.  For instance, it is not possible
/// to export a key with the `UnspecifiedParts` marker, because it is
/// unclear how to treat any secret key material.  To export such a
/// key, you need to first change the marker to [`key::PublicParts`]
/// or [`key::SecretParts`].
///
/// This marker is used when it is necessary to erase the type.  For
/// instance, we need to do this when mixing [`Key`]s with different
/// markers in the same collection.  See [`Cert::keys`] for an
/// example.
///
/// Refer to [`KeyParts`] for details.
///
/// [`key::PublicParts`]: PublicParts
/// [`key::SecretParts`]: SecretParts
/// [`Key`]: super::Key
/// [`Cert::keys`]: super::super::Cert::keys()
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnspecifiedParts;

assert_send_and_sync!(UnspecifiedParts);

impl seal::Sealed for UnspecifiedParts {}
impl KeyParts for UnspecifiedParts {
    fn convert_key<R: KeyRole>(key: Key<UnspecifiedParts, R>)
                               -> Result<Key<Self, R>> {
        Ok(key)
    }

    fn convert_key_ref<R: KeyRole>(key: &Key<UnspecifiedParts, R>)
                                   -> Result<&Key<Self, R>> {
        Ok(key)
    }

    fn convert_bundle<R: KeyRole>(bundle: KeyBundle<UnspecifiedParts, R>)
                                  -> Result<KeyBundle<Self, R>> {
        Ok(bundle)
    }

    fn convert_bundle_ref<R: KeyRole>(bundle: &KeyBundle<UnspecifiedParts, R>)
                                      -> Result<&KeyBundle<Self, R>> {
        Ok(bundle)
    }

    fn convert_key_amalgamation<R: KeyRole>(
        ka: ComponentAmalgamation<Key<UnspecifiedParts, R>>)
        -> Result<ComponentAmalgamation<Key<UnspecifiedParts, R>>> {
        Ok(ka)
    }

    fn convert_key_amalgamation_ref<'a, R: KeyRole>(
        ka: &'a ComponentAmalgamation<'a, Key<UnspecifiedParts, R>>)
        -> Result<&'a ComponentAmalgamation<'a, Key<Self, R>>> {
        Ok(ka)
    }

    fn significant_secrets() -> bool {
        true
    }
}

/// A marker that indicates the `Key` should be treated like a primary key.
///
/// Refer to [`KeyRole`] for details.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrimaryRole;

assert_send_and_sync!(PrimaryRole);

impl seal::Sealed for PrimaryRole {}
impl KeyRole for PrimaryRole {
    fn convert_key<P: KeyParts>(key: Key<P, UnspecifiedRole>)
                                -> Key<P, Self> {
        key.into()
    }

    fn convert_key_ref<P: KeyParts>(key: &Key<P, UnspecifiedRole>)
                                    -> &Key<P, Self> {
        key.into()
    }

    fn convert_bundle<P: KeyParts>(bundle: KeyBundle<P, UnspecifiedRole>)
                                   -> KeyBundle<P, Self> {
        bundle.into()
    }

    fn convert_bundle_ref<P: KeyParts>(bundle: &KeyBundle<P, UnspecifiedRole>)
                                       -> &KeyBundle<P, Self> {
        bundle.into()
    }

    fn role() -> KeyRoleRT {
        KeyRoleRT::Primary
    }
}

/// A marker that indicates the `Key` should be treated like a subkey.
///
/// Refer to [`KeyRole`] for details.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubordinateRole;

assert_send_and_sync!(SubordinateRole);

impl seal::Sealed for SubordinateRole {}
impl KeyRole for SubordinateRole {
    fn convert_key<P: KeyParts>(key: Key<P, UnspecifiedRole>)
                                -> Key<P, Self> {
        key.into()
    }

    fn convert_key_ref<P: KeyParts>(key: &Key<P, UnspecifiedRole>)
                                    -> &Key<P, Self> {
        key.into()
    }

    fn convert_bundle<P: KeyParts>(bundle: KeyBundle<P, UnspecifiedRole>)
                                   -> KeyBundle<P, Self> {
        bundle.into()
    }

    fn convert_bundle_ref<P: KeyParts>(bundle: &KeyBundle<P, UnspecifiedRole>)
                                       -> &KeyBundle<P, Self> {
        bundle.into()
    }

    fn role() -> KeyRoleRT {
        KeyRoleRT::Subordinate
    }
}

/// A marker that indicates the `Key`'s role is unspecified.
///
/// Neither primary key-specific nor subkey-specific operations are
/// allowed.  To perform those operations, the marker first has to be
/// changed to either [`key::PrimaryRole`] or
/// [`key::SubordinateRole`], as appropriate.
///
/// Refer to [`KeyRole`] for details.
///
/// [`key::PrimaryRole`]: PrimaryRole
/// [`key::SubordinateRole`]: SubordinateRole
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnspecifiedRole;

assert_send_and_sync!(UnspecifiedRole);

impl seal::Sealed for UnspecifiedRole {}
impl KeyRole for UnspecifiedRole {
    fn convert_key<P: KeyParts>(key: Key<P, UnspecifiedRole>)
                                -> Key<P, Self> {
        key
    }

    fn convert_key_ref<P: KeyParts>(key: &Key<P, UnspecifiedRole>)
                                    -> &Key<P, Self> {
        key
    }

    fn convert_bundle<P: KeyParts>(bundle: KeyBundle<P, UnspecifiedRole>)
                                   -> KeyBundle<P, Self> {
        bundle
    }

    fn convert_bundle_ref<P: KeyParts>(bundle: &KeyBundle<P, UnspecifiedRole>)
                                       -> &KeyBundle<P, Self> {
        bundle
    }

    fn role() -> KeyRoleRT {
        KeyRoleRT::Unspecified
    }
}

/// Encodes the key role at run time.
///
/// While `KeyRole` tracks the key's role in the type system,
/// `KeyRoleRT` tracks the key role at run time.
///
/// When we are doing a reference conversion (e.g. by using
/// [`Key::role_as_primary`]), we do not change the key's role.  But,
/// when we are doing an owned conversion (e.g. by using
/// [`Key::role_into_primary`]), we do change the key's role.  The
/// rationale here is that the former conversion is done to allow a
/// reference to be given to a function expecting a certain shape of
/// key (e.g. to prevent excessive monomorphization), while the latter
/// conversion signals intent (e.g. to put a key into a
/// `Packet::PublicKey`).
///
/// This is similar to how we have `KeyParts` that track the presence
/// or absence of secret key material in the type system, yet at run
/// time a key may or may not actually have secret key material (with
/// the constraint that a key with `SecretParts` MUST have secret key
/// material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRoleRT {
    /// The key is a primary key.
    Primary,

    /// The key is a subkey.
    Subordinate,

    /// The key's role is unspecified.
    Unspecified,
}

/// A Public Key.
pub(crate) type PublicKey = Key<PublicParts, PrimaryRole>;
/// A Public Subkey.
pub(crate) type PublicSubkey = Key<PublicParts, SubordinateRole>;
/// A Secret Key.
pub(crate) type SecretKey = Key<SecretParts, PrimaryRole>;
/// A Secret Subkey.
pub(crate) type SecretSubkey = Key<SecretParts, SubordinateRole>;

/// A key with public parts, and an unspecified role
/// (`UnspecifiedRole`).
#[allow(dead_code)]
pub(crate) type UnspecifiedPublic = Key<PublicParts, UnspecifiedRole>;
/// A key with secret parts, and an unspecified role
/// (`UnspecifiedRole`).
pub(crate) type UnspecifiedSecret = Key<SecretParts, UnspecifiedRole>;

/// A primary key with unspecified parts (`UnspecifiedParts`).
#[allow(dead_code)]
pub(crate) type UnspecifiedPrimary = Key<UnspecifiedParts, PrimaryRole>;
/// A subkey key with unspecified parts (`UnspecifiedParts`).
#[allow(dead_code)]
pub(crate) type UnspecifiedSecondary = Key<UnspecifiedParts, SubordinateRole>;

/// A key whose parts and role are unspecified
/// (`UnspecifiedParts`, `UnspecifiedRole`).
#[allow(dead_code)]
pub(crate) type UnspecifiedKey = Key<UnspecifiedParts, UnspecifiedRole>;

/// Cryptographic operations using the key material.
impl<P, R> Key<P, R>
     where P: key::KeyParts,
           R: key::KeyRole,
{
    /// Encrypts the given data with this key.
    pub fn encrypt(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use crate::crypto::ecdh::aes_key_wrap;
        use crate::crypto::backend::{Backend, interface::{Asymmetric, Kdf}};
        use crate::crypto::mpi::PublicKey;
        use PublicKeyAlgorithm::*;

        #[allow(deprecated, non_snake_case)]
        #[allow(clippy::erasing_op, clippy::identity_op)]
        match self.pk_algo() {
            X25519 =>
                if let mpi::PublicKey::X25519 { u: U } = self.mpis()
            {
                // Generate an ephemeral key pair {v, V=vG}
                let (v, V) = Backend::x25519_generate_key()?;

                // Compute the shared point S = vU;
                let S = Backend::x25519_shared_point(&v, U)?;

                // Compute the wrap key.
                let wrap_algo = SymmetricAlgorithm::AES128;
                let mut ikm: SessionKey = vec![0; 32 + 32 + 32].into();
                ikm[0 * 32..1 * 32].copy_from_slice(&V[..]);
                ikm[1 * 32..2 * 32].copy_from_slice(&U[..]);
                ikm[2 * 32..3 * 32].copy_from_slice(&S[..]);
                let mut kek = vec![0; wrap_algo.key_size()?].into();
                Backend::hkdf_sha256(&ikm, None, b"OpenPGP X25519", &mut kek)?;

                let esk = aes_key_wrap(wrap_algo, kek.as_protected(),
                                       data.as_protected())?;
                Ok(mpi::Ciphertext::X25519 {
                    e: Box::new(V),
                    key: esk.into(),
                })
            } else {
                Err(Error::MalformedPacket(format!(
                    "Key: Expected X25519 public key, got {:?}", self.mpis())).into())
            },

            X448 =>
                if let mpi::PublicKey::X448 { u: U } = self.mpis()
            {
                let (v, V) = Backend::x448_generate_key()?;

                // Compute the shared point S = vU;
                let S = Backend::x448_shared_point(&v, U)?;

                // Compute the wrap key.
                let wrap_algo = SymmetricAlgorithm::AES256;
                let mut ikm: SessionKey = vec![0; 56 + 56 + 56].into();
                ikm[0 * 56..1 * 56].copy_from_slice(&V[..]);
                ikm[1 * 56..2 * 56].copy_from_slice(&U[..]);
                ikm[2 * 56..3 * 56].copy_from_slice(&S[..]);
                let mut kek = vec![0; wrap_algo.key_size()?].into();
                Backend::hkdf_sha512(&ikm, None, b"OpenPGP X448", &mut kek)?;

                let esk = aes_key_wrap(wrap_algo, kek.as_protected(),
                                       data.as_protected())?;
                Ok(mpi::Ciphertext::X448 {
                    e: Box::new(V),
                    key: esk.into(),
                })
            } else {
                Err(Error::MalformedPacket(format!(
                    "Key: Expected X448 public key, got {:?}", self.mpis())).into())
            },

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            ECDH if matches!(self.mpis(),
                             PublicKey::ECDH { curve: Curve::Cv25519, ..}) =>
            {
                let q = match self.mpis() {
                    PublicKey::ECDH { q, .. } => q,
                    _ => unreachable!(),
                };

                // Obtain the authenticated recipient public key R
                let R = q.decode_point(&Curve::Cv25519)?.0;

                // Generate an ephemeral key pair {v, V=vG}
                // Compute the public key.
                let (v, VB) = Backend::x25519_generate_key()?;
                let VB = mpi::MPI::new_compressed_point(&VB);

                // Compute the shared point S = vR;
                let S = Backend::x25519_shared_point(&v, R.try_into()?)?;

                crate::crypto::ecdh::encrypt_wrap(
                    self.parts_as_public().role_as_subordinate(), data, VB, &S)
            },

            RSAEncryptSign | RSAEncrypt |
            ElGamalEncrypt | ElGamalEncryptSign |
            ECDH |
            Private(_) | Unknown(_) => self.encrypt_backend(data),
        }
    }

    /// Verifies the given signature.
    pub fn verify(&self, sig: &mpi::Signature, hash_algo: HashAlgorithm,
                  digest: &[u8]) -> Result<()> {
        use crate::crypto::backend::{Backend, interface::Asymmetric};
        use crate::crypto::mpi::{PublicKey, Signature};

        fn bad(e: impl ToString) -> anyhow::Error {
            Error::BadSignature(e.to_string()).into()
        }

        let ok = match (self.mpis(), sig) {
            (PublicKey::Ed25519 { a }, Signature::Ed25519 { s }) =>
                Backend::ed25519_verify(a, digest, s)?,

            (PublicKey::Ed448 { a }, Signature::Ed448 { s }) =>
                Backend::ed448_verify(a, digest, s)?,

            (PublicKey::EdDSA { curve, q }, Signature::EdDSA { r, s }) =>
              match curve {
                Curve::Ed25519 => {
                    let (public, ..) = q.decode_point(&Curve::Ed25519)?;
                    assert_eq!(public.len(), 32);

                    // OpenPGP encodes R and S separately, but our
                    // cryptographic backends expect them to be
                    // concatenated.
                    let mut signature = Vec::with_capacity(64);

                    // We need to zero-pad them at the front, because
                    // the MPI encoding drops leading zero bytes.
                    signature.extend_from_slice(
                        &r.value_padded(32).map_err(bad)?);
                    signature.extend_from_slice(
                        &s.value_padded(32).map_err(bad)?);

                    // Let's see if we got it right.
                    debug_assert_eq!(signature.len(), 64);

                    Backend::ed25519_verify(public.try_into()?,
                                            digest,
                                            &signature.as_slice().try_into()?)?
                },
                _ => return
                    Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (PublicKey::DSA { p, q, g, y }, Signature::DSA { r, s }) =>
                Backend::dsa_verify(p, q, g, y, digest, r, s)?,

            (PublicKey::RSA { .. }, Signature::RSA { .. }) |
            (PublicKey::ECDSA { .. }, Signature::ECDSA { .. }) =>
                return self.verify_backend(sig, hash_algo, digest),

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

/// Holds secret key material.
///
/// This type allows postponing the decryption of the secret key
/// material until it is actually needed.
///
/// If the secret key material is not encrypted with a password, then
/// we encrypt it in memory.  This helps protect against
/// [heartbleed]-style attacks where a buffer over-read allows an
/// attacker to read from the process's address space.  This
/// protection is less important for Rust programs, which are memory
/// safe.  However, it is essential when Sequoia is used via its FFI.
///
/// See [`crypto::mem::Encrypted`] for details.
///
/// [heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
/// [`crypto::mem::Encrypted`]: super::super::crypto::mem::Encrypted
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SecretKeyMaterial {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted(Unencrypted),
    /// The secret key is encrypted with a password.
    Encrypted(Encrypted),
}

assert_send_and_sync!(SecretKeyMaterial);

impl From<mpi::SecretKeyMaterial> for SecretKeyMaterial {
    fn from(mpis: mpi::SecretKeyMaterial) -> Self {
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
    /// Decrypts the secret key material using `password`.
    ///
    /// The `SecretKeyMaterial` type does not know what kind of key it
    /// contains.  So, in order to know how many MPIs to parse, the
    /// public key algorithm needs to be provided explicitly.
    ///
    /// This returns an error if the secret key material is not
    /// encrypted or the password is incorrect.
    pub fn decrypt<P, R>(mut self,
                         key: &Key<P, R>,
                         password: &Password)
                         -> Result<Self>
    where
        P: KeyParts,
        R: KeyRole,
    {
        self.decrypt_in_place(key, password)?;
        Ok(self)
    }

    /// Decrypts the secret key material using `password`.
    ///
    /// The `SecretKeyMaterial` type does not know what kind of key it
    /// contains.  So, in order to know how many MPIs to parse, the
    /// public key algorithm needs to be provided explicitly.
    ///
    /// This returns an error if the secret key material is not
    /// encrypted or the password is incorrect.
    pub fn decrypt_in_place<P, R>(&mut self,
                                  key: &Key<P, R>,
                                  password: &Password)
                                  -> Result<()>
    where
        P: KeyParts,
        R: KeyRole,
    {
        match self {
            SecretKeyMaterial::Encrypted(e) => {
                *self = e.decrypt(key, password)?.into();
                Ok(())
            }
            SecretKeyMaterial::Unencrypted(_) =>
                Err(Error::InvalidArgument(
                    "secret key is not encrypted".into()).into()),
        }
    }

    /// Encrypts the secret key material using `password`.
    ///
    /// This returns an error if the secret key material is encrypted.
    ///
    /// See [`Unencrypted::encrypt`] for details.
    pub fn encrypt<P, R>(mut self,
                         key: &Key<P, R>,
                         password: &Password)
                         -> Result<Self>
    where
        P: KeyParts,
        R: KeyRole,
    {
        self.encrypt_in_place(key, password)?;
        Ok(self)
    }

    /// Encrypts the secret key material using `password` with the
    /// given parameters.
    ///
    /// This returns an error if the secret key material is encrypted.
    ///
    /// See [`Unencrypted::encrypt_with`] for details.
    pub fn encrypt_with<P, R>(mut self,
                              key: &Key<P, R>,
                              s2k: S2K,
                              symm: SymmetricAlgorithm,
                              aead: Option<AEADAlgorithm>,
                              password: &Password)
                              -> Result<Self>
    where
        P: KeyParts,
        R: KeyRole,
    {
        self.encrypt_in_place_with(key, s2k, symm, aead, password)?;
        Ok(self)
    }

    /// Encrypts the secret key material using `password`.
    ///
    /// This returns an error if the secret key material is encrypted.
    ///
    /// See [`Unencrypted::encrypt`] for details.
    pub fn encrypt_in_place<P, R>(&mut self,
                                  key: &Key<P, R>,
                                  password: &Password)
                                  -> Result<()>
    where
        P: KeyParts,
        R: KeyRole,
    {
        match self {
            SecretKeyMaterial::Unencrypted(ref u) => {
                *self = SecretKeyMaterial::Encrypted(
                    u.encrypt(key, password)?);
                Ok(())
            }
            SecretKeyMaterial::Encrypted(_) =>
                Err(Error::InvalidArgument(
                    "secret key is encrypted".into()).into()),
        }
    }

    /// Encrypts the secret key material using `password` and the
    /// given parameters.
    ///
    /// This returns an error if the secret key material is encrypted.
    ///
    /// See [`Unencrypted::encrypt`] for details.
    pub fn encrypt_in_place_with<P, R>(&mut self,
                                       key: &Key<P, R>,
                                       s2k: S2K,
                                       symm: SymmetricAlgorithm,
                                       aead: Option<AEADAlgorithm>,
                                       password: &Password)
                                       -> Result<()>
    where
        P: KeyParts,
        R: KeyRole,
    {
        match self {
            SecretKeyMaterial::Unencrypted(ref u) => {
                *self = SecretKeyMaterial::Encrypted(
                    u.encrypt_with(key, s2k, symm, aead, password)?);
                Ok(())
            }
            SecretKeyMaterial::Encrypted(_) =>
                Err(Error::InvalidArgument(
                    "secret key is encrypted".into()).into()),
        }
    }

    /// Returns whether the secret key material is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretKeyMaterial::Encrypted(_) => true,
            SecretKeyMaterial::Unencrypted(_) => false,
        }
    }
}

/// Unencrypted secret key material.
///
/// This data structure is used by the [`SecretKeyMaterial`] enum.
///
/// Unlike an [`Encrypted`] key, this key can be used as-is.
///
/// The secret key is encrypted in memory and only decrypted on
/// demand.  This helps protect against [heartbleed]-style
/// attacks where a buffer over-read allows an attacker to read from
/// the process's address space.  This protection is less important
/// for Rust programs, which are memory safe.  However, it is
/// essential when Sequoia is used via its FFI.
///
/// See [`crypto::mem::Encrypted`] for details.
///
/// [heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
/// [`crypto::mem::Encrypted`]: super::super::crypto::mem::Encrypted
// Note: PartialEq, Eq, and Hash on mem::Encrypted does the right
// thing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unencrypted {
    /// MPIs of the secret key.
    mpis: mem::Encrypted,
}

assert_send_and_sync!(Unencrypted);

impl From<mpi::SecretKeyMaterial> for Unencrypted {
    fn from(mpis: mpi::SecretKeyMaterial) -> Self {
        use crate::serialize::MarshalInto;
        // We need to store the type.
        let mut plaintext = mem::Protected::new(1 + mpis.serialized_len());
        plaintext[0] =
            mpis.algo().unwrap_or(PublicKeyAlgorithm::Unknown(0)).into();

        mpis.serialize_into(&mut plaintext[1..])
            .expect("MPI serialization to vec failed");
        Unencrypted {
            mpis: mem::Encrypted::new(plaintext)
                .expect("encrypting memory failed"),
        }
    }
}

impl Unencrypted {
    /// Maps the given function over the secret.
    pub fn map<F, T>(&self, mut fun: F) -> T
        where F: FnMut(&mpi::SecretKeyMaterial) -> T
    {
        self.mpis.map(|plaintext| {
            let algo: PublicKeyAlgorithm = plaintext[0].into();
            let mpis = mpi::SecretKeyMaterial::from_bytes(algo, &plaintext[1..])
                .expect("Decrypted secret key is malformed");
            fun(&mpis)
        })
    }

    /// Encrypts the secret key material using `password`.
    ///
    /// This encrypts the secret key material using AES-128/OCB and a
    /// key derived from the `password` using the default [`S2K`]
    /// scheme.
    pub fn encrypt<P, R>(&self,
                         key: &Key<P, R>,
                         password: &Password)
                         -> Result<Encrypted>
    where
        P: KeyParts,
        R: KeyRole,
    {
        // Pick sensible parameters according to the key version.
        let (s2k, symm, aead) = match key.version() {
            6 => (
                S2K::default(),
                SymmetricAlgorithm::AES128,
                Some(AEADAlgorithm::OCB),
            ),

            _ => (
                S2K::default(),
                SymmetricAlgorithm::default(),
                None,
            ),
        };

        self.encrypt_with(key, s2k, symm, aead, password)
    }

    /// Encrypts the secret key material using `password` and the
    /// given parameters.
    pub fn encrypt_with<P, R>(&self,
                              key: &Key<P, R>,
                              s2k: S2K,
                              symm: SymmetricAlgorithm,
                              aead: Option<AEADAlgorithm>,
                              password: &Password)
                              -> Result<Encrypted>
    where
        P: KeyParts,
        R: KeyRole,
    {
        use std::io::Write;
        use crate::crypto::symmetric::Encryptor;

        let derived_key = s2k.derive_key(password, symm.key_size()?)?;
        let checksum = Default::default();

        constrain_encryption_methods(key, &s2k, symm, aead, Some(checksum))?;

        if matches!(s2k, S2K::Argon2 { .. }) && aead.is_none() {
            return Err(Error::InvalidOperation(
                "Argon2 MUST be used with an AEAD mode".into()).into());
        }

        if let Some(aead) = aead {
            use crate::serialize::MarshalInto;

            let mut iv = vec![0; aead.nonce_size()?];
            crypto::random(&mut iv)?;

            let schedule = Key253Schedule::new(
                match key.role() {
                    KeyRoleRT::Primary => Tag::SecretKey,
                    KeyRoleRT::Subordinate => Tag::SecretSubkey,
                    KeyRoleRT::Unspecified =>
                        return Err(Error::InvalidOperation(
                            "cannot encrypt key with unspecified role".into()).into()),
                },
                key.parts_as_public(), derived_key, symm, aead, &iv)?;
            let mut enc = schedule.encryptor()?;

            // Encrypt the secret key.
            let esk = self.map(|mpis| -> Result<Vec<u8>> {
                let mut esk =
                    vec![0; mpis.serialized_len() + aead.digest_size()?];
                let secret = mpis.to_vec()?;
                enc.encrypt_seal(&mut esk, &secret)?;
                Ok(esk)
            })?;

            Ok(Encrypted::new_aead(s2k, symm, aead, iv.into_boxed_slice(),
                                   esk.into_boxed_slice()))
        } else {
            use crypto::symmetric::{
                BlockCipherMode,
                PaddingMode,
            };

            // Ciphertext is preceded by a random block.
            let mut trash = vec![0u8; symm.block_size()?];
            crypto::random(&mut trash)?;

            let mut esk = Vec::new();
            let mut encryptor =
                Encryptor::new(symm, BlockCipherMode::CFB, PaddingMode::None,
                               &derived_key, None, &mut esk)?;
            encryptor.write_all(&trash)?;
            self.map(|mpis| mpis.serialize_with_checksum(&mut encryptor,
                                                         checksum))?;
            drop(encryptor);

            Ok(Encrypted::new(s2k, symm, Some(checksum),
                              esk.into_boxed_slice()))
        }
    }
}

/// Secret key material encrypted with a password.
///
/// This data structure is used by the [`SecretKeyMaterial`] enum.
///
#[derive(Clone, Debug)]
pub struct Encrypted {
    /// Key derivation mechanism to use.
    s2k: S2K,
    /// Symmetric algorithm used to encrypt the secret key material.
    algo: SymmetricAlgorithm,
    /// AEAD algorithm and IV used to encrypt the secret key material.
    aead: Option<(AEADAlgorithm, Box<[u8]>)>,
    /// Checksum method.
    checksum: Option<mpi::SecretKeyChecksum>,
    /// Encrypted MPIs prefixed with the IV.
    ///
    /// If we recognized the S2K object during parsing, we can
    /// successfully parse the data into S2K, IV, and ciphertext.
    /// However, if we do not recognize the S2K type, we do not know
    /// how large its parameters are, so we cannot cleanly parse it,
    /// and have to accept that the S2K's body bleeds into the rest of
    /// the data.
    ciphertext: std::result::Result<(usize, // IV length
                                     Box<[u8]>),    // IV + ciphertext.
                                    Box<[u8]>>, // S2K body + IV + ciphertext.
}

assert_send_and_sync!(Encrypted);

// Because the S2K and ciphertext cannot be cleanly separated at parse
// time, we need to carefully compare and hash encrypted key packets.

impl PartialEq for Encrypted {
    fn eq(&self, other: &Encrypted) -> bool {
        self.algo == other.algo
            && self.aead == other.aead
            && self.checksum == other.checksum
            && match (&self.ciphertext, &other.ciphertext) {
                (Ok(a), Ok(b)) =>
                    self.s2k == other.s2k && a == b,
                (Err(a_raw), Err(b_raw)) => {
                    // Treat S2K and ciphertext as opaque blob.
                    // XXX: This would be nicer without the allocations.
                    use crate::serialize::MarshalInto;
                    let mut a = self.s2k.to_vec().unwrap();
                    let mut b = other.s2k.to_vec().unwrap();
                    a.extend_from_slice(a_raw);
                    b.extend_from_slice(b_raw);
                    a == b
                },
                _ => false,
            }
    }
}

impl Eq for Encrypted {}

impl std::hash::Hash for Encrypted {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algo.hash(state);
        self.aead.hash(state);
        self.checksum.hash(state);
        match &self.ciphertext {
            Ok(c) => {
                self.s2k.hash(state);
                c.hash(state);
            },
            Err(c) => {
                // Treat S2K and ciphertext as opaque blob.
                // XXX: This would be nicer without the allocations.
                use crate::serialize::MarshalInto;
                let mut a = self.s2k.to_vec().unwrap();
                a.extend_from_slice(c);
                a.hash(state);
            },
        }
    }
}

impl Encrypted {
    /// Creates a new encrypted key object.
    pub fn new(s2k: S2K, algo: SymmetricAlgorithm,
               checksum: Option<mpi::SecretKeyChecksum>, ciphertext: Box<[u8]>)
        -> Self
    {
        Self::new_raw(s2k, algo, checksum, Ok((0, ciphertext)))
    }

    /// Creates a new encrypted key object.
    pub fn new_aead(s2k: S2K,
                    sym_algo: SymmetricAlgorithm,
                    aead_algo: AEADAlgorithm,
                    aead_iv: Box<[u8]>,
                    ciphertext: Box<[u8]>)
                    -> Self
    {
        Encrypted {
            s2k,
            algo: sym_algo,
            aead: Some((aead_algo, aead_iv)),
            checksum: None,
            ciphertext: Ok((0, ciphertext)),
        }
    }

    /// Creates a new encrypted key object.
    pub(crate) fn new_raw(s2k: S2K, algo: SymmetricAlgorithm,
                          checksum: Option<mpi::SecretKeyChecksum>,
                          ciphertext: std::result::Result<(usize, Box<[u8]>),
                                                          Box<[u8]>>)
        -> Self
    {
        Encrypted { s2k, algo, aead: None, checksum, ciphertext }
    }

    /// Returns the key derivation mechanism.
    pub fn s2k(&self) -> &S2K {
        &self.s2k
    }

    /// Returns the symmetric algorithm used to encrypt the secret
    /// key material.
    pub fn algo(&self) -> SymmetricAlgorithm {
        self.algo
    }

    /// Returns the AEAD algorithm used to encrypt the secret key
    /// material.
    pub fn aead_algo(&self) -> Option<AEADAlgorithm> {
        self.aead.as_ref().map(|(a, _iv)| *a)
    }

    /// Returns the AEAD IV used to encrypt the secret key material.
    pub fn aead_iv(&self) -> Option<&[u8]> {
        self.aead.as_ref().map(|(_a, iv)| &iv[..])
    }

    /// Returns the checksum method used to protect the encrypted
    /// secret key material, if any.
    pub fn checksum(&self) -> Option<mpi::SecretKeyChecksum> {
        self.checksum
    }

    /// Returns the encrypted secret key material.
    ///
    /// If the [`S2K`] mechanism is not supported by Sequoia, this
    /// function will fail.  Note that the information is not lost,
    /// but stored in the packet.  If the packet is serialized again,
    /// it is written out.
    ///
    ///   [`S2K`]: super::super::crypto::S2K
    pub fn ciphertext(&self) -> Result<&[u8]> {
        self.ciphertext
            .as_ref()
            .map(|(_cfb_iv_len, ciphertext)| &ciphertext[..])
            .map_err(|_| Error::MalformedPacket(
                format!("Unknown S2K: {:?}", self.s2k)).into())
    }

    /// Returns the encrypted secret key material, possibly including
    /// the body of the S2K object.
    pub(crate) fn raw_ciphertext(&self) -> &[u8] {
        match self.ciphertext.as_ref() {
            Ok((_cfb_iv_len, ciphertext)) => &ciphertext[..],
            Err(s2k_ciphertext) => &s2k_ciphertext[..],
        }
    }

    /// Returns the length of the CFB IV, if used.
    ///
    /// In v6 key packets, we explicitly model the length of the IV,
    /// but in Sequoia we store the IV and the ciphertext as one
    /// block, due to how bad this was modeled in v4 key packets.
    /// However, now that our in-core representation is less precise
    /// to support v4, we need to track this length to uphold our
    /// equality guarantee.
    pub(crate) fn cfb_iv_len(&self) -> usize {
        self.ciphertext.as_ref().ok()
            .map(|(cfb_iv_len, _)| *cfb_iv_len)
            .unwrap_or(0)
    }

    /// Decrypts the secret key material using `password`.
    ///
    /// The `Encrypted` key does not know what kind of key it is, so
    /// the public key algorithm is needed to parse the correct number
    /// of MPIs.
    pub fn decrypt<P, R>(&self, key: &Key<P, R>, password: &Password)
                         -> Result<Unencrypted>
    where
        P: KeyParts,
        R: KeyRole,
    {
        use std::io::Read;
        use crate::crypto;

        constrain_encryption_methods(
            key, &self.s2k, self.algo,self.aead.as_ref().map(|(a, _)| *a),
            self.checksum)?;

        let derived_key = self.s2k.derive_key(password, self.algo.key_size()?)?;
        let ciphertext = self.ciphertext()?;

        if let Some((aead, iv)) = &self.aead {
            let schedule = Key253Schedule::new(
                match key.role() {
                    KeyRoleRT::Primary => Tag::SecretKey,
                    KeyRoleRT::Subordinate => Tag::SecretSubkey,
                    KeyRoleRT::Unspecified =>
                        return Err(Error::InvalidOperation(
                            "cannot decrypt key with unspecified role".into()).into()),
                },
                key.parts_as_public(), derived_key, self.algo, *aead, iv)?;
            let mut dec = schedule.decryptor()?;

            // Read the secret key.
            let mut secret = mem::Protected::new(
                ciphertext.len().saturating_sub(aead.digest_size()?));
            dec.decrypt_verify(&mut secret, ciphertext)?;

            mpi::SecretKeyMaterial::from_bytes(
                key.pk_algo(), &secret).map(|m| m.into())
        } else {
            use crypto::symmetric::{
                BlockCipherMode,
                UnpaddingMode,
            };

            let cur = buffered_reader::Memory::with_cookie(
                ciphertext, Default::default());
            let mut dec =
                crypto::symmetric::InternalDecryptor::new(
                    self.algo,
                    BlockCipherMode::CFB,
                    UnpaddingMode::None,
                    &derived_key,
                    None,
                    cur)?;

            // Consume the first block.
            let block_size = self.algo.block_size()?;
            let mut trash = mem::Protected::new(block_size);
            dec.read_exact(&mut trash)?;

            // Read the secret key.
            let mut secret = mem::Protected::new(ciphertext.len() - block_size);
            dec.read_exact(&mut secret)?;

            mpi::SecretKeyMaterial::from_bytes_with_checksum(
                key.pk_algo(), &secret, self.checksum.unwrap_or_default())
                .map(|m| m.into())
        }
    }
}

/// Constrains the secret key material encryption methods according to
/// [Section 3.7.2.1. of RFC 9580].
///
/// [Section 3.7.2.1. of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.2.1
fn constrain_encryption_methods<P, R>(key: &Key<P, R>,
                                      s2k: &S2K,
                                      _symm: SymmetricAlgorithm,
                                      aead: Option<AEADAlgorithm>,
                                      checksum: Option<mpi::SecretKeyChecksum>)
                                      -> Result<()>
where
    P: KeyParts,
    R: KeyRole,
{
    #[allow(deprecated)]
    match s2k {
        S2K::Argon2 { .. } if aead.is_none() =>
            Err(Error::InvalidOperation(
                "Argon2 MUST be used with an AEAD mode".into()).into()),

        S2K::Implicit if key.version() == 6 =>
            Err(Error::InvalidOperation(
                "Implicit S2K MUST NOT be used with v6 keys".into()).into()),

        // Technically not forbidden, but this is a terrible idea and
        // I doubt that anyone depends on it.  Let's see whether we
        // can get away with being strict here.
        S2K::Simple { .. } if key.version() == 6 =>
            Err(Error::InvalidOperation(
                "Simple S2K SHOULD NOT be used with v6 keys".into()).into()),

        _ if key.version() == 6 && aead.is_none()
            && checksum != Some(mpi::SecretKeyChecksum::SHA1) =>
            Err(Error::InvalidOperation(
                "Malleable CFB MUST NOT be used with v6 keys".into()).into()),

        _ => Ok(()),
    }
}

pub(crate) struct Key253Schedule<'a> {
    symm: SymmetricAlgorithm,
    aead: AEADAlgorithm,
    nonce: &'a [u8],
    kek: SessionKey,
    ad: Vec<u8>
}

impl<'a> Key253Schedule<'a> {
    fn new<R>(tag: Tag,
              key: &Key<PublicParts, R>,
              derived_key: SessionKey,
              symm: SymmetricAlgorithm,
              aead: AEADAlgorithm,
              nonce: &'a [u8])
              -> Result<Self>
    where
        R: KeyRole,
    {
        use crate::serialize::{Marshal, MarshalInto};
        use crate::crypto::backend::{Backend, interface::Kdf};

        let info = [
            0b1100_0000 | u8::from(tag), // Canonicalized packet type.
            key.version(),
            symm.into(),
            aead.into(),
        ];
        let mut kek = vec![0; symm.key_size()?].into();
        Backend::hkdf_sha256(&derived_key, None, &info, &mut kek)?;

        let mut ad = Vec::with_capacity(key.serialized_len());
        ad.push(0b1100_0000 | u8::from(tag)); // Canonicalized packet type.
        key.serialize(&mut ad)?;

        Ok(Self {
            symm,
            aead,
            nonce,
            kek,
            ad,
        })
    }

    fn decryptor(&self) -> Result<crypto::aead::DecryptionContext> {
        self.aead.context(self.symm, &self.kek, &self.ad, self.nonce)?
            .for_decryption()
    }

    fn encryptor(&self) -> Result<crypto::aead::EncryptionContext> {
        self.aead.context(self.symm, &self.kek, &self.ad, self.nonce)?
            .for_encryption()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::Key;
    use crate::Cert;
    use crate::packet::key::SecretKeyMaterial;
    use crate::packet::Packet;
    use super::*;
    use crate::parse::Parse;
    use crate::SignatureType;
    use crate::crypto::mpi::PublicKey;

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
    fn signature_roundtrip() {
        let gen_v4_rsa = |bits: usize| -> Key<key::SecretParts, key::PrimaryRole> {
            Key4::generate_rsa(bits)
                .expect("Can generate a v4 RSA key")
                .into()
        };
        let gen_v6_rsa = |bits: usize| -> Key<_, _> {
            Key6::generate_rsa(bits)
                .expect("Can generate a v6 RSA key")
                .into()
        };
        // Disabled: see below.
        //let gen_v4_dsa = |bits: usize| -> Key<_, _> {
        //    Key4::generate_dsa(bits)
        //        .expect("Can generate a v4 DSA key")
        //        .into()
        //};
        let gen_v4_curve = |curve: Curve| -> Key<_, _> {
            Key4::generate_ecc(true, curve.clone())
                .expect(&format!("Can generate a v4 {:?}", curve))
                .into()
        };
        let gen_v6_curve = |curve: Curve| -> Key<_, _> {
            Key6::generate_ecc(true, curve.clone())
                .expect(&format!("Can generate a v6 {:?}", curve))
                .into()
        };
        let gen_v4_ed25519 = || -> Key<_, _> {
            Key4::generate_ed25519()
                .expect("Can generate a v4 Ed25519 key")
                .into()
        };
        let gen_v6_ed25519 = || -> Key<_, _> {
            Key6::generate_ed25519()
                .expect("Can generate a v6 Ed25519 key")
                .into()
        };
        let gen_v4_ed448 = || -> Key<_, _> {
            Key4::generate_ed448()
                .expect("Can generate a v4 Ed448 key")
                .into()
        };
        let gen_v6_ed448 = || -> Key<_, _> {
            Key6::generate_ed448()
                .expect("Can generate a v6 Ed448 key")
                .into()
        };

        #[allow(deprecated)]
        for (algo, curve, profile, gen) in [
            // RSA
            (PublicKeyAlgorithm::RSAEncryptSign, None, 4,
             Box::new(|| gen_v4_rsa(2048)) as Box<dyn Fn () -> _>),
            (PublicKeyAlgorithm::RSAEncryptSign, None, 4,
             Box::new(|| gen_v4_rsa(3072)) as Box<dyn Fn () -> _>),
            (PublicKeyAlgorithm::RSAEncryptSign, None, 4,
             Box::new(|| gen_v4_rsa(4096)) as Box<dyn Fn () -> _>),
            (PublicKeyAlgorithm::RSAEncryptSign, None, 6,
             Box::new(|| gen_v6_rsa(2048))),
            (PublicKeyAlgorithm::RSAEncryptSign, None, 6,
             Box::new(|| gen_v6_rsa(3072))),
            (PublicKeyAlgorithm::RSAEncryptSign, None, 6,
             Box::new(|| gen_v6_rsa(4096))),

            // DSA
            //
            // DSA is deprecated.
            //
            // Disabled, because DSA generation doesn't work on
            // Windows, but PublicKeyAlgorithm::DSA.is_supported()
            // returns true.  This is because CNG does support signing
            // and verification.
            //(PublicKeyAlgorithm::DSA, None, 4,
            // Box::new(|| gen_v4_dsa(2048)) as Box<dyn Fn () -> _>),
            //(PublicKeyAlgorithm::DSA, None, 4,
            // Box::new(|| gen_v4_dsa(3072)) as Box<dyn Fn () -> _>),

            // EdDSA 25519.
            //
            // Note: EdDSA Ed25519 is deprecated for v6.
            (PublicKeyAlgorithm::EdDSA, Some(Curve::Ed25519), 4,
             Box::new(|| gen_v4_curve(Curve::Ed25519))),

            // Modern Ed25519.
            (PublicKeyAlgorithm::Ed25519, None, 4,
             Box::new(gen_v4_ed25519)),
            (PublicKeyAlgorithm::Ed25519, None, 6,
             Box::new(gen_v6_ed25519)),

            // Ed448.
            (PublicKeyAlgorithm::Ed448, None, 4,
             Box::new(gen_v4_ed448)),
            (PublicKeyAlgorithm::Ed448, None, 6,
             Box::new(gen_v6_ed448)),

            // Nist.
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP256), 4,
             Box::new(|| gen_v4_curve(Curve::NistP256))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP256), 6,
             Box::new(|| gen_v6_curve(Curve::NistP256))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP384), 4,
             Box::new(|| gen_v4_curve(Curve::NistP384))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP384), 6,
             Box::new(|| gen_v6_curve(Curve::NistP384))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP521), 4,
             Box::new(|| gen_v4_curve(Curve::NistP521))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::NistP521), 6,
             Box::new(|| gen_v6_curve(Curve::NistP521))),

            // Brainpool.
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP256), 4,
             Box::new(|| gen_v4_curve(Curve::BrainpoolP256))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP256), 6,
             Box::new(|| gen_v6_curve(Curve::BrainpoolP256))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP384), 4,
             Box::new(|| gen_v4_curve(Curve::BrainpoolP384))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP384), 6,
             Box::new(|| gen_v6_curve(Curve::BrainpoolP384))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP512), 4,
             Box::new(|| gen_v4_curve(Curve::BrainpoolP512))),
            (PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP512), 6,
             Box::new(|| gen_v6_curve(Curve::BrainpoolP512))),
        ]
        {
            eprintln!("Checking algo: {}, curve: {:?}, profile: {}.",
                      algo, curve, profile);
            if ! algo.is_supported() {
                eprintln!("Algorithm {} not supported, skipping test.",
                          algo);
                continue;
            }

            if let Some(curve) = curve.as_ref() {
                if ! curve.is_supported() {
                    eprintln!("Curve {:?} not supported, skipping test.",
                              curve);
                    continue;
                }
            }

            let key = gen();

            // Make sure we got the right type of key.
            assert_eq!(algo, key.pk_algo(),
                       "\n\
                        algo expected: {:?} ({})\n\
                        algo got:      {:?} ({})",
                       algo, u8::from(algo),
                       key.pk_algo(), u8::from(key.pk_algo()));

            let got_curve = match key.mpis() {
                PublicKey::EdDSA { curve, .. }
                | PublicKey::ECDSA { curve, .. }
                | PublicKey::ECDH { curve, .. } =>
                {
                    Some(curve.clone())
                }
                _ => None,
            };
            assert_eq!(curve, got_curve,
                       "\n\
                        curve expected: {:?}\n\
                        curve got:      {:?}",
                       curve, got_curve);

            assert_eq!(profile, key.version(),
                       "\n\
                        profile expected: {:?}\n\
                        profile got:      {:?}",
                       profile, key.version());

            let mut pair = key.clone().into_keypair().unwrap();
            let hash = HashAlgorithm::default();

            // Sign.
            let ctx = hash.context().unwrap().for_signature(profile);
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .sign_hash(&mut pair, ctx).unwrap();

            // Verify.
            let ctx = hash.context().unwrap().for_signature(profile);
            sig.verify_hash(&key, ctx).unwrap();
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

        let check = |key: Key<SecretParts, R>| -> Result<()> {
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
            check(key.into())?;

            let key: Key6<_, R>
                = Key6::generate_ecc(true, curve.clone())?;
            check(key.into())?;
        }

        for bits in vec![2048, 3072] {
            if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
                eprintln!("Skipping unsupported RSA");
                continue;
            }

            let key: Key4<_, R>
                = Key4::generate_rsa(bits)?;
            check(key.into())?;

            let key: Key6<_, R>
                = Key6::generate_rsa(bits)?;
            check(key.into())?;
        }

        Ok(())
    }

    quickcheck! {
        fn roundtrip_public(p: Key<PublicParts, UnspecifiedRole>) -> bool {
            use crate::parse::Parse;
            use crate::serialize::MarshalInto;
            let buf = p.to_vec().expect("Failed to serialize key");
            let q = Key::from_bytes(&buf).expect("Failed to parse key").into();
            assert_eq!(p, q);
            true
        }
    }

    quickcheck! {
        fn roundtrip_secret(p: Key<SecretParts, PrimaryRole>) -> bool {
            use crate::parse::Parse;
            use crate::serialize::MarshalInto;
            let buf = p.to_vec().expect("Failed to serialize key");
            let q = Key::from_bytes(&buf).expect("Failed to parse key")
                .parts_into_secret().expect("No secret material")
                .role_into_primary();
            assert_eq!(p, q);
            true
        }
    }

    fn mutate_eq_discriminates_key<P, R>(key: Key<P, R>, i: usize) -> bool
        where P: KeyParts,
              R: KeyRole,
              Key<P, R>: Into<Packet>,
    {
        use crate::serialize::MarshalInto;
        let p: Packet = key.into();
        let mut buf = p.to_vec().unwrap();
        // Avoid first two bytes so that we don't change the
        // type and reduce the chance of changing the length.
        if buf.len() < 3 { return true; }
        let bit = i % ((buf.len() - 2) * 8) + 16;
        buf[bit / 8] ^= 1 << (bit % 8);
        let ok = match Packet::from_bytes(&buf) {
            Ok(q) => p != q,
            Err(_) => true, // Packet failed to parse.
        };
        if ! ok {
            eprintln!("mutate_eq_discriminates_key for ({:?}, {})", p, i);
        }
        ok
    }

    // Given a packet and a position, induces a bit flip in the
    // serialized form, then checks that PartialEq detects that.
    // Recall that for packets, PartialEq is defined using the
    // serialized form.
    quickcheck! {
        fn mutate_eq_discriminates_pp(key: Key<PublicParts, PrimaryRole>,
                                      i: usize) -> bool {
            mutate_eq_discriminates_key(key, i)
        }
    }
    quickcheck! {
        fn mutate_eq_discriminates_ps(key: Key<PublicParts, SubordinateRole>,
                                      i: usize) -> bool {
            mutate_eq_discriminates_key(key, i)
        }
    }
    quickcheck! {
        fn mutate_eq_discriminates_sp(key: Key<SecretParts, PrimaryRole>,
                                      i: usize) -> bool {
            mutate_eq_discriminates_key(key, i)
        }
    }
    quickcheck! {
        fn mutate_eq_discriminates_ss(key: Key<SecretParts, SubordinateRole>,
                                      i: usize) -> bool {
            mutate_eq_discriminates_key(key, i)
        }
    }
}
