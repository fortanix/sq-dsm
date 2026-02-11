//! Keys, their associated signatures, and some useful methods.
//!
//! A [`KeyAmalgamation`] is similar to a [`ComponentAmalgamation`],
//! but a `KeyAmalgamation` includes some additional functionality
//! that is needed to correctly implement a [`Key`] component's
//! semantics.  In particular, unlike other components where the
//! binding signature stores the component's meta-data, a Primary Key
//! doesn't have a binding signature (it is the thing that other
//! components are bound to!), and, as a consequence, the associated
//! meta-data is stored elsewhere.
//!
//! Unfortunately, a primary Key's meta-data is usually not stored on
//! a direct key signature, which would be convenient as it is located
//! at the same place as a binding signature would be, but on the
//! primary User ID's binding signature.  This requires some
//! acrobatics on the implementation side to realize the correct
//! semantics.  In particular, a `Key` needs to memorize its role
//! (i.e., whether it is a primary key or a subkey) in order to know
//! whether to consider its own self signatures or the primary User
//! ID's self signatures when looking for its meta-data.
//!
//! Ideally, a `KeyAmalgamation`'s role would be encoded in its type.
//! This increases safety, and reduces the run-time overhead.
//! However, we want [`Cert::keys`] to return an iterator over all
//! keys; we don't want the user to have to specially handle the
//! primary key when that fact is not relevant.  This means that
//! `Cert::keys` has to erase the returned `Key`s' roles: all items in
//! an iterator must have the same type.  To support this, we have to
//! keep track of a `KeyAmalgamation`'s role at run-time.
//!
//! But, just because we need to erase a `KeyAmalgamation`'s role to
//! implement `Cert::keys` doesn't mean that we have to always erase
//! it.  To achieve this, we use three data types:
//! [`PrimaryKeyAmalgamation`], [`SubordinateKeyAmalgamation`], and
//! [`ErasedKeyAmalgamation`].  The first two encode the role
//! information in their type, and the last one stores it at run time.
//! We provide conversion functions to convert the static type
//! information into dynamic type information, and vice versa.
//!
//! Note: `KeyBundle`s and `KeyAmalgamation`s have a notable
//! difference: whereas a `KeyBundle`'s role is a marker, a
//! `KeyAmalgamation`'s role determines its semantics.  A consequence
//! of this is that it is not possible to convert a
//! `PrimaryKeyAmalgamation` into a `SubordinateAmalgamation`s, or
//! vice versa even though we support changing a `KeyBundle`'s role:
//!
//! ```
//! # fn main() -> sequoia_openpgp::Result<()> {
//! # use std::convert::TryInto;
//! # use sequoia_openpgp as openpgp;
//! # use openpgp::cert::prelude::*;
//! # use openpgp::packet::prelude::*;
//! # let (cert, _) = CertBuilder::new()
//! #     .add_userid("Alice")
//! #     .add_signing_subkey()
//! #     .add_transport_encryption_subkey()
//! #     .generate()?;
//! // This works:
//! cert.primary_key().bundle().role_as_subordinate();
//!
//! // But this doesn't:
//! let ka: ErasedKeyAmalgamation<_> = cert.keys().nth(0).expect("primary key");
//! let ka: openpgp::Result<SubordinateKeyAmalgamation<key::PublicParts>> = ka.try_into();
//! assert!(ka.is_err());
//! # Ok(()) }
//! ```
//!
//! The use of the prefix `Erased` instead of `Unspecified`
//! (cf. [`KeyRole::UnspecifiedRole`]) emphasizes this.
//!
//! # Selecting Keys
//!
//! It is essential to choose the right keys, and to make sure that
//! they are appropriate.  Below, we present some guidelines for the most
//! common situations.
//!
//! ## Encrypting and Signing Messages
//!
//! As a general rule of thumb, when encrypting or signing a message,
//! you want to use keys that are alive, not revoked, and have the
//! appropriate capabilities right now.  For example, the following
//! code shows how to find a key, which is appropriate for signing a
//! message:
//!
//! ```rust
//! # use sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use openpgp::types::RevocationStatus;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() -> Result<()> {
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! #     let mut i = 0;
//! let p = &StandardPolicy::new();
//!
//! let cert = cert.with_policy(p, None)?;
//!
//! if let RevocationStatus::Revoked(_) = cert.revocation_status() {
//!     // The certificate is revoked, don't use any keys from it.
//! #   unreachable!();
//! } else if let Err(_) = cert.alive() {
//!     // The certificate is not alive, don't use any keys from it.
//! #   unreachable!();
//! } else {
//!     for ka in cert.keys() {
//!         if let RevocationStatus::Revoked(_) = ka.revocation_status() {
//!             // The key is revoked.
//! #           unreachable!();
//!         } else if let Err(_) = ka.alive() {
//!             // The key is not alive.
//! #           unreachable!();
//!         } else if ! ka.for_signing() {
//!             // The key is not signing capable.
//!         } else {
//!             // Use it!
//! #           i += 1;
//!         }
//!     }
//! }
//! # assert_eq!(i, 1);
//! #     Ok(())
//! # }
//! ```
//!
//! ## Verifying a Message
//!
//! When verifying a message, you only want to use keys that were
//! alive, not revoked, and signing capable *when the message was
//! signed*.  These are the keys that the signer would have used, and
//! they reflect the signer's policy when they made the signature.
//! (See the [`Policy` discussion] for an explanation.)
//!
//! For version 4 Signature packets, the `Signature Creation Time`
//! subpacket indicates when the signature was allegedly created.  For
//! the purpose of finding the key to verify the signature, this time
//! stamp should be trusted: if the key is authenticated and the
//! signature is valid, then the time stamp is valid; if the signature
//! is not valid, then forging the time stamp won't help an attacker.
//!
//! ```rust
//! # use sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use openpgp::types::RevocationStatus;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() -> Result<()> {
//! let p = &StandardPolicy::new();
//!
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! #     let timestamp = None;
//! #     let issuer = cert.with_policy(p, None)?.keys()
//! #         .for_signing().nth(0).unwrap().key().fingerprint();
//! #     let mut i = 0;
//! let cert = cert.with_policy(p, timestamp)?;
//! if let RevocationStatus::Revoked(_) = cert.revocation_status() {
//!     // The certificate is revoked, don't use any keys from it.
//! #   unreachable!();
//! } else if let Err(_) = cert.alive() {
//!     // The certificate is not alive, don't use any keys from it.
//! #   unreachable!();
//! } else {
//!     for ka in cert.keys().key_handle(issuer) {
//!         if let RevocationStatus::Revoked(_) = ka.revocation_status() {
//!             // The key is revoked, don't use it!
//! #           unreachable!();
//!         } else if let Err(_) = ka.alive() {
//!             // The key was not alive when the signature was made!
//!             // Something fishy is going on.
//! #           unreachable!();
//!         } else if ! ka.for_signing() {
//!             // The key was not signing capable!  Better be safe
//!             // than sorry.
//! #           unreachable!();
//!         } else {
//!             // Try verifying the message with this key.
//! #           i += 1;
//!         }
//!     }
//! }
//! #     assert_eq!(i, 1);
//! #     Ok(())
//! # }
//! ```
//!
//! ## Decrypting a Message
//!
//! When decrypting a message, it seems like one ought to only use keys
//! that were alive, not revoked, and encryption-capable when the
//! message was encrypted.  Unfortunately, we don't know when a
//! message was encrypted.  But anyway, due to the slow propagation of
//! revocation certificates, we can't assume that senders won't
//! mistakenly use a revoked key.
//!
//! However, wanting to decrypt a message encrypted using an expired
//! or revoked key is reasonable.  If someone is trying to decrypt a
//! message using an expired key, then they are the certificate
//! holder, and probably attempting to access archived data using a
//! key that they themselves revoked!  We don't want to prevent that.
//!
//! We do, however, want to check whether a key is really encryption
//! capable.  [This discussion] explains why using a signing key to
//! decrypt a message can be dangerous.  Since we need a binding
//! signature to determine this, but we don't have the time that the
//! message was encrypted, we need a workaround.  One approach would
//! be to check whether the key is encryption capable now.  Since a
//! key's key flags don't typically change, this will correctly filter
//! out keys that are not encryption capable.  But, it will skip keys
//! whose self signature has expired.  But that is not a problem
//! either: no one sets self signatures to expire; if anything, they
//! set keys to expire.  Thus, this will not result in incorrectly
//! failing to decrypt messages in practice, and is a reasonable
//! approach.
//!
//! ```rust
//! # use sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() -> Result<()> {
//! let p = &StandardPolicy::new();
//!
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(Some("alice@example.org"))
//! #         .generate()?;
//! let decryption_keys = cert.keys().with_policy(p, None)
//!     .for_storage_encryption().for_transport_encryption()
//!     .collect::<Vec<_>>();
//! #     Ok(())
//! # }
//! ```
//!
//! [`ComponentAmalgamation`]: super::ComponentAmalgamation
//! [`Key`]: crate::packet::key
//! [`Cert::keys`]: super::super::Cert::keys()
//! [`PrimaryKeyAmalgamation`]: super::PrimaryKeyAmalgamation
//! [`SubordinateKeyAmalgamation`]: super::SubordinateKeyAmalgamation
//! [`ErasedKeyAmalgamation`]: super::ErasedKeyAmalgamation
//! [`KeyRole::UnspecifiedRole`]: crate::packet::key::KeyRole
//! [`Policy` discussion]: super
//! [This discussion]: https://crypto.stackexchange.com/a/12138
use std::time;
use std::time::SystemTime;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::Context;

use crate::{
    Cert,
    cert::bundle::KeyBundle,
    cert::amalgamation::{
        ComponentAmalgamation,
        key::signature::subpacket::SubpacketValue,
        ValidAmalgamation,
        ValidBindingSignature,
        ValidateAmalgamation,
    },
    cert::ValidCert,
    crypto::Signer,
    Error,
    packet::Key,
    packet::key,
    packet::Signature,
    packet::signature,
    packet::signature::subpacket::SubpacketTag,
    policy::Policy,
    Result,
    seal,
    types::{
        KeyFlags,
        RevocationKey,
        RevocationStatus,
        SignatureType,
    },
};

mod iter;
pub use iter::{
    KeyAmalgamationIter,
    ValidKeyAmalgamationIter,
};

/// Whether the key is a primary key.
///
/// This trait is an implementation detail.  It exists so that we can
/// have a blanket implementation of [`ValidAmalgamation`] for
/// [`ValidKeyAmalgamation`], for instance, even though we only have
/// specialized implementations of `PrimaryKey`.
///
/// [`ValidAmalgamation`]: super::ValidAmalgamation
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait PrimaryKey<'a, P, R>: seal::Sealed
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    /// Returns whether the key amalgamation is a primary key
    /// amalgamation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let fpr = cert.fingerprint();
    /// // This works if the type is concrete:
    /// let ka: PrimaryKeyAmalgamation<_> = cert.primary_key();
    /// assert!(ka.primary());
    ///
    /// // Or if it has been erased:
    /// for (i, ka) in cert.keys().enumerate() {
    ///     let ka: ErasedKeyAmalgamation<_> = ka;
    ///     if i == 0 {
    ///         // The primary key is always the first key returned by
    ///         // `Cert::keys`.
    ///         assert!(ka.primary());
    ///     } else {
    ///         // The rest are subkeys.
    ///         assert!(! ka.primary());
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    fn primary(&self) -> bool;
}

/// A key, and its associated data, and useful methods.
///
/// A `KeyAmalgamation` is like a [`ComponentAmalgamation`], but
/// specialized for keys.  Due to the requirement to keep track of the
/// key's role when it is erased ([see the module's documentation] for
/// more details), this is a different data structure rather than a
/// specialized type alias.
///
/// Generally, you won't use this type directly, but instead use
/// [`PrimaryKeyAmalgamation`], [`SubordinateKeyAmalgamation`], or
/// [`ErasedKeyAmalgamation`].
///
/// A `KeyAmalgamation` is returned by [`Cert::primary_key`], and
/// [`Cert::keys`].
///
/// `KeyAmalgamation` implements [`ValidateAmalgamation`], which
/// allows you to turn a `KeyAmalgamation` into a
/// [`ValidKeyAmalgamation`] using [`KeyAmalgamation::with_policy`].
///
/// # Examples
///
/// Iterating over all keys:
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// for ka in cert.keys() {
///     let ka: ErasedKeyAmalgamation<_> = ka;
/// }
/// #     Ok(())
/// # }
/// ```
///
/// Getting the primary key:
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// let ka: PrimaryKeyAmalgamation<_> = cert.primary_key();
/// #     Ok(())
/// # }
/// ```
///
/// Iterating over just the subkeys:
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// // We can skip the primary key (it's always first):
/// for ka in cert.keys().skip(1) {
///     let ka: ErasedKeyAmalgamation<_> = ka;
/// }
///
/// // Or use `subkeys`, which returns a more accurate type:
/// for ka in cert.keys().subkeys() {
///     let ka: SubordinateKeyAmalgamation<_> = ka;
/// }
/// #     Ok(())
/// # }
/// ```
///
/// [`ComponentAmalgamation`]: super::ComponentAmalgamation
/// [see the module's documentation]: self
/// [`Cert::primary_key`]: crate::cert::Cert::primary_key()
/// [`Cert::keys`]: crate::cert::Cert::keys()
/// [`ValidateAmalgamation`]: super::ValidateAmalgamation
/// [`KeyAmalgamation::with_policy`]: super::ValidateAmalgamation::with_policy()
#[derive(Debug, PartialEq)]
pub struct KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    ca: ComponentAmalgamation<'a, Key<P, R>>,
    primary: R2,
}
assert_send_and_sync!(KeyAmalgamation<'_, P, R, R2>
    where P: key::KeyParts,
          R: key::KeyRole,
          R2,
);

impl<'a, P, R> ComponentAmalgamation<'a, Key<P, R>>
where
    P: key::KeyParts,
    R: key::KeyRole,
{
    /// Returns a reference to the key.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentAmalgamation::component`].
    ///
    /// [`ComponentAmalgamation::component`]: ComponentAmalgamation::component()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about the keys.
    /// for ka in cert.keys() {
    ///     eprintln!(" - {:?}", ka.key());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn key(&self) -> &Key<P, R> {
        self.component()
    }

    pub(crate) fn set_role(&mut self, _: key::KeyRoleRT) {
        // The amalgamation only has an immutable reference, we cannot
        // change the role.
    }

    /// Forwarder for the conversion macros.
    pub(crate) fn has_secret(&self) -> bool {
        self.key().has_secret()
    }
}

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, P, R, R2> Clone for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    fn clone(&self) -> Self {
        Self {
            ca: self.ca.clone(),
            primary: self.primary,
        }
    }
}


/// A primary key amalgamation.
///
/// A specialized version of [`KeyAmalgamation`].
///
pub type PrimaryKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A subordinate key amalgamation.
///
/// A specialized version of [`KeyAmalgamation`].
///
pub type SubordinateKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::SubordinateRole, ()>;


impl<'a, P> SubordinateKeyAmalgamation<'a, P>
where
    P: key::KeyParts,
{
    /// Returns the subkey's revocation status at time `t`.
    ///
    /// A subkey is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    ///   - There is a hard revocation (even if it is not live at
    ///     time `t`, and even if there is a newer self-signature).
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this subkey is revoked; it
    /// does not imply anything about the Cert or other components.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display the subkeys' revocation status.
    /// for ka in cert.keys().subkeys() {
    ///     eprintln!(" Revocation status of {}: {:?}",
    ///               ka.key().fingerprint(), ka.revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
                                -> RevocationStatus
    where
        T: Into<Option<time::SystemTime>>,
    {
        let t = t.into();
        self.bundle().revocation_status(policy, t)
    }
}

/// An amalgamation whose role is not known at compile time.
///
/// A specialized version of [`KeyAmalgamation`].
///
/// Unlike a [`Key`] or a [`KeyBundle`] with an unspecified role, an
/// `ErasedKeyAmalgamation` remembers its role; it is just not exposed
/// to the type system.  For details, see the [module-level
/// documentation].
///
/// [`Key`]: crate::packet::key
/// [`KeyBundle`]: super::super::bundle
/// [module-level documentation]: self
pub type ErasedKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;

impl<'a, P> seal::Sealed
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{}
impl<'a, P> ValidateAmalgamation<'a, Key<P, key::PrimaryRole>>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidPrimaryKeyAmalgamation<'a, P>;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.clone().into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> seal::Sealed
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{}
impl<'a, P> ValidateAmalgamation<'a, Key<P, key::SubordinateRole>>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidSubordinateKeyAmalgamation<'a, P>;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.clone().into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> seal::Sealed
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{}
impl<'a, P> ValidateAmalgamation<'a, Key<P, key::UnspecifiedRole>>
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidErasedKeyAmalgamation<'a, P>;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(crate::now);

        // We need to make sure the certificate is okay.  This means
        // checking the primary key.  But, be careful: we don't need
        // to double-check.
        if ! self.primary() {
            let pka = PrimaryKeyAmalgamation::new(self.cert());
            pka.with_policy(policy, time).context("primary key")?;
        }

        let binding_signature = self.binding_signature(policy, time)?;
        let cert = self.ca.cert();
        let vka = ValidErasedKeyAmalgamation {
            ka: KeyAmalgamation {
                ca: self.ca.clone().parts_into_public(),
                primary: self.primary,
            },
            // We need some black magic to avoid infinite
            // recursion: a ValidCert must be valid for the
            // specified policy and reference time.  A ValidCert
            // is considered valid if the primary key is valid.
            // ValidCert::with_policy checks that by calling this
            // function.  So, if we call ValidCert::with_policy
            // here we'll recurse infinitely.
            //
            // But, hope is not lost!  We know that if we get
            // here, we've already checked that the primary key is
            // valid (see above), or that we're in the process of
            // evaluating the primary key's validity and we just
            // need to check the user's policy.  So, it is safe to
            // create a ValidCert from scratch.
            cert: ValidCert {
                cert,
                policy,
                time,
            },
            binding_signature
        };
        policy.key(&vka)?;
        Ok(ValidErasedKeyAmalgamation {
            ka: KeyAmalgamation {
                ca: P::convert_key_amalgamation(
                    vka.ka.ca.parts_into_unspecified()).expect("roundtrip"),
                primary: vka.ka.primary,
            },
            cert: vka.cert,
            binding_signature,
        })
    }
}

impl<'a, P> PrimaryKey<'a, P, key::PrimaryRole>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> PrimaryKey<'a, P, key::SubordinateRole>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> PrimaryKey<'a, P, key::UnspecifiedRole>
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        self.primary
    }
}


impl<'a, P: 'a + key::KeyParts> From<PrimaryKeyAmalgamation<'a, P>>
    for ErasedKeyAmalgamation<'a, P>
{
    fn from(ka: PrimaryKeyAmalgamation<'a, P>) -> Self {
        ErasedKeyAmalgamation {
            ca: ka.ca.role_into_unspecified(),
            primary: true,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<SubordinateKeyAmalgamation<'a, P>>
    for ErasedKeyAmalgamation<'a, P>
{
    fn from(ka: SubordinateKeyAmalgamation<'a, P>) -> Self {
        ErasedKeyAmalgamation {
            ca: ka.ca.role_into_unspecified(),
            primary: false,
        }
    }
}


// We can infallibly convert part X to part Y for everything but
// Public -> Secret and Unspecified -> Secret.
macro_rules! impl_conversion {
    ($s:ident, $primary:expr, $p1:path, $p2:path) => {
        impl<'a> From<$s<'a, $p1>>
            for ErasedKeyAmalgamation<'a, $p2>
        {
            fn from(ka: $s<'a, $p1>) -> Self {
                ErasedKeyAmalgamation {
                    ca: ka.ca.into(),
                    primary: $primary,
                }
            }
        }
    }
}

impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::SecretParts, key::PublicParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::UnspecifiedParts, key::PublicParts);

impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::SecretParts, key::PublicParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::UnspecifiedParts, key::PublicParts);


impl<'a, P, P2> TryFrom<ErasedKeyAmalgamation<'a, P>>
    for PrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.role_into_primary().parts_into_unspecified())?,
                primary: (),
            })
        } else {
            Err(Error::InvalidArgument(
                "can't convert a SubordinateKeyAmalgamation \
                 to a PrimaryKeyAmalgamation".into()).into())
        }
    }
}

impl<'a, P, P2> TryFrom<ErasedKeyAmalgamation<'a, P>>
    for SubordinateKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Err(Error::InvalidArgument(
                "can't convert a PrimaryKeyAmalgamation \
                 to a SubordinateKeyAmalgamation".into()).into())
        } else {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.role_into_subordinate().parts_into_unspecified())?,
                primary: (),
            })
        }
    }
}

impl<'a> PrimaryKeyAmalgamation<'a, key::PublicParts> {
    pub(crate) fn new(cert: &'a Cert) -> Self {
        PrimaryKeyAmalgamation {
            ca: ComponentAmalgamation::new(cert, &cert.primary),
            primary: (),
        }
    }
}

impl<'a, P> PrimaryKeyAmalgamation<'a, P>
where
    P: key::KeyParts,
{
    /// Returns the active binding signature at time `t`.
    ///
    /// The active binding signature is the most recent, non-revoked
    /// self-signature that is valid according to the `policy` and
    /// alive at time `t` (`creation time <= t`, `t < expiry`).  If
    /// there are multiple such signatures then the signatures are
    /// ordered by their MPIs interpreted as byte strings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display information about the primary key's current active
    /// // binding signature (the `time` parameter is `None`), if any.
    /// eprintln!("{:?}", cert.primary_key().binding_signature(p, None));
    /// # Ok(()) }
    /// ```
    pub fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
                                -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(crate::now);
        self.bundle().binding_signature(policy, time)
    }
}

impl<'a, P: 'a + key::KeyParts> SubordinateKeyAmalgamation<'a, P> {
    pub(crate) fn new(
        cert: &'a Cert, bundle: &'a KeyBundle<P, key::SubordinateRole>)
        -> Self
    {
        SubordinateKeyAmalgamation {
            ca: ComponentAmalgamation::new(cert, bundle),
            primary: (),
        }
    }

    /// Returns the active binding signature at time `t`.
    ///
    /// The active binding signature is the most recent, non-revoked
    /// self-signature that is valid according to the `policy` and
    /// alive at time `t` (`creation time <= t`, `t < expiry`).  If
    /// there are multiple such signatures then the signatures are
    /// ordered by their MPIs interpreted as byte strings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display information about each keys' current active
    /// // binding signature (the `time` parameter is `None`), if any.
    /// for k in cert.keys().subkeys() {
    ///     eprintln!("{:?}", k.binding_signature(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
                                -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(crate::now);
        self.bundle().binding_signature(policy, time)
    }
}

impl<'a, P: 'a + key::KeyParts> ErasedKeyAmalgamation<'a, P> {
    /// Returns the key's binding signature as of the reference time,
    /// if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should instead do: `ka.with_policy(policy,
    /// time)?.binding_signature()`.
    fn binding_signature<T>(&self, policy: &'a dyn Policy, time: T)
        -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(crate::now);
        if self.primary {
            self.cert().primary_userid_relaxed(policy, time, false)
                .map(|u| u.binding_signature())
                .or_else(|e0| {
                    // Lookup of the primary user id binding failed.
                    // Look for direct key signatures.
                    self.cert().primary_key().bundle()
                        .binding_signature(policy, time)
                        .map_err(|e1| {
                            // Both lookups failed.  Keep the more
                            // meaningful error.
                            if let Some(Error::NoBindingSignature(_))
                                = e1.downcast_ref()
                            {
                                e0 // Return the original error.
                            } else {
                                e1
                            }
                        })
                })
        } else {
            self.bundle().binding_signature(policy, time)
        }
    }
}


impl<'a, P, R, R2> KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,

{
    /// Returns the component's associated certificate.
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.keys() {
    ///     // It's not only an identical `Cert`, it's the same one.
    ///     assert!(std::ptr::eq(k.cert(), &cert));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn cert(&self) -> &'a Cert {
        self.ca.cert()
    }

    /// Returns this amalgamation's bundle.
    pub fn bundle(&self) -> &'a crate::cert::ComponentBundle<Key<P, R>> {
        self.ca.bundle()
    }

    /// Returns this amalgamation's component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about any unknown components.
    /// for k in cert.keys() {
    ///     eprintln!(" - {:?}", k.component());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn component(&self) -> &'a Key<P, R> {
        self.bundle().component()
    }

    /// Returns the `KeyAmalgamation`'s key.
    pub fn key(&self) -> &'a Key<P, R> {
        self.component()
    }

    /// Returns the component's self-signatures.
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} self signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.self_signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_signatures(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ca.self_signatures()
    }

    /// Returns the component's third-party certifications.
    ///
    /// The signatures are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.keys() {
    ///     eprintln!("Key {} has {:?} unverified, third-party certifications",
    ///               k.key().fingerprint(),
    ///               k.certifications().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn certifications(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ca.certifications()
    }

    /// Returns the component's revocations that were issued by the
    /// certificate holder.
    ///
    /// The revocations are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.keys() {
    ///     eprintln!("Key {} has {:?} revocation certificates.",
    ///               k.key().fingerprint(),
    ///               k.self_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ca.self_revocations()
    }

    /// Returns the component's revocations that were issued by other
    /// certificates.
    ///
    /// The revocations are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.keys() {
    ///     eprintln!("Key {} has {:?} unverified, third-party revocation certificates.",
    ///               k.key().fingerprint(),
    ///               k.other_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn other_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ca.other_revocations()
    }

    /// Returns all of the component's signatures.
    ///
    /// Only the self-signatures are validated.  The signatures are
    /// sorted first by type, then by creation time.  The self
    /// revocations come first, then the self signatures,
    /// then any certification approval key signatures,
    /// certifications, and third-party revocations coming last.  This
    /// function may return additional types of signatures that could
    /// be associated to this component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn signatures(&self)
                      -> impl Iterator<Item = &'a Signature> + Send + Sync {
        self.ca.signatures()
    }

    /// Forwarder for the conversion macros.
    pub(crate) fn has_secret(&self) -> bool {
        self.key().has_secret()
    }
}

impl<'a, P, R, R2> KeyAmalgamation<'a, P, R, R2>
    where Self: PrimaryKey<'a, P, R>,
          P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    /// Returns the third-party certifications issued by the specified
    /// key, and valid at the specified time.
    ///
    /// This function returns the certifications issued by the
    /// specified key.  Specifically, it returns a certification if:
    ///
    ///   - it is well-formed,
    ///   - it is live with respect to the reference time,
    ///   - it conforms to the policy, and
    ///   - the signature is cryptographically valid.
    ///
    /// This method is implemented on a [`KeyAmalgamation`] and not
    /// a [`ValidKeyAmalgamation`], because a third-party
    /// certification does not require the key to be self-signed.
    ///
    /// # Examples
    ///
    /// Alice has certified that a certificate belongs to Bob on two
    /// occasions.  Whereas
    /// [`KeyAmalgamation::valid_certifications_by_key`] returns
    /// both certifications,
    /// [`KeyAmalgamation::active_certifications_by_key`] only
    /// returns the most recent certification.
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::packet::UserID;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::types::SignatureType;
    ///
    /// const P: &StandardPolicy = &StandardPolicy::new();
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// # let epoch = std::time::SystemTime::now()
    /// #     - std::time::Duration::new(100, 0);
    /// # let t0 = epoch;
    /// #
    /// # let (alice, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid("<alice@example.org>")
    /// #     .generate()
    /// #     .unwrap();
    /// let alice: Cert = // ...
    /// # alice;
    /// #
    /// # let bob_userid = "<bob@example.org>";
    /// # let (bob, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid(bob_userid)
    /// #     .generate()
    /// #     .unwrap();
    /// let bob: Cert = // ...
    /// # bob;
    ///
    /// # // Alice has not certified Bob's User ID.
    /// # let ka = bob.primary_key();
    /// # assert_eq!(
    /// #     ka.active_certifications_by_key(
    /// #         P, t0, alice.primary_key().key()).count(),
    /// #     0);
    /// #
    /// # // Have Alice certify Bob's certificate.
    /// # let mut alice_signer = alice
    /// #     .keys()
    /// #     .with_policy(P, None)
    /// #     .for_certification()
    /// #     .next().expect("have a certification-capable key")
    /// #     .key()
    /// #     .clone()
    /// #     .parts_into_secret().expect("have unencrypted key material")
    /// #     .into_keypair().expect("have unencrypted key material");
    /// #
    /// # let mut bob = bob;
    /// # for i in 1..=2usize {
    /// #     let ti = t0 + std::time::Duration::new(i as u64, 0);
    /// #
    /// #     let certification = SignatureBuilder::new(SignatureType::DirectKey)
    /// #         .set_signature_creation_time(ti)?
    /// #         .sign_direct_key(
    /// #             &mut alice_signer,
    /// #             bob.primary_key().key())?;
    /// #     bob = bob.insert_packets(certification)?.0;
    /// #
    /// #     let ka = bob.primary_key();
    /// #     assert_eq!(
    /// #         ka.valid_certifications_by_key(
    /// #             P, ti, alice.primary_key().key()).count(),
    /// #         i);
    /// #
    /// #     assert_eq!(
    /// #         ka.active_certifications_by_key(
    /// #             P, ti, alice.primary_key().key()).count(),
    /// #         1);
    /// # }
    /// let bob_pk = bob.primary_key();
    ///
    /// let valid_certifications = bob_pk.valid_certifications_by_key(
    ///     P, None, alice.primary_key().key());
    /// // Alice certified Bob's certificate twice.
    /// assert_eq!(valid_certifications.count(), 2);
    ///
    /// let active_certifications = bob_pk.active_certifications_by_key(
    ///     P, None, alice.primary_key().key());
    /// // But only the most recent one is active.
    /// assert_eq!(active_certifications.count(), 1);
    /// # Ok(()) }
    /// ```
    pub fn valid_certifications_by_key<T, PK>(&self,
                                              policy: &'a dyn Policy,
                                              reference_time: T,
                                              issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a Key<key::PublicParts,
                         key::UnspecifiedRole>>,
    {
        let reference_time = reference_time.into();
        let issuer = issuer.into();

        let primary = self.primary();

        self.ca.valid_certifications_by_key_(
            policy, reference_time, issuer, false,
            self.certifications(),
            move |sig| {
                if primary {
                    sig.clone().verify_direct_key(
                        issuer,
                        self.component().role_as_primary())
                } else {
                    sig.clone().verify_subkey_binding(
                        issuer,
                        self.cert().primary_key().key(),
                        self.component().role_as_subordinate())
                }
            })
    }

    /// Returns any active third-party certifications issued by the
    /// specified key.
    ///
    /// This function is like
    /// [`KeyAmalgamation::valid_certifications_by_key`], but it
    /// only returns active certifications.  Active certifications are
    /// the most recent valid certifications with respect to the
    /// reference time.
    ///
    /// Although there is normally only a single active certification,
    /// there can be multiple certifications with the same timestamp.
    /// In this case, all of them are returned.
    ///
    /// Unlike self-signatures, multiple third-party certifications
    /// issued by the same key at the same time can be sensible.  For
    /// instance, Alice may fully trust a CA for user IDs in a
    /// particular domain, and partially trust it for everything else.
    /// This can only be expressed using multiple certifications.
    ///
    /// This method is implemented on a [`KeyAmalgamation`] and not
    /// a [`ValidKeyAmalgamation`], because a third-party
    /// certification does not require the user ID to be self-signed.
    ///
    /// # Examples
    ///
    /// See the examples for
    /// [`KeyAmalgamation::valid_certifications_by_key`].
    pub fn active_certifications_by_key<T, PK>(&self,
                                               policy: &'a dyn Policy,
                                               reference_time: T,
                                               issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a Key<key::PublicParts,
                         key::UnspecifiedRole>>,
    {
        let reference_time = reference_time.into();
        let issuer = issuer.into();

        let primary = self.primary();

        self.ca.valid_certifications_by_key_(
            policy, reference_time, issuer, true,
            self.certifications(),
            move |sig| {
                if primary {
                    sig.clone().verify_direct_key(
                        issuer,
                        self.component().role_as_primary())
                } else {
                    sig.clone().verify_subkey_binding(
                        issuer,
                        self.cert().primary_key().key(),
                        &self.component().role_as_subordinate())
                }
            })
    }

    /// Returns the third-party revocations issued by the specified
    /// key, and valid at the specified time.
    ///
    /// This function returns the revocations issued by the specified
    /// key.  Specifically, it returns a revocation if:
    ///
    ///   - it is well-formed,
    ///   - it is a [hard revocation](crate::types::RevocationType),
    ///     or it is live with respect to the reference time,
    ///   - it conforms to the policy, and
    ///   - the signature is cryptographically valid.
    ///
    /// This method is implemented on a [`KeyAmalgamation`] and not
    /// a [`ValidKeyAmalgamation`], because a third-party
    /// revocation does not require the key to be self-signed.
    ///
    /// # Examples
    ///
    /// Alice revoked Bob's certificate.
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// # use openpgp::Packet;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::packet::UserID;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::types::ReasonForRevocation;
    /// # use openpgp::types::SignatureType;
    ///
    /// const P: &StandardPolicy = &StandardPolicy::new();
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// # let epoch = std::time::SystemTime::now()
    /// #     - std::time::Duration::new(100, 0);
    /// # let t0 = epoch;
    /// # let t1 = epoch + std::time::Duration::new(1, 0);
    /// #
    /// # let (alice, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid("<alice@example.org>")
    /// #     .generate()
    /// #     .unwrap();
    /// let alice: Cert = // ...
    /// # alice;
    /// #
    /// # let bob_userid = "<bob@example.org>";
    /// # let (bob, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid(bob_userid)
    /// #     .generate()
    /// #     .unwrap();
    /// let bob: Cert = // ...
    /// # bob;
    ///
    /// # // Have Alice certify Bob's certificate.
    /// # let mut alice_signer = alice
    /// #     .keys()
    /// #     .with_policy(P, None)
    /// #     .for_certification()
    /// #     .next().expect("have a certification-capable key")
    /// #     .key()
    /// #     .clone()
    /// #     .parts_into_secret().expect("have unencrypted key material")
    /// #     .into_keypair().expect("have unencrypted key material");
    /// #
    /// # let certification = SignatureBuilder::new(SignatureType::KeyRevocation)
    /// #     .set_signature_creation_time(t1)?
    /// #     .set_reason_for_revocation(
    /// #         ReasonForRevocation::KeyRetired, b"")?
    /// #     .sign_direct_key(
    /// #         &mut alice_signer,
    /// #         bob.primary_key().key())?;
    /// # let bob = bob.insert_packets(certification)?.0;
    /// let ka = bob.primary_key();
    ///
    /// let revs = ka.valid_third_party_revocations_by_key(
    ///     P, None, alice.primary_key().key());
    /// // Alice revoked Bob's certificate.
    /// assert_eq!(revs.count(), 1);
    /// # Ok(()) }
    /// ```
    pub fn valid_third_party_revocations_by_key<T, PK>(&self,
                                                       policy: &'a dyn Policy,
                                                       reference_time: T,
                                                       issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a Key<key::PublicParts,
                         key::UnspecifiedRole>>,
    {
        let issuer = issuer.into();
        let reference_time = reference_time.into();

        let primary = self.primary();

        self.ca.valid_certifications_by_key_(
            policy, reference_time, issuer, false,
            self.other_revocations(),
            move |sig| {
                if primary {
                    sig.clone().verify_primary_key_revocation(
                        issuer,
                        self.component().role_as_primary())
                } else {
                    sig.clone().verify_subkey_revocation(
                        issuer,
                        self.cert().primary_key().key(),
                        &self.component().role_as_subordinate())
                }
            })
    }
}

/// A `KeyAmalgamation` plus a `Policy` and a reference time.
///
/// In the same way that a [`ValidComponentAmalgamation`] extends a
/// [`ComponentAmalgamation`], a `ValidKeyAmalgamation` extends a
/// [`KeyAmalgamation`]: a `ValidKeyAmalgamation` combines a
/// `KeyAmalgamation`, a [`Policy`], and a reference time.  This
/// allows it to implement the [`ValidAmalgamation`] trait, which
/// provides methods like [`ValidAmalgamation::binding_signature`] that require a
/// `Policy` and a reference time.  Although `KeyAmalgamation` could
/// implement these methods by requiring that the caller explicitly
/// pass them in, embedding them in the `ValidKeyAmalgamation` helps
/// ensure that multipart operations, even those that span multiple
/// functions, use the same `Policy` and reference time.
///
/// A `ValidKeyAmalgamation` can be obtained by transforming a
/// `KeyAmalgamation` using [`ValidateAmalgamation::with_policy`].  A
/// [`KeyAmalgamationIter`] can also be changed to yield
/// `ValidKeyAmalgamation`s.
///
/// A `ValidKeyAmalgamation` is guaranteed to come from a valid
/// certificate, and have a valid and live *binding* signature at the
/// specified reference time.  Note: this only means that the binding
/// signatures are live; it says nothing about whether the
/// *certificate* or the *`Key`* is live and non-revoked.  If you care
/// about those things, you need to check them separately.
///
/// # Examples:
///
/// Find all non-revoked, live, signing-capable keys:
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::RevocationStatus;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// # let (cert, _) = CertBuilder::new()
/// #     .add_userid("Alice")
/// #     .add_signing_subkey()
/// #     .add_transport_encryption_subkey()
/// #     .generate().unwrap();
/// // `with_policy` ensures that the certificate and any components
/// // that it returns have valid *binding signatures*.  But, we still
/// // need to check that the certificate and `Key` are not revoked,
/// // and live.
/// //
/// // Note: `ValidKeyAmalgamation::revocation_status`, etc. use the
/// // embedded policy and timestamp.  Even though we used `None` for
/// // the timestamp (i.e., now), they are guaranteed to use the same
/// // timestamp, because `with_policy` eagerly transforms it into
/// // the current time.
/// let cert = cert.with_policy(p, None)?;
/// if let RevocationStatus::Revoked(_revs) = cert.revocation_status() {
///     // Revoked by the certificate holder.  (If we care about
///     // designated revokers, then we need to check those
///     // ourselves.)
/// #   unreachable!();
/// } else if let Err(_err) = cert.alive() {
///     // Certificate was created in the future or is expired.
/// #   unreachable!();
/// } else {
///     // `ValidCert::keys` returns `ValidKeyAmalgamation`s.
///     for ka in cert.keys() {
///         if let RevocationStatus::Revoked(_revs) = ka.revocation_status() {
///             // Revoked by the key owner.  (If we care about
///             // designated revokers, then we need to check those
///             // ourselves.)
/// #           unreachable!();
///         } else if let Err(_err) = ka.alive() {
///             // Key was created in the future or is expired.
/// #           unreachable!();
///         } else if ! ka.for_signing() {
///             // We're looking for a signing-capable key, skip this one.
///         } else {
///             // Use it!
///         }
///     }
/// }
/// # Ok(()) }
/// ```
///
/// [`ValidComponentAmalgamation`]: super::ValidComponentAmalgamation
/// [`ComponentAmalgamation`]: super::ComponentAmalgamation
/// [`Policy`]: crate::policy::Policy
/// [`ValidAmalgamation`]: super::ValidAmalgamation
/// [`ValidAmalgamation::binding_signature`]: super::ValidAmalgamation::binding_signature()
/// [`ValidateAmalgamation::with_policy`]: super::ValidateAmalgamation::with_policy
#[derive(Debug, Clone)]
pub struct ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    // Ouch, ouch, ouch!  ka is a `KeyAmalgamation`, which contains a
    // reference to a `Cert`.  `cert` is a `ValidCert` and contains a
    // reference to the same `Cert`!  We do this so that
    // `ValidKeyAmalgamation` can deref to a `KeyAmalgamation` and
    // `ValidKeyAmalgamation::cert` can return a `&ValidCert`.

    ka: KeyAmalgamation<'a, P, R, R2>,
    cert: ValidCert<'a>,

    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}
assert_send_and_sync!(ValidKeyAmalgamation<'_, P, R, R2>
    where P: key::KeyParts,
          R: key::KeyRole,
          R2: Copy,
);


impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
where
    P: 'a + key::KeyParts,
    R: 'a + key::KeyRole,
    R2: Copy,
{
    /// Returns the component's associated certificate.
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.with_policy(p, None)?.keys() {
    ///     // It's not only an identical `Cert`, it's the same one.
    ///     assert!(std::ptr::eq(k.cert(), &cert));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn cert(&self) -> &'a Cert {
        self.ka.cert()
    }

    /// Returns the valid amalgamation's active binding signature.
    ///
    /// The active binding signature is the most recent, non-revoked
    /// self-signature that is valid according to the `policy` and
    /// alive at time `t` (`creation time <= t`, `t < expiry`).  If
    /// there are multiple such signatures then the signatures are
    /// ordered by their MPIs interpreted as byte strings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display information about each User ID's current active
    /// // binding signature (the `time` parameter is `None`), if any.
    /// for ua in cert.with_policy(p, None)?.userids() {
    ///     eprintln!("{:?}", ua.binding_signature());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the valid amalgamation's amalgamation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// // Get a key amalgamation.
    /// let ka = cert.primary_key();
    ///
    /// // Validate it, yielding a valid key amalgamation.
    /// let vka = ka.with_policy(p, None)?;
    ///
    /// // And here we get the amalgamation back.
    /// let ka2 = vka.amalgamation();
    /// assert_eq!(&ka, ka2);
    /// # Ok(()) }
    /// ```
    pub fn amalgamation(&self) -> &KeyAmalgamation<'a, P, R, R2> {
        &self.ka
    }

    /// Returns this amalgamation's bundle.
    pub fn bundle(&self) -> &'a crate::cert::ComponentBundle<Key<P, R>> {
        self.ka.bundle()
    }

    /// Returns this amalgamation's component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about any unknown components.
    /// for k in cert.with_policy(p, None)?.keys() {
    ///     eprintln!(" - {:?}", k.component());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn component(&self) -> &'a Key<P, R> {
        self.bundle().component()
    }

    /// Returns the `KeyAmalgamation`'s key.
    pub fn key(&self) -> &'a Key<P, R> {
        self.component()
    }

    /// Returns the component's self-signatures.
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.with_policy(p, None)?.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} self signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.self_signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_signatures(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ka.self_signatures()
    }

    /// Returns the component's third-party certifications.
    ///
    /// The signatures are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.with_policy(p, None)?.keys() {
    ///     eprintln!("Key {} has {:?} unverified, third-party certifications",
    ///               k.key().fingerprint(),
    ///               k.certifications().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn certifications(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ka.certifications()
    }

    /// Returns the component's revocations that were issued by the
    /// certificate holder.
    ///
    /// The revocations are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.with_policy(p, None)?.keys() {
    ///     eprintln!("Key {} has {:?} revocation certificates.",
    ///               k.key().fingerprint(),
    ///               k.self_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ka.self_revocations()
    }

    /// Returns the component's revocations that were issued by other
    /// certificates.
    ///
    /// The revocations are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for k in cert.with_policy(p, None)?.keys() {
    ///     eprintln!("Key {} has {:?} unverified, third-party revocation certificates.",
    ///               k.key().fingerprint(),
    ///               k.other_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn other_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.ka.other_revocations()
    }

    /// Returns all of the component's signatures.
    ///
    /// Only the self-signatures are validated.  The signatures are
    /// sorted first by type, then by creation time.  The self
    /// revocations come first, then the self signatures,
    /// then any certification approval key signatures,
    /// certifications, and third-party revocations coming last.  This
    /// function may return additional types of signatures that could
    /// be associated to this component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.with_policy(p, None)?.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn signatures(&self)
                      -> impl Iterator<Item = &'a Signature> + Send + Sync {
        self.ka.signatures()
    }

    /// Forwarder for the conversion macros.
    pub(crate) fn has_secret(&self) -> bool {
        self.key().has_secret()
    }
}

/// A Valid primary Key, and its associated data.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
pub type ValidPrimaryKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A Valid subkey, and its associated data.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
pub type ValidSubordinateKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::SubordinateRole, ()>;

/// A valid key whose role is not known at compile time.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
pub type ValidErasedKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;


impl<'a, P, R, R2> From<ValidKeyAmalgamation<'a, P, R, R2>>
    for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    fn from(vka: ValidKeyAmalgamation<'a, P, R, R2>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        vka.ka
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidPrimaryKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<&ValidPrimaryKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: &ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.clone().into(),
            cert: vka.cert.clone(),
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidSubordinateKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<&ValidSubordinateKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: &ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.clone().into(),
            cert: vka.cert.clone(),
            binding_signature: vka.binding_signature,
        }
    }
}

// We can infallibly convert part X to part Y for everything but
// Public -> Secret and Unspecified -> Secret.
macro_rules! impl_conversion {
    ($s:ident, $p1:path, $p2:path) => {
        impl<'a> From<$s<'a, $p1>>
            for ValidErasedKeyAmalgamation<'a, $p2>
        {
            fn from(vka: $s<'a, $p1>) -> Self {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                ValidErasedKeyAmalgamation {
                    ka: vka.ka.into(),
                    cert: vka.cert,
                    binding_signature: vka.binding_signature,
                }
            }
        }

        impl<'a> From<&$s<'a, $p1>>
            for ValidErasedKeyAmalgamation<'a, $p2>
        {
            fn from(vka: &$s<'a, $p1>) -> Self {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                ValidErasedKeyAmalgamation {
                    ka: vka.ka.clone().into(),
                    cert: vka.cert.clone(),
                    binding_signature: vka.binding_signature,
                }
            }
        }
    }
}

impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::SecretParts, key::PublicParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::UnspecifiedParts, key::PublicParts);

impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::SecretParts, key::PublicParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::UnspecifiedParts, key::PublicParts);


impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidPrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        Ok(ValidPrimaryKeyAmalgamation {
            ka: vka.ka.try_into()?,
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        })
    }
}

impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidSubordinateKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        Ok(ValidSubordinateKeyAmalgamation {
            ka: vka.ka.try_into()?,
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        })
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::PrimaryRole>>
    for ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::SubordinateRole>>
    for ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::UnspecifiedRole>>
    for ValidErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}

impl<'a, P, R, R2> seal::Sealed for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{}

impl<'a, P, R, R2> ValidAmalgamation<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{
    fn valid_cert(&self) -> &ValidCert<'a> {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        &self.cert
    }

    fn time(&self) -> SystemTime {
        self.cert.time()
    }

    fn policy(&self) -> &'a dyn Policy {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.cert.policy()
    }

    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    fn revocation_status(&self) -> RevocationStatus<'a> {
        if self.primary() {
            self.cert.revocation_status()
        } else {
            self.bundle().revocation_status_intern(
                self.policy(), Some(self.time()), true,
                Some(self.binding_signature))
        }
    }

    fn revocation_keys(&self)
                       -> Box<dyn Iterator<Item = &'a RevocationKey> + 'a>
    {
        let mut keys = std::collections::HashSet::new();

        let policy = self.policy();
        let pk_sec = self.cert().primary_key().key().hash_algo_security();

        // All valid self-signatures.
        let sec = self.bundle().hash_algo_security;
        self.self_signatures()
            .filter(move |sig| {
                policy.signature(sig, sec).is_ok()
            })
        // All direct-key signatures.
            .chain(self.cert().primary_key()
                   .self_signatures()
                   .filter(|sig| {
                       policy.signature(sig, pk_sec).is_ok()
                   }))
            .flat_map(|sig| sig.revocation_keys())
            .for_each(|rk| { keys.insert(rk); });

        Box::new(keys.into_iter())
    }
}

impl<'a, P, R, R2> ValidBindingSignature<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
where P: 'a + key::KeyParts,
      R: 'a + key::KeyRole,
      R2: Copy,
      Self: PrimaryKey<'a, P, R>,
{}

impl<'a, P> PrimaryKey<'a, P, key::PrimaryRole>
    for ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> PrimaryKey<'a, P, key::SubordinateRole>
    for ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> PrimaryKey<'a, P, key::UnspecifiedRole>
    for ValidErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        self.ka.primary
    }
}


impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: ValidAmalgamation<'a, Key<P, R>>,
          Self: PrimaryKey<'a, P, R>,
{
    /// Returns whether the key is alive as of the amalgamation's
    /// reference time.
    ///
    /// A `ValidKeyAmalgamation` is guaranteed to have a live binding
    /// signature.  This is independent of whether the component is
    /// live.
    ///
    /// If the certificate is not alive as of the reference time, no
    /// subkey can be alive.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.10 of RFC 9580].
    ///
    ///   [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    ///
    /// For a definition of liveness, see the [`key_alive`] method.
    ///
    /// [`key_alive`]: crate::packet::signature::subpacket::SubpacketAreas::key_alive()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// let ka = cert.primary_key().with_policy(p, None)?;
    /// if let Err(_err) = ka.alive() {
    ///     // Not alive.
    /// #   unreachable!();
    /// }
    /// # Ok(()) }
    /// ```
    pub fn alive(&self) -> Result<()>
    {
        if ! self.primary() {
            // First, check the certificate.
            self.valid_cert().alive()
                .context("The certificate is not live")?;
        }

        let sig = {
            let binding : &Signature = self.binding_signature();
            if binding.key_validity_period().is_some() {
                Some(binding)
            } else {
                self.direct_key_signature().ok()
            }
        };
        if let Some(sig) = sig {
            sig.key_alive(self.key(), self.time())
                .with_context(|| if self.primary() {
                    "The primary key is not live"
                } else {
                    "The subkey is not live"
                })
        } else {
            // There is no key expiration time on the binding
            // signature.  This key does not expire.
            Ok(())
        }
    }
}

impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: key::KeyParts,
          R: key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{
    /// Returns the key's primary key binding signature, if any.
    ///
    /// The [primary key binding signature] is embedded inside a
    /// subkey binding signature.  It is made by the subkey to
    /// indicate that it should be associated with the primary key.
    /// This prevents an attack in which an attacker creates a
    /// certificate, and associates the victim's subkey with it
    /// thereby creating confusion about the certificate that issued a
    /// signature.
    ///
    ///   [primary key binding signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1
    ///
    /// Not all keys have primary key binding signatures.  First,
    /// primary keys don't have them, because they don't need them.
    /// Second, encrypt-capable subkeys don't have them because they
    /// are not (usually) able to issue signatures.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// #
    /// # const P: &StandardPolicy = &StandardPolicy::new();
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let fpr = cert.fingerprint();
    /// let vc = cert.with_policy(P, None)?;
    ///
    /// assert!(vc.primary_key().primary_key_binding_signature().is_none());
    ///
    /// // A signing key has to have a primary key binding signature.
    /// for ka in vc.keys().for_signing() {
    ///     assert!(ka.primary_key_binding_signature().is_some());
    /// }
    ///
    /// // Encryption keys normally can't have a primary key binding
    /// // signature, because they can't issue signatures.
    /// for ka in vc.keys().for_transport_encryption() {
    ///     assert!(ka.primary_key_binding_signature().is_none());
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    pub fn primary_key_binding_signature(&self) -> Option<&Signature> {
        let subkey = if self.primary() {
            // A primary key has no backsig.
            return None;
        } else {
            self.key().role_as_subordinate()
        };

        let pk = self.cert().primary_key().key();

        for backsig in
            self.binding_signature.subpackets(SubpacketTag::EmbeddedSignature)
        {
            if let SubpacketValue::EmbeddedSignature(sig) =
                backsig.value()
            {
                if sig.verify_primary_key_binding(pk, subkey).is_ok() {
                    // Mark the subpacket as authenticated by the
                    // embedded signature.
                    backsig.set_authenticated(true);

                    return Some(sig);
                }
            } else {
                unreachable!("subpackets(EmbeddedSignature) returns \
                              EmbeddedSignatures");
            }
        }

        None
    }
}

impl<'a, P> ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    #[cfg(test)]
    pub(crate) fn set_validity_period_as_of(&self,
                                            primary_signer: &mut dyn Signer,
                                            expiration: Option<time::Duration>,
                                            now: time::SystemTime)
        -> Result<Vec<Signature>>
    {
        ValidErasedKeyAmalgamation::<P>::from(self)
            .set_validity_period_as_of(primary_signer, None, expiration, now)
    }

    /// Creates signatures that cause the key to expire at the specified time.
    ///
    /// This function creates new binding signatures that cause the
    /// key to expire at the specified time when integrated into the
    /// certificate.  For the primary key, it is necessary to
    /// create a new self-signature for each non-revoked User ID, and
    /// to create a direct key signature.  This is needed, because the
    /// primary User ID is first consulted when determining the
    /// primary key's expiration time, and certificates can be
    /// distributed with a possibly empty subset of User IDs.
    ///
    /// Setting a key's expiry time means updating an existing binding
    /// signature---when looking up information, only one binding
    /// signature is normally considered, and we don't want to drop
    /// the other information stored in the current binding signature.
    /// This function uses the binding signature determined by
    /// `ValidKeyAmalgamation`'s policy and reference time for this.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let t = time::SystemTime::now() - time::Duration::from_secs(10);
    /// # let (cert, _) = CertBuilder::new()
    /// #     .set_creation_time(t)
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// let vc = cert.with_policy(p, None)?;
    ///
    /// // Assert that the primary key is not expired.
    /// assert!(vc.primary_key().alive().is_ok());
    ///
    /// // Make the primary key expire in a week.
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// // We assume that the secret key material is available, and not
    /// // password protected.
    /// let mut signer = vc.primary_key()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    ///
    /// let sigs = vc.primary_key().set_expiration_time(&mut signer, Some(t))?;
    /// let cert = cert.insert_packets(sigs)?.0;
    ///
    /// // The primary key isn't expired yet.
    /// let vc = cert.with_policy(p, None)?;
    /// assert!(vc.primary_key().alive().is_ok());
    ///
    /// // But in two weeks, it will be...
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(2 * 7 * 24 * 60 * 60);
    /// let vc = cert.with_policy(p, t)?;
    /// assert!(vc.primary_key().alive().is_err());
    /// # Ok(()) }
    pub fn set_expiration_time(&self,
                               primary_signer: &mut dyn Signer,
                               expiration: Option<time::SystemTime>)
        -> Result<Vec<Signature>>
    {
        ValidErasedKeyAmalgamation::<P>::from(self)
            .set_expiration_time(primary_signer, None, expiration)
    }
}

impl<'a, P> ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    /// Creates signatures that cause the key to expire at the specified time.
    ///
    /// This function creates new binding signatures that cause the
    /// key to expire at the specified time when integrated into the
    /// certificate.  For subkeys, a single `Signature` is returned.
    ///
    /// Setting a key's expiry time means updating an existing binding
    /// signature---when looking up information, only one binding
    /// signature is normally considered, and we don't want to drop
    /// the other information stored in the current binding signature.
    /// This function uses the binding signature determined by
    /// `ValidKeyAmalgamation`'s policy and reference time for this.
    ///
    /// When updating the expiration time of signing-capable subkeys,
    /// we need to create a new [primary key binding signature].
    /// Therefore, we need a signer for the subkey.  If
    /// `subkey_signer` is `None`, and this is a signing-capable
    /// subkey, this function fails with [`Error::InvalidArgument`].
    /// Likewise, this function fails if `subkey_signer` is not `None`
    /// when updating the expiration of a non signing-capable subkey.
    ///
    ///   [primary key binding signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1
    ///   [`Error::InvalidArgument`]: super::super::super::Error::InvalidArgument
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let t = time::SystemTime::now() - time::Duration::from_secs(10);
    /// # let (cert, _) = CertBuilder::new()
    /// #     .set_creation_time(t)
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// let vc = cert.with_policy(p, None)?;
    ///
    /// // Assert that the keys are not expired.
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // Make the keys expire in a week.
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// // We assume that the secret key material is available, and not
    /// // password protected.
    /// let mut primary_signer = vc.primary_key()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    /// let mut signing_subkey_signer = vc.keys().for_signing().nth(0).unwrap()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    ///
    /// let mut sigs = Vec::new();
    /// for ka in vc.keys() {
    ///     if ! ka.for_signing() {
    ///         // Non-signing-capable subkeys are easy to update.
    ///         sigs.append(&mut ka.set_expiration_time(&mut primary_signer,
    ///                                                 None, Some(t))?);
    ///     } else {
    ///         // Signing-capable subkeys need to create a primary
    ///         // key binding signature with the subkey:
    ///         assert!(ka.set_expiration_time(&mut primary_signer,
    ///                                        None, Some(t)).is_err());
    ///
    ///         // Here, we need the subkey's signer:
    ///         sigs.append(&mut ka.set_expiration_time(&mut primary_signer,
    ///                                                 Some(&mut signing_subkey_signer),
    ///                                                 Some(t))?);
    ///     }
    /// }
    /// let cert = cert.insert_packets(sigs)?.0;
    ///
    /// // They aren't expired yet.
    /// let vc = cert.with_policy(p, None)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // But in two weeks, they will be...
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(2 * 7 * 24 * 60 * 60);
    /// let vc = cert.with_policy(p, t)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_err());
    /// }
    /// # Ok(()) }
    pub fn set_expiration_time(&self,
                               primary_signer: &mut dyn Signer,
                               subkey_signer: Option<&mut dyn Signer>,
                               expiration: Option<time::SystemTime>)
        -> Result<Vec<Signature>>
    {
        ValidErasedKeyAmalgamation::<P>::from(self)
            .set_expiration_time(primary_signer, subkey_signer, expiration)
    }
}

impl<'a, P> ValidErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    pub(crate) fn set_validity_period_as_of(&self,
                                            primary_signer: &mut dyn Signer,
                                            subkey_signer:
                                                Option<&mut dyn Signer>,
                                            expiration: Option<time::Duration>,
                                            now: time::SystemTime)
        -> Result<Vec<Signature>>
    {
        let mut sigs = Vec::new();

        // There are two cases to consider.  If we are extending the
        // validity of the primary key, we also need to create new
        // binding signatures for all userids.
        if self.primary() {
            // First, update or create a direct key signature.
            let template = self.direct_key_signature()
                .map(|sig| {
                    signature::SignatureBuilder::from(sig.clone())
                })
                .unwrap_or_else(|_| {
                    let mut template = signature::SignatureBuilder::from(
                        self.binding_signature().clone())
                        .set_type(SignatureType::DirectKey);

                    // We're creating a direct signature from a User
                    // ID self signature.  Remove irrelevant packets.
                    use SubpacketTag::*;
                    let ha = template.hashed_area_mut();
                    ha.remove_all(ExportableCertification);
                    ha.remove_all(Revocable);
                    ha.remove_all(TrustSignature);
                    ha.remove_all(RegularExpression);
                    ha.remove_all(PrimaryUserID);
                    ha.remove_all(SignersUserID);
                    ha.remove_all(ReasonForRevocation);
                    ha.remove_all(SignatureTarget);
                    ha.remove_all(EmbeddedSignature);

                    template
                });
            let mut builder = template
                .set_signature_creation_time(now)?
                .set_key_validity_period(expiration)?;
            builder.hashed_area_mut().remove_all(
                signature::subpacket::SubpacketTag::PrimaryUserID);

            // Generate the signature.
            sigs.push(builder.sign_direct_key(primary_signer, None)?);

            // Second, generate a new binding signature for every
            // userid.  We need to be careful not to change the
            // primary userid, so we make it explicit using the
            // primary userid subpacket.
            for userid in self.valid_cert().userids().revoked(false) {
                // To extend the validity of the subkey, create a new
                // binding signature with updated key validity period.
                let binding_signature = userid.binding_signature();

                let builder = signature::SignatureBuilder::from(binding_signature.clone())
                    .set_signature_creation_time(now)?
                    .set_key_validity_period(expiration)?
                    .set_primary_userid(
                        self.valid_cert().primary_userid().map(|primary| {
                            userid.userid() == primary.userid()
                        }).unwrap_or(false))?;

                sigs.push(builder.sign_userid_binding(primary_signer,
                                                      self.cert().primary_key().component(),
                                                      userid.userid())?);
            }
        } else {
            // To extend the validity of the subkey, create a new
            // binding signature with updated key validity period.
            let backsig = if self.for_certification() || self.for_signing()
                || self.for_authentication()
            {
                if let Some(subkey_signer) = subkey_signer {
                    Some(signature::SignatureBuilder::new(
                        SignatureType::PrimaryKeyBinding)
                         .set_signature_creation_time(now)?
                         .set_hash_algo(self.binding_signature.hash_algo())
                         .sign_primary_key_binding(
                             subkey_signer,
                             self.cert().primary_key().key(),
                             self.key().role_as_subordinate())?)
                } else {
                    return Err(Error::InvalidArgument(
                        "Changing expiration of signing-capable subkeys \
                         requires subkey signer".into()).into());
                }
            } else {
                if subkey_signer.is_some() {
                    return Err(Error::InvalidArgument(
                        "Subkey signer given but subkey is not signing-capable"
                            .into()).into());
                }
                None
            };

            let mut sig =
                signature::SignatureBuilder::from(
                        self.binding_signature().clone())
                    .set_signature_creation_time(now)?
                    .set_key_validity_period(expiration)?;

            if let Some(bs) = backsig {
                sig = sig.set_embedded_signature(bs)?;
            }

            sigs.push(sig.sign_subkey_binding(
                primary_signer,
                self.cert().primary_key().component(),
                self.key().role_as_subordinate())?);
        }

        Ok(sigs)
    }

    /// Creates signatures that cause the key to expire at the specified time.
    ///
    /// This function creates new binding signatures that cause the
    /// key to expire at the specified time when integrated into the
    /// certificate.  For subkeys, only a single `Signature` is
    /// returned.  For the primary key, however, it is necessary to
    /// create a new self-signature for each non-revoked User ID, and
    /// to create a direct key signature.  This is needed, because the
    /// primary User ID is first consulted when determining the
    /// primary key's expiration time, and certificates can be
    /// distributed with a possibly empty subset of User IDs.
    ///
    /// Setting a key's expiry time means updating an existing binding
    /// signature---when looking up information, only one binding
    /// signature is normally considered, and we don't want to drop
    /// the other information stored in the current binding signature.
    /// This function uses the binding signature determined by
    /// `ValidKeyAmalgamation`'s policy and reference time for this.
    ///
    /// When updating the expiration time of signing-capable subkeys,
    /// we need to create a new [primary key binding signature].
    /// Therefore, we need a signer for the subkey.  If
    /// `subkey_signer` is `None`, and this is a signing-capable
    /// subkey, this function fails with [`Error::InvalidArgument`].
    /// Likewise, this function fails if `subkey_signer` is not `None`
    /// when updating the expiration of the primary key, or a non
    /// signing-capable subkey.
    ///
    ///   [primary key binding signature]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1
    ///   [`Error::InvalidArgument`]: super::super::super::Error::InvalidArgument
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let t = time::SystemTime::now() - time::Duration::from_secs(10);
    /// # let (cert, _) = CertBuilder::new()
    /// #     .set_creation_time(t)
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// let vc = cert.with_policy(p, None)?;
    ///
    /// // Assert that the keys are not expired.
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // Make the keys expire in a week.
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// // We assume that the secret key material is available, and not
    /// // password protected.
    /// let mut primary_signer = vc.primary_key()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    /// let mut signing_subkey_signer = vc.keys().for_signing().nth(0).unwrap()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    ///
    /// let mut sigs = Vec::new();
    /// for ka in vc.keys() {
    ///     if ! ka.for_signing() {
    ///         // Non-signing-capable subkeys are easy to update.
    ///         sigs.append(&mut ka.set_expiration_time(&mut primary_signer,
    ///                                                 None, Some(t))?);
    ///     } else {
    ///         // Signing-capable subkeys need to create a primary
    ///         // key binding signature with the subkey:
    ///         assert!(ka.set_expiration_time(&mut primary_signer,
    ///                                        None, Some(t)).is_err());
    ///
    ///         // Here, we need the subkey's signer:
    ///         sigs.append(&mut ka.set_expiration_time(&mut primary_signer,
    ///                                                 Some(&mut signing_subkey_signer),
    ///                                                 Some(t))?);
    ///     }
    /// }
    /// let cert = cert.insert_packets(sigs)?.0;
    ///
    /// // They aren't expired yet.
    /// let vc = cert.with_policy(p, None)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // But in two weeks, they will be...
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(2 * 7 * 24 * 60 * 60);
    /// let vc = cert.with_policy(p, t)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_err());
    /// }
    /// # Ok(()) }
    pub fn set_expiration_time(&self,
                               primary_signer: &mut dyn Signer,
                               subkey_signer: Option<&mut dyn Signer>,
                               expiration: Option<time::SystemTime>)
        -> Result<Vec<Signature>>
    {
        let expiration =
            if let Some(e) = expiration.map(crate::types::normalize_systemtime)
        {
            let ct = self.key().creation_time();
            match e.duration_since(ct) {
                Ok(v) => Some(v),
                Err(_) => return Err(Error::InvalidArgument(
                    format!("Expiration time {:?} predates creation time \
                             {:?}", e, ct)).into()),
            }
        } else {
            None
        };

        self.set_validity_period_as_of(primary_signer, subkey_signer,
                                       expiration, crate::now())
    }
}

impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: ValidAmalgamation<'a, Key<P, R>>,
          Self: ValidBindingSignature<'a, Key<P, R>>,
{
    /// Returns the key's `Key Flags`.
    ///
    /// A Key's [`Key Flags`] holds information about the key.  As of
    /// RFC 9580, this information is primarily concerned with the
    /// key's capabilities (e.g., whether it may be used for signing).
    /// The other information that has been defined is: whether the
    /// key has been split using something like [SSS], and whether the
    /// primary key material is held by multiple parties.  In
    /// practice, the latter two flags are ignored.
    ///
    /// As per [Section 5.2.3.10 of RFC 9580], when looking for the
    /// `Key Flags`, the key's binding signature is first consulted
    /// (in the case of the primary Key, this is the binding signature
    /// of the primary User ID).  If the `Key Flags` subpacket is not
    /// present, then the direct key signature is consulted.
    ///
    /// Since the key flags are taken from the active self signature,
    /// a key's flags may change depending on the policy and the
    /// reference time.
    ///
    /// To increase compatibility with early v4 certificates, if there
    /// is no key flags subpacket on the considered signatures, we
    /// infer the key flags from the key's role and public key
    /// algorithm.
    ///
    ///   [`Key Flags`]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.29
    ///   [SSS]: https://de.wikipedia.org/wiki/Shamir%E2%80%99s_Secret_Sharing
    ///   [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p: &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// let ka = cert.primary_key();
    /// println!("Primary Key's Key Flags: {:?}", ka.key_flags());
    /// # assert!(ka.key_flags().unwrap().for_certification());
    /// # Ok(()) }
    /// ```
    pub fn key_flags(&self) -> Option<KeyFlags> {
        self.map(|s| s.key_flags())
            .or_else(|| {
                // There is no key flags subpacket.  Match on the key
                // role and algorithm and synthesize one.  We do this
                // to better support very early v4 certificates, where
                // either the binding signature is a v3 signature and
                // cannot contain subpackets, or it is a v4 signature,
                // but the key's capabilities were implied by the
                // public key algorithm.
                use crate::types::PublicKeyAlgorithm;

                // XXX: We cannot know whether this is a primary key
                // or not because of
                // https://gitlab.com/sequoia-pgp/sequoia/-/issues/1036
                let is_primary = false;

                // We only match on public key algorithms used at the
                // time.
                #[allow(deprecated)]
                match (is_primary, self.key().pk_algo()) {
                    (true, PublicKeyAlgorithm::RSAEncryptSign) =>
                        Some(KeyFlags::empty()
                             .set_certification()
                             .set_transport_encryption()
                             .set_storage_encryption()
                             .set_signing()),

                    (true, _) =>
                        Some(KeyFlags::empty()
                             .set_certification()
                             .set_signing()),

                    (false, PublicKeyAlgorithm::RSAEncryptSign) =>
                        Some(KeyFlags::empty()
                             .set_transport_encryption()
                             .set_storage_encryption()
                             .set_signing()),

                    (false,
                     | PublicKeyAlgorithm::RSASign
                     | PublicKeyAlgorithm::DSA) =>
                        Some(KeyFlags::empty().set_signing()),

                    (false,
                     | PublicKeyAlgorithm::RSAEncrypt
                     | PublicKeyAlgorithm::ElGamalEncrypt
                     | PublicKeyAlgorithm::ElGamalEncryptSign) =>
                        Some(KeyFlags::empty()
                             .set_transport_encryption()
                             .set_storage_encryption()),

                    // Be conservative: newer algorithms don't get to
                    // benefit from implicit key flags.
                    (false, _) => None,
                }
            })
    }

    /// Returns whether the key has at least one of the specified key
    /// flags.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that may be used for transport encryption (data in
    /// motion) *or* storage encryption (data at rest):
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.has_any_key_flag(KeyFlags::empty()
    ///        .set_storage_encryption()
    ///        .set_transport_encryption())
    ///     {
    ///         // `ka` is encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        let our_flags = self.key_flags().unwrap_or_else(KeyFlags::empty);
        !(&our_flags & flags.borrow()).is_empty()
    }

    /// Returns whether the key is certification capable.
    ///
    /// Note: [Section 10.1 of RFC 9580] says that the primary key is
    /// certification capable independent of the `Key Flags`
    /// subpacket:
    ///
    /// > In a V4 key, the primary key MUST be a key capable of
    /// > certification.
    ///
    /// This function only reflects what is stored in the `Key Flags`
    /// packet; it does not implicitly set this flag.  In practice,
    /// there are keys whose primary key's `Key Flags` do not have the
    /// certification capable flag set.  Some versions of netpgp, for
    /// instance, create keys like this.  Sequoia's higher-level
    /// functionality correctly handles these keys by always
    /// considering the primary key to be certification capable.
    /// Users of this interface should too.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are certification capable:
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.primary() || ka.for_certification() {
    ///         // `ka` is certification capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [Section 10.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.29
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_certification())
    }

    /// Returns whether the key is signing capable.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are signing capable:
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_signing() {
    ///         // `ka` is signing capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_signing())
    }

    /// Returns whether the key is authentication capable.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are authentication capable:
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_authentication() {
    ///         // `ka` is authentication capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_authentication())
    }

    /// Returns whether the key is storage-encryption capable.
    ///
    /// OpenPGP distinguishes two types of encryption keys: those for
    /// storage ([data at rest]) and those for transport ([data in
    /// transit]).  Most OpenPGP implementations, however, don't
    /// distinguish between them in practice.  Instead, when they
    /// create a new encryption key, they just set both flags.
    /// Likewise, when encrypting a message, it is not typically
    /// possible to indicate the type of protection that is needed.
    /// Sequoia supports creating keys with only one of these flags
    /// set, and makes it easy to select the right type of key when
    /// encrypting messages.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are storage-encryption capable:
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_storage_encryption() {
    ///         // `ka` is storage-encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [data at rest]: https://en.wikipedia.org/wiki/Data_at_rest
    /// [data in transit]: https://en.wikipedia.org/wiki/Data_in_transit
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_storage_encryption())
    }

    /// Returns whether the key is transport-encryption capable.
    ///
    /// OpenPGP distinguishes two types of encryption keys: those for
    /// storage ([data at rest]) and those for transport ([data in
    /// transit]).  Most OpenPGP implementations, however, don't
    /// distinguish between them in practice.  Instead, when they
    /// create a new encryption key, they just set both flags.
    /// Likewise, when encrypting a message, it is not typically
    /// possible to indicate the type of protection that is needed.
    /// Sequoia supports creating keys with only one of these flags
    /// set, and makes it easy to select the right type of key when
    /// encrypting messages.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are transport-encryption capable:
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_transport_encryption() {
    ///         // `ka` is transport-encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [data at rest]: https://en.wikipedia.org/wiki/Data_at_rest
    /// [data in transit]: https://en.wikipedia.org/wiki/Data_in_transit
    /// [`ValidKeyAmalgamation::key_flags`]: ValidKeyAmalgamation::key_flags()
    pub fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_transport_encryption())
    }

    /// Returns how long the key is live.
    ///
    /// This returns how long the key is live relative to its creation
    /// time.  Use [`ValidKeyAmalgamation::key_expiration_time`] to
    /// get the key's absolute expiry time.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.10 of RFC 9580].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// use std::convert::TryInto;
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::Timestamp;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// // OpenPGP Timestamps have a one-second resolution.  Since we
    /// // want to round trip the time, round it down.
    /// let now: Timestamp = time::SystemTime::now().try_into()?;
    /// let now: time::SystemTime = now.try_into()?;
    ///
    /// let a_week = time::Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(Some("alice@example.org"))
    ///     .set_creation_time(now)
    ///     .set_validity_period(a_week)
    ///     .generate()?;
    ///
    /// assert_eq!(cert.primary_key().with_policy(p, None)?.key_validity_period(),
    ///            Some(a_week));
    /// # Ok(()) }
    /// ```
    ///
    ///   [`ValidKeyAmalgamation::key_expiration_time`]: ValidKeyAmalgamation::key_expiration_time()
    ///   [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    pub fn key_validity_period(&self) -> Option<std::time::Duration> {
        self.map(|s| s.key_validity_period())
    }

    /// Returns the key's expiration time.
    ///
    /// If this function returns `None`, the key does not expire.
    ///
    /// This returns the key's expiration time.  Use
    /// [`ValidKeyAmalgamation::key_validity_period`] to get the
    /// duration of the key's lifetime.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.10 of RFC 9580].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// use std::convert::TryInto;
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::Timestamp;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// // OpenPGP Timestamps have a one-second resolution.  Since we
    /// // want to round trip the time, round it down.
    /// let now: Timestamp = time::SystemTime::now().try_into()?;
    /// let now: time::SystemTime = now.try_into()?;
    //
    /// let a_week = time::Duration::from_secs(7 * 24 * 60 * 60);
    /// let a_week_later = now + a_week;
    ///
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(Some("alice@example.org"))
    ///     .set_creation_time(now)
    ///     .set_validity_period(a_week)
    ///     .generate()?;
    ///
    /// assert_eq!(cert.primary_key().with_policy(p, None)?.key_expiration_time(),
    ///            Some(a_week_later));
    /// # Ok(()) }
    /// ```
    ///
    ///   [`ValidKeyAmalgamation::key_validity_period`]: ValidKeyAmalgamation::key_validity_period()
    ///   [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    pub fn key_expiration_time(&self) -> Option<time::SystemTime> {
        match self.key_validity_period() {
            Some(vp) if vp.as_secs() > 0 => Some(self.key().creation_time() + vp),
            _ => None,
        }
    }

    // NOTE: If you add a method to ValidKeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for ValidPrimaryKeyAmalgamation.
}


#[cfg(test)]
mod test {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use crate::policy::StandardPolicy as P;
    use crate::cert::prelude::*;
    use crate::packet::Packet;
    use crate::packet::signature::SignatureBuilder;
    use crate::types::ReasonForRevocation;
    use crate::types::RevocationType;

    use super::*;

    #[test]
    fn expire_subkeys() {
        let p = &P::new();

        // Timeline:
        //
        // -1: Key created with no key expiration.
        // 0: Setkeys set to expire in 1 year
        // 1: Subkeys expire

        let now = crate::now();
        let a_year = time::Duration::from_secs(365 * 24 * 60 * 60);
        let in_a_year = now + a_year;
        let in_two_years = now + 2 * a_year;

        let (cert, _) = CertBuilder::new()
            .set_creation_time(now - a_year)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        for ka in cert.keys().with_policy(p, None) {
            assert!(ka.alive().is_ok());
        }

        let mut primary_signer = cert.primary_key().key().clone()
            .parts_into_secret().unwrap().into_keypair().unwrap();
        let mut signing_subkey_signer = cert.with_policy(p, None).unwrap()
            .keys().for_signing().next().unwrap()
            .key().clone().parts_into_secret().unwrap()
            .into_keypair().unwrap();

        // Only expire the subkeys.
        let sigs = cert.keys().subkeys().with_policy(p, None)
            .flat_map(|ka| {
                if ! ka.for_signing() {
                    ka.set_expiration_time(&mut primary_signer,
                                           None,
                                           Some(in_a_year)).unwrap()
                } else {
                    ka.set_expiration_time(&mut primary_signer,
                                           Some(&mut signing_subkey_signer),
                                           Some(in_a_year)).unwrap()
                }
                    .into_iter()
                    .map(Into::into)
            })
            .collect::<Vec<Packet>>();
        let cert = cert.insert_packets(sigs).unwrap().0;

        for ka in cert.keys().with_policy(p, None) {
            assert!(ka.alive().is_ok());
        }

        // Primary should not be expired two years from now.
        assert!(cert.primary_key().with_policy(p, in_two_years).unwrap()
                .alive().is_ok());
        // But the subkeys should be.
        for ka in cert.keys().subkeys().with_policy(p, in_two_years) {
            assert!(ka.alive().is_err());
        }
    }

    /// Test that subkeys of expired certificates are also considered
    /// expired.
    #[test]
    fn issue_564() -> Result<()> {
        use crate::parse::Parse;
        use crate::packet::signature::subpacket::SubpacketTag;
        let p = &P::new();
        let cert = Cert::from_bytes(crate::tests::key("testy.pgp"))?;
        assert!(cert.with_policy(p, None)?.alive().is_err());
        let subkey = cert.with_policy(p, None)?.keys().nth(1).unwrap();
        assert!(subkey.binding_signature().hashed_area()
                .subpacket(SubpacketTag::KeyExpirationTime).is_none());
        assert!(subkey.alive().is_err());
        Ok(())
    }

    /// When setting the primary key's validity period, we create a
    /// direct key signature.  Check that this works even when the
    /// original certificate doesn't have a direct key signature.
    #[test]
    fn set_expiry_on_certificate_without_direct_signature() -> Result<()> {
        use crate::policy::StandardPolicy;

        let p = &StandardPolicy::new();

        let (cert, _) =
            CertBuilder::general_purpose(Some("alice@example.org"))
            .set_validity_period(None)
            .generate()?;

        // Remove the direct key signatures.
        let cert = Cert::from_packets(
            cert.as_tsk().into_packets()
            .filter(|p| ! matches!(
                        p,
                        Packet::Signature(s) if s.typ() == SignatureType::DirectKey
            )))?;

        let vc = cert.with_policy(p, None)?;

        // Assert that the keys are not expired.
        for ka in vc.keys() {
            assert!(ka.alive().is_ok());
        }

        // Make the primary key expire in a week.
        let t = crate::now()
            + time::Duration::from_secs(7 * 24 * 60 * 60);

        let mut signer = vc
            .primary_key().key().clone().parts_into_secret()?
            .into_keypair()?;
        let sigs = vc.primary_key()
            .set_expiration_time(&mut signer, Some(t))?;

        assert!(sigs.iter().any(|s| {
            s.typ() == SignatureType::DirectKey
        }));

        let cert = cert.insert_packets(sigs)?.0;

        // Make sure the primary key *and* all subkeys expire in a
        // week: the subkeys inherit the KeyExpirationTime subpacket
        // from the direct key signature.
        for ka in cert.keys() {
            let ka = ka.with_policy(p, None)?;
            assert!(ka.alive().is_ok());

            let ka = ka.with_policy(p, t + std::time::Duration::new(1, 0))?;
            assert!(ka.alive().is_err());
        }

        Ok(())
    }

    #[test]
    fn key_amalgamation_certifications_by_key() -> Result<()> {
        // Alice and Bob certify Carol's certificate.  We then check
        // that valid_certifications_by_key and
        // active_certifications_by_key return them.
        let p = &crate::policy::StandardPolicy::new();

        // $ date -u -d '2024-01-02 13:00' +%s
        let t0 = UNIX_EPOCH + Duration::new(1704200400, 0);
        // $ date -u -d '2024-01-02 14:00' +%s
        let t1 = UNIX_EPOCH + Duration::new(1704204000, 0);
        // $ date -u -d '2024-01-02 15:00' +%s
        let t2 = UNIX_EPOCH + Duration::new(1704207600, 0);

        let (alice, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<alice@example.example>")
            .generate()
            .unwrap();
        let alice_primary = alice.primary_key().key();

        let (bob, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<bob@example.example>")
            .generate()
            .unwrap();
        let bob_primary = bob.primary_key().key();

        let carol_userid = "<carol@example.example>";
        let (carol, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid(carol_userid)
            .generate()
            .unwrap();

        let ka = alice.primary_key();
        assert_eq!(
            ka.valid_certifications_by_key(p, None, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, None, alice_primary).count(),
            0);

        // Alice has not certified Bob's User ID.
        let ka = bob.primary_key();
        assert_eq!(
            ka.valid_certifications_by_key(p, None, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, None, alice_primary).count(),
            0);

        // Alice has not certified Carol's User ID.
        let ka = carol.primary_key();
        assert_eq!(
            ka.valid_certifications_by_key(p, None, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, None, alice_primary).count(),
            0);


        // Have Alice certify Carol's certificate at t1.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(t1)?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.certifications().count(), 1);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, alice_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, alice_primary).count(),
            1);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, alice_primary).count(),
            1);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, bob_primary).count(),
            0);


        // Have Alice certify Carol's certificate at t1 (again).
        // Since both certifications were created at t1, they should
        // both be returned.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(t1)?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.certifications().count(), 2);
        assert_eq!(
            ka.valid_certifications_by_key(p, t0, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, alice_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, alice_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, alice_primary).count(),
            2);

        assert_eq!(
            ka.valid_certifications_by_key(p, t2, alice_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, alice_primary).count(),
            2);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, bob_primary).count(),
            0);


        // Have Alice certify Carol's certificate at t2.  Now we only
        // have one active certification.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(t2)?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.certifications().count(), 3);
        assert_eq!(
            ka.valid_certifications_by_key(p, t0, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, alice_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, alice_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, alice_primary).count(),
            2);

        assert_eq!(
            ka.valid_certifications_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, alice_primary).count(),
            1);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, bob_primary).count(),
            0);


        // Have Bob certify Carol's certificate at t1 and have it expire at t2.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(t1)?
            .set_signature_validity_period(t2.duration_since(t1)?)?
            .sign_direct_key(
                &mut bob_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.certifications().count(), 4);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, alice_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, alice_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, alice_primary).count(),
            2);

        assert_eq!(
            ka.valid_certifications_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, alice_primary).count(),
            1);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, bob_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, bob_primary).count(),
            1);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, bob_primary).count(),
            1);

        // It expired.
        assert_eq!(
            ka.valid_certifications_by_key(p, t2, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, bob_primary).count(),
            0);


        // Have Bob certify Carol's certificate at t1 again.  This
        // time don't have it expire.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(t1)?
            .sign_direct_key(
                &mut bob_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.certifications().count(), 5);
        assert_eq!(
            ka.valid_certifications_by_key(p, t0, alice_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, alice_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, alice_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, alice_primary).count(),
            2);

        assert_eq!(
            ka.valid_certifications_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, alice_primary).count(),
            1);

        assert_eq!(
            ka.valid_certifications_by_key(p, t0, bob_primary).count(),
            0);
        assert_eq!(
            ka.active_certifications_by_key(p, t0, bob_primary).count(),
            0);

        assert_eq!(
            ka.valid_certifications_by_key(p, t1, bob_primary).count(),
            2);
        assert_eq!(
            ka.active_certifications_by_key(p, t1, bob_primary).count(),
            2);

        // One of the certifications expired.
        assert_eq!(
            ka.valid_certifications_by_key(p, t2, bob_primary).count(),
            1);
        assert_eq!(
            ka.active_certifications_by_key(p, t2, bob_primary).count(),
            1);

        Ok(())
    }

    fn key_amalgamation_valid_third_party_revocations_by_key(
        reason: ReasonForRevocation)
        -> Result<()>
    {
        // Hard revocations are returned independent of the reference
        // time and independent of their expiration.  They are always
        // live.
        let soft = reason.revocation_type() == RevocationType::Soft;

        // Alice and Bob revoke Carol's certificate.  We then check
        // that valid_third_party_revocations_by_key returns them.
        let p = &crate::policy::StandardPolicy::new();

        // $ date -u -d '2024-01-02 13:00' +%s
        let t0 = UNIX_EPOCH + Duration::new(1704200400, 0);
        // $ date -u -d '2024-01-02 14:00' +%s
        let t1 = UNIX_EPOCH + Duration::new(1704204000, 0);
        // $ date -u -d '2024-01-02 15:00' +%s
        let t2 = UNIX_EPOCH + Duration::new(1704207600, 0);

        let (alice, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<alice@example.example>")
            .generate()
            .unwrap();
        let alice_primary = alice.primary_key().key();

        let (bob, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<bob@example.example>")
            .generate()
            .unwrap();
        let bob_primary = bob.primary_key().key();

        let carol_userid = "<carol@example.example>";
        let (carol, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid(carol_userid)
            .generate()
            .unwrap();

        let ka = alice.primary_key();
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, None, alice_primary).count(),
            0);

        // Alice has not revoked Bob's certificate.
        let ka = bob.primary_key();
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, None, alice_primary).count(),
            0);

        // Alice has not revoked Carol's certificate.
        let ka = carol.primary_key();
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, None, alice_primary).count(),
            0);


        // Have Alice revoke Carol's revoke at t1.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(
                reason, b"")?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(rev)?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.other_revocations().count(), 1);

        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, alice_primary).count(),
            if soft { 0 } else { 1 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, alice_primary).count(),
            1);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, bob_primary).count(),
            0);


        // Have Alice revoke Carol's certificate at t1 (again).
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(reason, b"")?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(rev)?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.other_revocations().count(), 2);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, alice_primary).count(),
            if soft { 0 } else { 2 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, alice_primary).count(),
            2);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, alice_primary).count(),
            2);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, bob_primary).count(),
            0);


        // Have Alice revoke Carol's certificate at t2.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t2)?
            .set_reason_for_revocation(reason, b"")?
            .sign_direct_key(
                &mut alice_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(rev)?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.other_revocations().count(), 3);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, alice_primary).count(),
            if soft { 0 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, alice_primary).count(),
            if soft { 2 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, bob_primary).count(),
            0);


        // Have Bob revoke Carol's certificate at t1 and have it expire at t2.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t1)?
            .set_signature_validity_period(t2.duration_since(t1)?)?
            .set_reason_for_revocation(reason, b"")?
            .sign_direct_key(
                &mut bob_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(rev)?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(ka.other_revocations().count(), 4);

        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, alice_primary).count(),
            if soft { 0 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, alice_primary).count(),
            if soft { 2 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, bob_primary).count(),
            if soft { 0 } else { 1 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, bob_primary).count(),
            1);
        // It expired.
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, bob_primary).count(),
            if soft { 0 } else { 1 });


        // Have Bob revoke Carol's certificate at t1 again.  This
        // time don't have it expire.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(reason, b"")?
            .sign_direct_key(
                &mut bob_signer,
                carol.primary_key().key())?;
        let carol = carol.insert_packets(rev)?.0;

        // Check that it is returned.
        let ka = carol.primary_key();
        assert_eq!(
            ka.other_revocations().count(), 5);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, alice_primary).count(),
            if soft { 0 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, alice_primary).count(),
            if soft { 2 } else { 3 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, alice_primary).count(),
            3);
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t0, bob_primary).count(),
            if soft { 0 } else { 2 });
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t1, bob_primary).count(),
            2);
        // One of the revocations expired.
        assert_eq!(
            ka.valid_third_party_revocations_by_key(p, t2, bob_primary).count(),
            if soft { 1 } else { 2 });

        Ok(())
    }

    #[test]
    fn key_amalgamation_valid_third_party_revocations_by_key_soft()
        -> Result<()>
    {
        key_amalgamation_valid_third_party_revocations_by_key(
            ReasonForRevocation::KeyRetired)
    }

    #[test]
    fn key_amalgamation_valid_third_party_revocations_by_key_hard()
        -> Result<()>
    {
        key_amalgamation_valid_third_party_revocations_by_key(
            ReasonForRevocation::KeyCompromised)
    }
}
