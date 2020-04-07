//! Key amalgamations.
//!
//! Whereas a `KeyBundle` groups a `Key` with its self signatures, its
//! third-party signatures, and its revocation certificates, a
//! `KeyAmalgamation` groups a `KeyBundle` with all of the necessary
//! context needed to correctly implement relevant key-related
//! functionality.  Specifically, a `KeyAmalgamation` includes a
//! reference to the `KeyBundle`, a reference to the containing
//! certificate, and the key's role (primary or subordinate).
//!
//! There are two notable differences between `KeyBundle`s and
//! `KeyAmalgamation`s.  First, whereas a `KeyBundle`'s role is
//! primarily a marker, a `KeyAmalgamation`'s role determines the
//! `KeyAmalgamation`'s semantics.  As such, it is not possible to
//! convert a `PrimaryKeyAmalgamation` to a `SubordinateAmalgamation`,
//! and vice versa.  Second, a `KeyBundle`, owns its data, but a
//! `KeyAmalgamation` only references the contained data.
//!
//! There are three `KeyAmalgamation` variants:
//! `PrimaryKeyAmalgamation`, `SubordinateKeyAmalgamation`, and
//! `ErasedKeyAmalgamation`.  Unlike a `Key` or a `KeyBundle` with an
//! `UnspecifiedRole`, an `ErasedKeyAmalgamation` remembers its role.
//! This means that an `ErasedKeyAmalgamation` implements the correct
//! semantics even though the role marker has been erased (hence the
//! name).
//!
//! `ErasedKeyAmalgamation`s are returned by `Cert::keys`.
//! `Cert::keys` can't return a more specific type, because it returns
//! an iterator that can contain both primary and subordinate keys.
//! The reason that we use a concrete type instead of a trait object
//! is so that when the user converts a `KeyAmalgamation` to a
//! `ValidKeyAmalgamation`, the `ValidKeyAmalgamation` retains the
//! type information about the role.  Preserving this type information
//! increases type safety for users of this API.
use std::time;
use std::time::SystemTime;
use std::ops::Deref;
use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::Context;

use crate::{
    Cert,
    cert::bundle::KeyBundle,
    cert::amalgamation::{
        ComponentAmalgamation,
        ValidAmalgamation,
        ValidateAmalgamation,
    },
    cert::ValidCert,
    crypto::{hash::Hash, Signer},
    Error,
    Packet,
    packet::Key,
    packet::key,
    packet::key::KeyParts,
    packet::signature,
    packet::Signature,
    policy::Policy,
    Result,
    SignatureType,
    types::HashAlgorithm,
    types::RevocationStatus,
};

/// Methods specific to key amalgamations.
// This trait exists primarily so that `ValidAmalgamation` can depend
// on it, and use it in its default implementations.
pub trait PrimaryKey<'a, P, R>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    /// Returns whether the key amalgamation is a primary key
    /// amalgamation.
    fn primary(&self) -> bool;
}

/// A key amalgamation.
///
/// Generally, you won't use this type directly, but instead use
/// `PrimaryKeyAmalgamation`, `SubordinateKeyAmalgamation`, or
/// `ErasedKeyAmalgamation`.
///
/// See the module-level documentation for information about key
/// amalgamations.
#[derive(Debug)]
pub struct KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    ca: ComponentAmalgamation<'a, Key<P, R>>,
    primary: R2,
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
pub type PrimaryKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A subordinate key amalgamation.
pub type SubordinateKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::SubordinateRole, ()>;

/// An amalgamation whose role is not known at compile time.
///
/// Note: unlike a `Key` or a `KeyBundle` with an unspecified role, an
/// `ErasedKeyAmalgamation` remembers its role; it is just not exposed
/// to the type system.  For details, see the documentation for
/// `KeyAmalgamation`.
pub type ErasedKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;


impl<'a, P, R, R2> Deref for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    type Target = ComponentAmalgamation<'a, Key<P, R>>;

    fn deref(&self) -> &Self::Target {
        &self.ca
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::PrimaryRole>>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidPrimaryKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::SubordinateRole>>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidSubordinateKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::UnspecifiedRole>>
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidErasedKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);

        // We need to make sure the certificate is okay.  This means
        // checking the primary key.  But, be careful: we don't need
        // to double check.
        if ! self.primary() {
            let pka = PrimaryKeyAmalgamation::new(self.cert());
            pka.with_policy(policy, time).context("primary key")?;
        }

        let binding_signature = self.binding_signature(policy, time)?;
        let cert = self.ca.cert();
        let vka = ValidErasedKeyAmalgamation {
            ka: KeyAmalgamation {
                ca: key::PublicParts::convert_key_amalgamation(
                    self.ca.parts_into_unspecified()).expect("to public"),
                primary: self.primary,
            },
            // We need some black magic to avoid infinite
            // recursion: a ValidCert must be valid for the
            // specified policy and reference time.  A ValidCert
            // is consider valid if the primary key is valid.
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
                cert: cert,
                policy: policy,
                time: time,
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
            ca: ka.ca.mark_role_unspecified(),
            primary: true,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<SubordinateKeyAmalgamation<'a, P>>
    for ErasedKeyAmalgamation<'a, P>
{
    fn from(ka: SubordinateKeyAmalgamation<'a, P>) -> Self {
        ErasedKeyAmalgamation {
            ca: ka.ca.mark_role_unspecified(),
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
                    ka.ca.mark_role_primary().parts_into_unspecified())?,
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
                    ka.ca.mark_role_subordinate().parts_into_unspecified())?,
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
        let time = time.into().unwrap_or_else(SystemTime::now);
        if self.primary {
            self.cert().primary_userid_relaxed(policy, time, false)
                .map(|u| u.binding_signature())
                .or_else(|e0| {
                    // Lookup of the primary user id binding failed.
                    // Look for direct key signatures.
                    self.cert().primary_key().bundle()
                        .binding_signature(policy, time)
                        .or_else(|e1| {
                            // Both lookups failed.  Keep the more
                            // meaningful error.
                            if let Some(Error::NoBindingSignature(_))
                                = e1.downcast_ref()
                            {
                                Err(e0) // Return the original error.
                            } else {
                                Err(e1)
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
    /// Returns the `KeyAmalgamation`'s `ComponentAmalgamation`.
    pub fn component_amalgamation(&self)
        -> &ComponentAmalgamation<'a, Key<P, R>> {
        &self.ca
    }

    /// Returns the `KeyAmalgamation`'s key.
    ///
    /// Normally, a type implementing `KeyAmalgamation` eventually
    /// derefs to a `Key`, however, this method provides a more
    /// accurate lifetime.  See the documentation for
    /// `ComponentAmalgamation::component` for an explanation.
    pub fn key(&self) -> &'a Key<P, R> {
        self.ca.component()
    }
}

/// A validated `KeyAmalgamation`.
///
/// A `ValidKeyAmalgamation` includes a policy and a reference time,
/// and is guaranteed to have a live binding signature at that time.
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

/// A valid primary key amalgamation.
pub type ValidPrimaryKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A valid subordinate key amalgamation.
pub type ValidSubordinateKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::SubordinateRole, ()>;

/// A valid amalgamation whose role is not known at compile time.
pub type ValidErasedKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;


impl<'a, P, R, R2> Deref for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    type Target = KeyAmalgamation<'a, P, R, R2>;

    fn deref(&self) -> &Self::Target {
        &self.ka
    }
}


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

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
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

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
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

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
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


impl<'a, P, R, R2> ValidAmalgamation<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{
    fn cert(&self) -> &ValidCert<'a> {
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

    fn revoked(&self) -> RevocationStatus<'a> {
        if self.primary() {
            self.cert.revoked()
        } else {
            self.bundle()._revoked(self.policy(), self.time(),
                                   true, Some(self.binding_signature))
        }
    }

    fn key_expiration_time(&self) -> Option<time::SystemTime> {
        match self.key_validity_period() {
            Some(vp) if vp.as_secs() > 0 => Some(self.key().creation_time() + vp),
            _ => None,
        }
    }
}


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
          Self: ValidAmalgamation<'a, Key<P, R>>
{
    /// Returns whether the key (not just the binding signature!) is
    /// alive as of the amalgamtion's reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    pub fn alive(&self) -> Result<()>
    {
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
        } else {
            // There is no key expiration time on the binding
            // signature.  This key does not expire.
            Ok(())
        }
    }

    /// Returns the wrapped `KeyAmalgamation`.
    pub fn into_key_amalgamation(self) -> KeyAmalgamation<'a, P, R, R2> {
        self.ka
    }

}

impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
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
                                            expiration: Option<time::Duration>,
                                            now: time::SystemTime)
        -> Result<Vec<Packet>>
    {
        let mut sigs = Vec::new();
        let binding = self.binding_signature();
        for template in [
            // The primary key's binding signature might be the direct
            // key signature.  To avoid generating two new direct key
            // signatures, check that we do in fact have a userid
            // binding signature.
            if binding.typ() != SignatureType::DirectKey {
                // Userid binding signature.
                Some(binding)
            } else {
                None
            },
            // Also update the direct key signature if we're updating
            // the primary key's expiration time.
            if self.primary() {
                self.direct_key_signature().ok()
            } else {
                None
            },
        ].iter().filter_map(|&x| x) {
            // Recompute the signature.
            let hash_algo = HashAlgorithm::SHA512;
            let mut hash = hash_algo.context()?;

            self.cert().primary.key().hash(&mut hash);
            match template.typ() {
                SignatureType::DirectKey =>
                    (), // Nothing to hash.
                SignatureType::GenericCertification
                    | SignatureType::PersonaCertification
                    | SignatureType::CasualCertification
                    | SignatureType::PositiveCertification =>
                    self.cert.primary_userid()
                    .expect("this type must be from a userid binding, \
                             hence there must be a userid valid at `now`")
                    .userid().hash(&mut hash),
                SignatureType::SubkeyBinding =>
                    self.key().hash(&mut hash),
                _ => unreachable!(),
            }

            // Generate the signature.
            sigs.push(signature::Builder::from(template.clone())
                      .set_key_validity_period(expiration)?
                      .set_signature_creation_time(now)?
                      .sign_hash(primary_signer, hash)?.into());
        }

        Ok(sigs)
    }

    /// Sets the key to expire at the given time.
    ///
    /// A policy is needed, because the expiration is updated by adding
    /// a self-signature to the primary user id.
    pub fn set_expiration_time(&self,
                               primary_signer: &mut dyn Signer,
                               expiration: Option<time::SystemTime>)
        -> Result<Vec<Packet>>
    {
        let expiration =
            if let Some(e) = expiration.map(crate::types::normalize_systemtime)
        {
            let ct = self.creation_time();
            match e.duration_since(ct) {
                Ok(v) => Some(v),
                Err(_) => return Err(Error::InvalidArgument(
                    format!("Expiration time {:?} predates creation time \
                             {:?}", e, ct)).into()),
            }
        } else {
            None
        };

        self.set_validity_period_as_of(primary_signer, expiration,
                                       time::SystemTime::now())
    }


    // NOTE: If you add a method to ValidKeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for ValidPrimaryKeyAmalgamation.
}


#[cfg(test)]
mod test {
    use crate::policy::StandardPolicy as P;
    use crate::cert::prelude::*;

    use super::*;

    #[test]
    fn expire_subkeys() {
        let p = &P::new();

        // Timeline:
        //
        // -1: Key created with no key expiration.
        // 0: Setkeys set to expire in 1 year
        // 1: Subkeys expire

        let now = time::SystemTime::now();
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

        let mut primary = cert.primary_key().key().clone()
            .parts_into_secret().unwrap().into_keypair().unwrap();

        // Only expire the subkeys.
        let sigs = cert.keys().subkeys().with_policy(p, None)
            .flat_map(|ka| {
                ka.set_expiration_time(&mut primary, Some(in_a_year))
                    .unwrap()
                    .into_iter()
                    .map(Into::into)
            })
            .collect::<Vec<Packet>>();
        let cert = cert.merge_packets(sigs).unwrap();

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
}
