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

use failure::ResultExt;

use crate::{
    Cert,
    cert::components::KeyBundle,
    cert::amalgamation::{
        ComponentAmalgamation,
        ValidAmalgamation,
        ValidateAmalgamation,
    },
    Error,
    packet::Key,
    packet::key,
    packet::key::KeyParts,
    packet::Signature,
    policy::Policy,
    Result,
    types::RevocationStatus,
};

/// Methods specific to key amalgamations.
// This trait exists primarily so that `ValidAmalgamation` can depend
// on it, and use it in its default implementations.
pub trait Primary<'a, P, R>
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

        if let Some(binding_signature) = self.binding_signature(policy, time) {
            let vka = ValidErasedKeyAmalgamation {
                ka: KeyAmalgamation {
                    ca: key::PublicParts::convert_key_amalgamation(
                        self.ca.mark_parts_unspecified()).expect("to public"),
                    primary: self.primary,
                },
                policy: policy,
                time: time,
                binding_signature: binding_signature,
            };
            policy.key(&vka)?;
            Ok(ValidErasedKeyAmalgamation {
                ka: KeyAmalgamation {
                    ca: P::convert_key_amalgamation(
                        vka.ka.ca.mark_parts_unspecified()).expect("roundtrip"),
                    primary: vka.ka.primary,
                },
                policy: policy,
                time: time,
                binding_signature: binding_signature,
            })
        } else {
            Err(Error::NoBindingSignature(time).into())
        }
    }
}

impl<'a, P> Primary<'a, P, key::PrimaryRole>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> Primary<'a, P, key::SubordinateRole>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> Primary<'a, P, key::UnspecifiedRole>
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


impl<'a, P, P2> TryFrom<ErasedKeyAmalgamation<'a, P>>
    for PrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = failure::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.mark_role_primary().mark_parts_unspecified())?,
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
    type Error = failure::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Err(Error::InvalidArgument(
                "can't convert a PrimaryKeyAmalgamation \
                 to a SubordinateKeyAmalgamation".into()).into())
        } else {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.mark_role_subordinate().mark_parts_unspecified())?,
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
        -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if self.primary {
            self.cert().primary_userid(policy, time)
                .map(|u| u.binding_signature())
                .or_else(|| self.cert().primary_key().bundle()
                         .binding_signature(policy, time))
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
    ka: KeyAmalgamation<'a, P, R, R2>,
    // The policy.
    policy: &'a dyn Policy,
    // The reference time.
    time: SystemTime,
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
        vka.ka
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidPrimaryKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            time: vka.time,
            policy: vka.policy,
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidSubordinateKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            time: vka.time,
            policy: vka.policy,
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidPrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = failure::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        Ok(ValidPrimaryKeyAmalgamation {
            ka: vka.ka.try_into()?,
            time: vka.time,
            policy: vka.policy,
            binding_signature: vka.binding_signature,
        })
    }
}

impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidSubordinateKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = failure::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        Ok(ValidSubordinateKeyAmalgamation {
            ka: vka.ka.try_into()?,
            time: vka.time,
            policy: vka.policy,
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
        self.ka.with_policy(policy, time)
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
        self.ka.with_policy(policy, time)
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
        self.ka.with_policy(policy, time)
    }
}


impl<'a, P, R, R2> ValidAmalgamation<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: Primary<'a, P, R>,
{
    fn cert(&self) -> &'a Cert {
        self.ka.cert()
    }

    fn time(&self) -> SystemTime {
        self.time
    }

    fn policy(&self) -> &'a dyn Policy {
        self.policy
    }

    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    fn direct_key_signature(&self) -> Option<&'a Signature> {
        self.cert().primary.binding_signature(self.policy, self.time())
    }

    fn revoked(&self) -> RevocationStatus<'a> {
        if self.primary() {
            self.cert().revoked(self.policy, self.time())
        } else {
            self.bundle()._revoked(self.policy, self.time(),
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


impl<'a, P> Primary<'a, P, key::PrimaryRole>
    for ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> Primary<'a, P, key::SubordinateRole>
    for ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> Primary<'a, P, key::UnspecifiedRole>
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
                self.direct_key_signature()
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

    // NOTE: If you add a method to ValidKeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for ValidPrimaryKeyAmalgamation.
}


impl<'a, P, R, R2> crate::cert::Preferences<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: Primary<'a, P, R>,
{
}
