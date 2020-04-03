//! Component amalgamations.
//!
//! Whereas a `ComponentBundle` groups a `Component` with its self
//! signatures, its third-party signatures, and its revocation
//! certificates, an `Amalgamation` groups a `ComponentBundle` with
//! all of the necessary context needed to correctly implement
//! relevant functionality related to the component.  Specifically, a
//! `Amalgamation` includes a reference to the `ComponentBundle`, and
//! a reference to the containing certificate.
//!
//! A notable differences between `ComponentBundle`s and
//! `Amalgamation`s is that a `ComponentBundle`, owns its data, but an
//! `Amalgamation` only references the contained data.
use std::borrow::Borrow;
use std::time;
use std::time::SystemTime;
use std::clone::Clone;

use crate::{
    cert::prelude::*,
    Error,
    packet::Signature,
    Result,
    policy::Policy,
    types::{
        AEADAlgorithm,
        CompressionAlgorithm,
        Features,
        HashAlgorithm,
        KeyFlags,
        KeyServerPreferences,
        RevocationKey,
        RevocationStatus,
        SymmetricAlgorithm,
    },
};

mod iter;
pub use iter::{
    KeyAmalgamationIter,
    ValidKeyAmalgamationIter,
};

/// Applies a policy to an amalgamation.
///
/// Note: This trait is split off from the `Amalgamation` trait, to
/// reduce code duplication: it is often possible to provide blanket
/// implementations of `Amalgamation`, but the `ValidateAmalgamation`
/// trait can only be implemented on more concrete types.
pub trait ValidateAmalgamation<'a, C: 'a> {
    /// The type returned by `with_policy`.
    type V;

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// Applies a policy to an amalgamation.
///
/// This is an internal variant of `ValidateAmalgamation`, which
/// allows validating a component for an otherwise invalid
/// certificate.  See `ValidComponentAmalgamation::primary` for an
/// explanation.
trait ValidateAmalgamationRelaxed<'a, C: 'a> {
    /// The type returned by `with_policy`.
    type V;

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only expose to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    fn with_policy_relaxed<T>(self, policy: &'a dyn Policy, time: T,
                              valid_cert: bool) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// An amalgamation with a policy and a reference time.
///
/// In a certain sense, a `ValidAmalgamation` provides a view of an
/// `Amalgamation` as it was at a particular time.  That is,
/// signatures and components that are not valid at the reference
/// time, because they were created after the reference time, for
/// instance, are ignored.
///
/// The methods exposed by a `ValidAmalgamation` are similar to those
/// exposed by an `Amalgamation`, but the policy and reference time
/// are taken from the `ValidAmalgamation`.  This helps prevent using
/// different policies or different reference times when using a
/// component, which can easily happen when the checks span multiple
/// functions.
pub trait ValidAmalgamation<'a, C: 'a>
{
    /// Returns the certificate.
    fn cert(&self) -> &ValidCert<'a>;

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a component is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidComponentAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    fn time(&self) -> SystemTime;

    /// Returns the amalgamation's policy.
    fn policy(&self) -> &'a dyn Policy;

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature;

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Result<&'a Signature>;

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a>;

    /// Returns the certificate's revocation status as of the
    /// amalgamation's reference time.
    fn cert_revoked(&self) -> RevocationStatus<'a> {
        self.cert().revoked()
    }

    /// Returns whether the certificate is alive as of the
    /// amalgamation's reference time.
    fn cert_alive(&self) -> Result<()> {
        self.cert().alive()
    }

    /// Maps the given function over binding and direct key signature.
    ///
    /// Makes `f` consider both the binding signature and the direct
    /// key signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn map<F: Fn(&'a Signature) -> Option<T>, T>(&self, f: F) -> Option<T> {
        f(self.binding_signature())
            .or_else(|| self.direct_key_signature().ok().and_then(f))
    }

    /// Returns the key's key flags as of the amalgamation's
    /// reference time.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn key_flags(&self) -> Option<KeyFlags> {
        self.map(|s| s.key_flags())
    }

    /// Returns whether the key has at least one of the specified key
    /// flags as of the amalgamation's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        let our_flags = self.key_flags().unwrap_or_default();
        !(&our_flags & flags.borrow()).is_empty()
    }

    /// Returns whether key is certification capable as of the
    /// amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::default().set_certification(true))
    }

    /// Returns whether key is signing capable as of the amalgamation's
    /// reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::default().set_signing(true))
    }

    /// Returns whether key is authentication capable as of the
    /// amalgamation's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption as of
    /// the amalgamation's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_storage_encryption(true))
    }

    /// Returns whether key is intended for transport encryption as of the
    /// amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_transport_encryption(true))
    }

    /// Returns the key's expiration time as of the amalgamation's
    /// reference time.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn key_validity_period(&self) -> Option<std::time::Duration> {
        self.map(|s| s.key_validity_period())
    }

    /// Returns the key's expiration time as of the amalgamation's
    /// reference time.
    ///
    /// If this function returns `None`, the key does not expire.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn key_expiration_time(&self) -> Option<time::SystemTime>;

    /// Returns the value of the Revocation Key subpacket, which
    /// contains a designated revoker.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.
    fn revocation_keys(&self)
                       -> Box<dyn Iterator<Item = &'a RevocationKey> + 'a>
    {
        if let Some(dk) = self.direct_key_signature().ok() {
            Box::new(self.binding_signature().revocation_keys().chain(
                dk.revocation_keys()))
        } else {
            Box::new(self.binding_signature().revocation_keys())
        }
    }
}

/// A certificate's component and its associated data.
#[derive(Debug, PartialEq)]
pub struct ComponentAmalgamation<'a, C> {
    cert: &'a Cert,
    bundle: &'a ComponentBundle<C>,
}

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert,
            bundle: self.bundle,
        }
    }
}

impl<'a, C> std::ops::Deref for ComponentAmalgamation<'a, C> {
    type Target = ComponentBundle<C>;

    fn deref(&self) -> &Self::Target {
        self.bundle
    }
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Returns the certificate that the component came from.
    pub fn cert(&self) -> &'a Cert {
        &self.cert
    }

    /// Returns this amalgamation's bundle.
    ///
    /// Note: although `Amalgamation` derefs to a
    /// `ComponentBundle`, this method provides a more accurate
    /// lifetime, which is helpful when returning the reference
    /// from a function.
    ///
    /// Consider the following, which doesn't work:
    ///
    /// ```compile_fail
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// cert.keys()
    ///     .map(|ka| {
    ///         let b : &KeyBundle<_, _> = &ka;
    ///         b
    ///     })
    ///     .collect::<Vec<&KeyBundle<_, _>>>();
    /// ```
    ///
    /// Compiling the above code results in the following error:
    ///
    /// > `b` returns a value referencing data owned by the current
    /// function
    ///
    /// This error occurs because the [`Deref` trait] says that the
    /// lifetime of the target, i.e., `&KeyBundle`, is
    /// bounded by `ka`'s lifetime, whose lifetime is indeed
    /// limited to the closure.  But, `&KeyBundle` is independent
    /// of `ka`!  It is a copy of the `KeyAmalgamation`'s
    /// reference to the `KeyBundle` whose lifetime is `'a`.
    /// Unfortunately, this can't be expressed using `Deref`, but
    /// it can be done using a separate method:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// cert.keys().map(|ka| ka.bundle())
    ///     .collect::<Vec<&KeyBundle<_, _>>>();
    /// ```
    ///
    /// [`Deref` trait]: https://doc.rust-lang.org/stable/std/ops/trait.Deref.html
    pub fn bundle(&self) -> &'a ComponentBundle<C> {
        &self.bundle
    }

    /// Returns this amalgamation's component.
    ///
    /// Note: although `Amalgamation` derefs to a `Component` (via
    /// `ComponentBundle`), this method provides a more accurate
    /// lifetime, which is helpful when returning the reference
    /// from a function.
    ///
    /// Consider the following, which doesn't work:
    ///
    /// ```compile_fail
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// cert.keys()
    ///     .map(|ka| {
    ///         let k : &Key<_, _> = &ka;
    ///         k
    ///     })
    ///     .collect::<Vec<&Key<_, _>>>();
    /// ```
    ///
    /// Compiling the above code results in the following error:
    ///
    /// > `k` returns a value referencing data owned by the current
    /// function
    ///
    /// This error occurs because the [`Deref` trait] says that the
    /// lifetime of the target, i.e., `&Key`, is bounded by
    /// the `ka`'s lifetime, whose lifetime is indeed limited to
    /// the closure.  But, `&Key` is independent of `ka`!  It is a
    /// copy of the `KeyAmalgamation`'s reference to the `Key`
    /// whose lifetime is `'a`.  Unfortunately, this can't be
    /// expressed using `Deref`, but it can be done using a
    /// separate method:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// cert.keys().map(|ka| ka.key())
    ///     .collect::<Vec<&Key<_, _>>>();
    /// ```
    ///
    /// [`Deref` trait]: https://doc.rust-lang.org/stable/std/ops/trait.Deref.html
    pub fn component(&self) -> &'a C {
        self.bundle().component()
    }
}

macro_rules! impl_with_policy {
    ($func:ident, $value:ident $(, $arg:ident: $type:ty )*) => {
        fn $func<T>(self, policy: &'a dyn Policy, time: T, $($arg: $type, )*)
            -> Result<Self::V>
            where T: Into<Option<time::SystemTime>>,
                  Self: Sized
        {
            let time = time.into().unwrap_or_else(SystemTime::now);

            if $value {
                self.cert.with_policy(policy, time)?;
            }

            let binding_signature = self.binding_signature(policy, time)?;
            let cert = self.cert;
            // We can't do `Cert::with_policy` as that would
            // result in infinite recursion.  But at this point,
            // we know the certificate is valid (unless the caller
            // doesn't care).
            Ok(ValidComponentAmalgamation {
                ca: self,
                cert: ValidCert {
                    cert: cert,
                    policy: policy,
                    time: time,
                },
                binding_signature: binding_signature,
            })
        }
    }
}

impl<'a, C> ValidateAmalgamation<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy, true);
}

impl<'a, C> ValidateAmalgamationRelaxed<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy_relaxed, valid_cert, valid_cert: bool);
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Creates a new amalgamation.
    pub(crate) fn new(cert: &'a Cert, bundle: &'a ComponentBundle<C>) -> Self
    {
        Self {
            cert,
            bundle,
        }
    }

    /// Returns the components's binding signature as of the reference
    /// time, if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ca.with_policy(policy, time)?.binding_signature().
    fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
        -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.bundle.binding_signature(policy, time)
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserID> {
    /// Returns a reference to the User ID.
    pub fn userid(&self) -> &'a crate::packet::UserID {
        self.component()
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserAttribute> {
    /// Returns a reference to the User Attribute.
    pub fn user_attribute(&self) -> &'a crate::packet::UserAttribute {
        self.component()
    }
}

/// A certificate's component and its associated data.
#[derive(Debug)]
pub struct ValidComponentAmalgamation<'a, C> {
    ca: ComponentAmalgamation<'a, C>,
    cert: ValidCert<'a>,
    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ValidComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            binding_signature: self.binding_signature,
        }
    }
}

impl<'a, C> std::ops::Deref for ValidComponentAmalgamation<'a, C> {
    type Target = ComponentAmalgamation<'a, C>;

    fn deref(&self) -> &Self::Target {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        &self.ca
    }
}

impl<'a, C: 'a> From<ValidComponentAmalgamation<'a, C>>
    for ComponentAmalgamation<'a, C>
{
    fn from(vca: ValidComponentAmalgamation<'a, C>) -> Self {
        assert!(std::ptr::eq(vca.ca.cert(), vca.cert.cert()));
        vca.ca
    }
}

impl<'a, C> ValidComponentAmalgamation<'a, C>
    where C: Ord
{
    /// Returns the amalgamated primary component at time `time`
    ///
    /// If `time` is None, then the current time is used.
    /// `ValidComponentBundleIter` for the definition of a valid component.
    ///
    /// The primary component is determined by taking the components that
    /// are alive at time `t`, and sorting them as follows:
    ///
    ///   - non-revoked first
    ///   - primary first
    ///   - signature creation first
    ///
    /// If there is more than one, than one is selected in a
    /// deterministic, but undefined manner.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only expose to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    pub(super) fn primary(cert: &'a Cert,
                          iter: std::slice::Iter<'a, ComponentBundle<C>>,
                          policy: &'a dyn Policy, t: SystemTime,
                          valid_cert: bool)
        -> Result<ValidComponentAmalgamation<'a, C>>
    {
        use std::cmp::Ordering;

        let mut error = None;

        // Filter out components that are not alive at time `t`.
        //
        // While we have the binding signature, extract a few
        // properties to avoid recomputing the same thing multiple
        // times.
        iter.filter_map(|c| {
            // No binding signature at time `t` => not alive.
            let sig = match c.binding_signature(policy, t) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    error = Some(e);
                    None
                },
            }?;

            let revoked = c._revoked(policy, t, false, Some(sig));
            let primary = sig.primary_userid().unwrap_or(false);
            let signature_creation_time = match sig.signature_creation_time() {
                Some(time) => Some(time),
                None => {
                    error = Some(Error::MalformedPacket(
                        "Signature has no creation time".into()).into());
                    None
                },
            }?;

            Some(((c, sig, revoked), primary, signature_creation_time))
        })
            .max_by(|(a, a_primary, a_signature_creation_time),
                    (b, b_primary, b_signature_creation_time)| {
                match (destructures_to!(RevocationStatus::Revoked(_) = &a.2),
                       destructures_to!(RevocationStatus::Revoked(_) = &b.2)) {
                    (true, false) => return Ordering::Less,
                    (false, true) => return Ordering::Greater,
                    _ => (),
                }
                match (a_primary, b_primary) {
                    (true, false) => return Ordering::Greater,
                    (false, true) => return Ordering::Less,
                    _ => (),
                }
                match a_signature_creation_time.cmp(&b_signature_creation_time)
                {
                    Ordering::Less => return Ordering::Less,
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Equal => (),
                }

                // Fallback to a lexographical comparison.  Prefer
                // the "smaller" one.
                match a.0.component().cmp(&b.0.component()) {
                    Ordering::Less => return Ordering::Greater,
                    Ordering::Greater => return Ordering::Less,
                    Ordering::Equal =>
                        panic!("non-canonicalized Cert (duplicate components)"),
                }
            })
            .ok_or_else(|| {
                error.map(|e| e.context(format!(
                    "No binding signature at time {}", crate::fmt::time(&t))))
                    .unwrap_or(Error::NoBindingSignature(t).into())
            })
            .and_then(|c| ComponentAmalgamation::new(cert, (c.0).0)
                      .with_policy_relaxed(policy, t, valid_cert))
    }
}

impl<'a, C> ValidateAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C> {
    type V = Self;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized,
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));

        let time = time.into().unwrap_or_else(SystemTime::now);
        self.ca.with_policy(policy, time)
    }
}

impl<'a, C> ValidAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C> {
    fn cert(&self) -> &ValidCert<'a> {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        &self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a component is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidComponentAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    fn time(&self) -> SystemTime {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.time
    }

    /// Returns the amalgamation's policy.
    fn policy(&self) -> &'a dyn Policy
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.policy
    }

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.binding_signature
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Result<&'a Signature> {
        self.cert.cert.primary.binding_signature(self.policy(), self.time())
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a> {
        self.bundle._revoked(self.policy(), self.cert.time,
                              false, Some(self.binding_signature))
    }

    /// Returns the key's expiration time as of the amalgamtion's
    /// reference time.
    ///
    /// If this function returns `None`, the key does not expire.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn key_expiration_time(&self) -> Option<time::SystemTime> {
        let key = self.cert().primary_key().key();
        match self.key_validity_period() {
            Some(vp) if vp.as_secs() > 0 => Some(key.creation_time() + vp),
            _ => None,
        }
    }
}

impl<'a, C> crate::cert::Preferences<'a>
    for ValidComponentAmalgamation<'a, C>
{
    fn preferred_symmetric_algorithms(&self)
                                      -> Option<&'a [SymmetricAlgorithm]> {
        self.map(|s| s.preferred_symmetric_algorithms())
    }

    fn preferred_hash_algorithms(&self) -> Option<&'a [HashAlgorithm]> {
        self.map(|s| s.preferred_hash_algorithms())
    }

    fn preferred_compression_algorithms(&self)
                                        -> Option<&'a [CompressionAlgorithm]> {
        self.map(|s| s.preferred_compression_algorithms())
    }

    fn preferred_aead_algorithms(&self) -> Option<&'a [AEADAlgorithm]> {
        self.map(|s| s.preferred_aead_algorithms())
    }

    fn key_server_preferences(&self) -> Option<KeyServerPreferences> {
        self.map(|s| s.key_server_preferences())
    }

    fn preferred_key_server(&self) -> Option<&'a [u8]> {
        self.map(|s| s.preferred_key_server())
    }

    fn features(&self) -> Option<Features> {
        self.map(|s| s.features())
    }
}

#[cfg(test)]
mod test {
    use crate::policy::StandardPolicy as P;
    use crate::cert::prelude::*;
    use crate::packet::UserID;

    // derive(Clone) doesn't work with generic parameters that don't
    // implement clone.  Make sure that our custom implementations
    // work.
    //
    // See: https://github.com/rust-lang/rust/issues/26925
    #[test]
    fn clone() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let userid : ComponentAmalgamation<UserID>
            = cert.userids().nth(0).unwrap();
        assert_eq!(userid.userid(), userid.clone().userid());

        let userid : ValidComponentAmalgamation<UserID>
            = userid.with_policy(p, None).unwrap();
        let c = userid.clone();
        assert_eq!(userid.userid(), c.userid());
        assert_eq!(userid.time(), c.time());
    }

    #[test]
    fn map() {
        // The reference returned by `ComponentAmalgamation::userid`
        // and `ComponentAmalgamation::user_attribute` is bound by the
        // reference to the `Component` in the
        // `ComponentAmalgamation`, not the `ComponentAmalgamation`
        // itself.
        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let _ = cert.userids().map(|ua| ua.userid())
            .collect::<Vec<_>>();

        let _ = cert.user_attributes().map(|ua| ua.user_attribute())
            .collect::<Vec<_>>();
    }
}
