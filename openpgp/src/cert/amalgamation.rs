use std::borrow::Borrow;
use std::time;
use std::time::SystemTime;

use crate::{
    Cert,
    cert::components::ComponentBundle,
    Error,
    packet::Signature,
    Result,
    RevocationStatus,
    policy::Policy,
    types::{
        RevocationKey,
        KeyFlags,
    },
};

/// A certificate's component and its associated data.
#[derive(Debug, Clone)]
pub struct ComponentAmalgamation<'a, C>{
    cert: &'a Cert,
    bundle: &'a ComponentBundle<C>,
}

impl<'a, C> std::ops::Deref for ComponentAmalgamation<'a, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        self.bundle.component()
    }
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

    /// Returns the certificate that the component came from.
    pub fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns this component's bundle.
    pub fn bundle(&self) -> &'a ComponentBundle<C> {
        &self.bundle
    }

    /// Returns the components's binding signature as of the reference
    /// time, if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ca.with_policy(policy, time)?.binding_signature().
    fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
        -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.bundle.binding_signature(policy, time)
    }

    /// Sets the policy and the reference time for the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// This transforms the `ComponentAmalgamation` into a
    /// `ValidComponentAmalgamation`, which exposes additional
    /// methods.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<ValidComponentAmalgamation<'a, C>>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if let Some(binding_signature) = self.binding_signature(policy, time) {
            Ok(ValidComponentAmalgamation {
                a: self,
                policy: policy,
                time: time,
                binding_signature: binding_signature,
            })
        } else {
            Err(Error::NoBindingSignature(time).into())
        }
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserID> {
    /// Returns a reference to the User ID.
    pub fn userid(&self) -> &crate::packet::UserID {
        self.bundle().userid()
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserAttribute> {
    /// Returns a reference to the User Attribute.
    pub fn user_attribute(&self) -> &crate::packet::UserAttribute {
        self.bundle().user_attribute()
    }
}

/// A certificate's component and its associated data.
#[derive(Debug, Clone)]
pub struct ValidComponentAmalgamation<'a, C> {
    a: ComponentAmalgamation<'a, C>,
    policy: &'a dyn Policy,
    // The reference time.
    time: SystemTime,
    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

impl<'a, C> std::ops::Deref for ValidComponentAmalgamation<'a, C> {
    type Target = ComponentAmalgamation<'a, C>;

    fn deref(&self) -> &Self::Target {
        &self.a
    }
}

impl<'a, C> ValidComponentAmalgamation<'a, C>
    where C: Ord
{
    /// Returns the amalgamated primary component at time `time`
    ///
    /// If `time` is None, then the current time is used.
    /// `ValidComponentIter` for the definition of a valid component.
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
    pub(super) fn primary(cert: &'a Cert,
                          iter: std::slice::Iter<'a, ComponentBundle<C>>,
                          policy: &'a dyn Policy, t: SystemTime)
        -> Option<ValidComponentAmalgamation<'a, C>>
    {
        use std::cmp::Ordering;

        // Filter out components that are not alive at time `t`.
        //
        // While we have the binding signature, extract a few
        // properties to avoid recomputing the same thing multiple
        // times.
        iter.filter_map(|c| {
            // No binding signature at time `t` => not alive.
            let sig = c.binding_signature(policy, t)?;

            if !sig.signature_alive(t, std::time::Duration::new(0, 0)).is_ok() {
                return None;
            }

            let revoked = c._revoked(policy, t, false, Some(sig));
            let primary = sig.primary_userid().unwrap_or(false);
            let signature_creation_time = sig.signature_creation_time()?;

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
            .and_then(|c| ComponentAmalgamation::new(cert, (c.0).0)
                      .with_policy(policy, t).ok())
    }
}

/// Represents a component under a given policy.
pub trait Amalgamation<'a> {
    /// Returns the certificate that the component came from.
    fn cert(&self) -> &'a Cert;

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

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self>
        where Self: Sized, T: Into<Option<time::SystemTime>>;

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature;

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Option<&'a Signature>;

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a>;

    /// Returns the certificate's revocation status as of the
    /// amalgamtion's reference time.
    fn cert_revoked(&self) -> RevocationStatus<'a> {
        self.cert().revoked(self.policy(), self.time())
    }

    /// Returns whether the certificateis alive as of the
    /// amalgamtion's reference time.
    fn cert_alive(&self) -> Result<()> {
        self.cert().alive(self.policy(), self.time())
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
            .or_else(|| self.direct_key_signature().and_then(f))
    }

    /// Returns the key's key flags as of the amalgamtion's
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
    /// flags as of the amalgamtion's reference time.
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

    /// Returns whether key is signing capable as of the amalgamtion's
    /// reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::default().set_signing(true))
    }

    /// Returns whether key is authentication capable as of the
    /// amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption as of
    /// the amalgamtion's reference time.
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

    /// Returns the key's expiration time as of the amalgamtion's
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
    fn key_expiration_time(&self) -> Option<time::SystemTime>;

    /// Returns the value of the Revocation Key subpacket, which
    /// contains a designated revoker.
    ///
    /// Considers both the binding signature and the direct key
    /// signature.
    fn revocation_keys(&self) -> Box<Iterator<Item = &'a RevocationKey> + 'a> {
        if let Some(dk) = self.direct_key_signature() {
            Box::new(self.binding_signature().revocation_keys().chain(
                dk.revocation_keys()))
        } else {
            Box::new(self.binding_signature().revocation_keys())
        }
    }
}

impl<'a, C> Amalgamation<'a> for ValidComponentAmalgamation<'a, C> {
    // NOTE: No docstring, because ComponentAmalgamation has the same method.
    // Returns the certificate that the component came from.
    fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a component is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidComponentAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    fn time(&self) -> SystemTime {
        self.time
    }

    /// Returns the amalgamation's policy.
    fn policy(&self) -> &'a dyn Policy
    {
        self.policy
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.a.with_policy(policy, time)
    }

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Option<&'a Signature> {
        self.cert.primary.binding_signature(self.policy(), self.time())
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a> {
        self.bundle._revoked(self.policy(), self.time,
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
    for ValidComponentAmalgamation<'a, C> {}
