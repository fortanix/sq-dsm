use std::time;
use std::time::SystemTime;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::borrow::Borrow;
use std::ops::Deref;

use crate::{
    Cert,
    cert::components::{
        Amalgamation,
        KeyBundle,
    },
    Error,
    packet::key,
    packet::key::SecretKeyMaterial,
    packet::Key,
    packet::Signature,
    policy::Policy,
    Result,
    RevocationStatus,
    types::KeyFlags,
};

/// The underlying `KeyAmalgamation` type.
///
/// We don't make this type public, because an enum's variant types
/// must also all be public, and we don't want that here.  Wrapping
/// this in a struct means that we can hide that.
#[derive(Debug, Clone)]
enum KeyAmalgamationBundle<'a, P: key::KeyParts> {
    Primary(),
    Subordinate(&'a KeyBundle<P, key::SubordinateRole>),
}

/// A `Key` and its associated data.
#[derive(Debug, Clone)]
pub struct KeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    bundle: KeyAmalgamationBundle<'a, P>,
}

impl<'a, P: key::KeyParts> Deref for KeyAmalgamation<'a, P>
    where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
{
    type Target = Key<P, key::UnspecifiedRole>;

    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a> From<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::UnspecifiedParts>
{
    fn from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Primary(),
            } =>
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Primary(),
                },
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Subordinate(bundle),
            } =>
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Subordinate(bundle.into()),
                },
        }
    }
}

impl<'a> From<KeyAmalgamation<'a, key::SecretParts>>
    for KeyAmalgamation<'a, key::PublicParts>
{
    fn from(ka: KeyAmalgamation<'a, key::SecretParts>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Primary(),
            } =>
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Primary(),
                },
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Subordinate(bundle),
            } =>
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Subordinate(bundle.into()),
                },
        }
    }
}

impl<'a> TryFrom<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::SecretParts>
{
    type Error = failure::Error;

    fn try_from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Result<Self> {
        Ok(match ka {
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Primary(),
            } => {
                // Error out if the primary key does not have secret
                // key material.
                let _ : &KeyBundle<key::SecretParts, key::PrimaryRole>
                    = (&cert.primary).try_into()?;
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Primary(),
                }
            }
            KeyAmalgamation {
                cert,
                bundle: KeyAmalgamationBundle::Subordinate(bundle),
            } =>
                KeyAmalgamation {
                    cert,
                    bundle: KeyAmalgamationBundle::Subordinate(bundle.try_into()?),
                },
        })
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P> {
    pub(crate) fn new_primary(cert: &'a Cert) -> Self {
        KeyAmalgamation {
            cert: cert,
            bundle: KeyAmalgamationBundle::Primary(),
        }
    }

    pub(crate) fn new_subordinate(
        cert: &'a Cert, bundle: &'a KeyBundle<P, key::SubordinateRole>)
        -> Self
    {
        KeyAmalgamation {
            cert: cert,
            bundle: KeyAmalgamationBundle::Subordinate(bundle),
        }
    }

    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::UnspecifiedRole>
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        match self {
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Primary(), .. } =>
                self.cert.primary.key().into(),
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Subordinate(bundle), .. } =>
                bundle.key().into(),
        }
    }

    /// Returns the key, but without conversion to P.
    fn generic_key(&self)
                   -> &'a Key<key::UnspecifiedParts, key::UnspecifiedRole> {
        match self {
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Primary(), .. } =>
                self.cert.primary.key().into(),
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Subordinate(bundle), .. } =>
                bundle.key().mark_parts_unspecified_ref().into(),
        }
    }

    /// Returns the certificate that the key came from.
    pub fn cert(&self) -> &'a Cert
    {
        self.cert
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.generic_key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.generic_key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns this key's bundle.
    pub fn bundle(&self) -> &'a KeyBundle<P, key::UnspecifiedRole>
        where &'a KeyBundle<P, key::UnspecifiedRole>:
            From<&'a KeyBundle<key::PublicParts, key::PrimaryRole>>
    {
        match self {
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Primary(), .. } =>
                (&self.cert.primary).into(),
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Subordinate(bundle), .. } =>
                (*bundle).into(),
        }
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ka.with_policy(time)?.binding_signature().
    fn binding_signature<T>(&self, policy: &'a dyn Policy, time: T)
        -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        match self {
            KeyAmalgamation {
                bundle: KeyAmalgamationBundle::Primary(),
                ..
            } => {
                self.cert.primary_userid(policy, time)
                    .map(|u| u.binding_signature())
                    .or_else(|| self.cert.primary_key().bundle()
                             .binding_signature(policy, time))
            },
            KeyAmalgamation {
                bundle: KeyAmalgamationBundle::Subordinate(bundle),
                ..
            } =>
                bundle.binding_signature(policy, time),
        }
    }

    /// Sets the reference time for the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// This transforms the `KeyAmalgamation` into a
    /// `ValidKeyAmalgamation`.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<ValidKeyAmalgamation<'a, P>>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if let Some(binding_signature) = self.binding_signature(policy, time) {
            Ok(ValidKeyAmalgamation {
                a: self,
                policy: policy,
                time: time,
                binding_signature: binding_signature,
            })
        } else {
            Err(Error::NoBindingSignature(time).into())
        }
    }

    // NOTE: If you add a method to KeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for PrimaryKeyAmalgamation.
}

/// A `Key` and its associated data.
///
/// This is just a wrapper around `KeyAmalgamation` that preserves the
/// `KeyAmalgamation`'s role.
#[derive(Debug, Clone)]
pub struct PrimaryKeyAmalgamation<'a, P: key::KeyParts> {
    a: KeyAmalgamation<'a, P>,
}

impl<'a, P> From<PrimaryKeyAmalgamation<'a, P>>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(a: PrimaryKeyAmalgamation<'a, P>) -> Self {
        a.a
    }
}

impl<'a, P: key::KeyParts> Deref for PrimaryKeyAmalgamation<'a, P>
    where &'a Key<P, key::PrimaryRole>: From<&'a key::PublicKey>
{
    type Target = KeyAmalgamation<'a, P>;

    fn deref(&self) -> &Self::Target {
        &self.a
    }
}

impl<'a, P: key::KeyParts> PrimaryKeyAmalgamation<'a, P> {
    /// Constructs a PrimaryKeyAmalgamation from a KeyAmalgamation.
    ///
    /// Note: This function panics if the `KeyAmalgamation` does not
    /// contain a primary key!
    pub(super) fn new(a: KeyAmalgamation<'a, P>) -> Self {
        assert_match!(
            &KeyAmalgamation {
                bundle: KeyAmalgamationBundle::Primary(),
                ..
            } = &a);

        PrimaryKeyAmalgamation {
            a
        }
    }

    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole>
        where &'a Key<P, key::UnspecifiedRole>:
            From<&'a Key<key::PublicParts, key::PrimaryRole>>
    {
        self.a.key().into()
    }

    /// Sets the reference time for the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// This transforms the `KeyAmalgamation` into a
    /// `ValidKeyAmalgamation`.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<ValidPrimaryKeyAmalgamation<'a, P>>
        where T: Into<Option<time::SystemTime>>
    {
        Ok(ValidPrimaryKeyAmalgamation::new(self.a.with_policy(policy, time)?))
    }
}


/// A `Key` and its associated data.
///
/// A `ValidKeyAmalgamation` includes a reference time, and is
/// guaranteed to have a live binding signature at that time.
#[derive(Debug, Clone)]
pub struct ValidKeyAmalgamation<'a, P: key::KeyParts> {
    a: KeyAmalgamation<'a, P>,

    // The policy.
    policy: &'a dyn Policy,
    // The reference time.
    time: SystemTime,

    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

impl<'a, P: key::KeyParts> Deref for ValidKeyAmalgamation<'a, P> {
    type Target = KeyAmalgamation<'a, P>;

    fn deref(&self) -> &Self::Target {
        &self.a
    }
}

impl<'a, P: key::KeyParts> From<ValidKeyAmalgamation<'a, P>>
    for KeyAmalgamation<'a, P>
{
    fn from(vka: ValidKeyAmalgamation<'a, P>) -> Self {
        vka.a
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a> From<ValidKeyAmalgamation<'a, key::PublicParts>>
    for ValidKeyAmalgamation<'a, key::UnspecifiedParts>
{
    fn from(ka: ValidKeyAmalgamation<'a, key::PublicParts>) -> Self {
        ValidKeyAmalgamation {
            a: ka.a.into(),
            policy: ka.policy,
            time: ka.time,
            binding_signature: ka.binding_signature,
        }
    }
}

impl<'a> From<ValidKeyAmalgamation<'a, key::SecretParts>>
    for ValidKeyAmalgamation<'a, key::PublicParts>
{
    fn from(ka: ValidKeyAmalgamation<'a, key::SecretParts>) -> Self {
        ValidKeyAmalgamation {
            a: ka.a.into(),
            policy: ka.policy,
            time: ka.time,
            binding_signature: ka.binding_signature,
        }
    }
}

impl<'a> TryFrom<ValidKeyAmalgamation<'a, key::PublicParts>>
    for ValidKeyAmalgamation<'a, key::SecretParts>
{
    type Error = failure::Error;

    fn try_from(ka: ValidKeyAmalgamation<'a, key::PublicParts>) -> Result<Self> {
        Ok(ValidKeyAmalgamation {
            a: ka.a.try_into()?,
            policy: ka.policy,
            time: ka.time,
            binding_signature: ka.binding_signature,
        })
    }
}

impl<'a, P: 'a + key::KeyParts> Amalgamation<'a> for ValidKeyAmalgamation<'a, P>
{
    // NOTE: No docstring, because KeyAmalgamation has the same method.
    // Returns the certificate that the component came from.
    fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a key is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidKeyAmalgamation::alive` will return true if the reference
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

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Option<&'a Signature> {
        self.cert.primary.binding_signature(self.policy, self.time())
    }

    /// Returns the key's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this function only returns whether the key has been
    /// revoked, it does not return whether the certificate has been
    /// revoked.
    fn revoked(&self) -> RevocationStatus<'a> {
        match self.a.bundle {
            KeyAmalgamationBundle::Primary() =>
                self.cert.revoked(self.policy, self.time()),
            KeyAmalgamationBundle::Subordinate(bundle) =>
                bundle.revoked(self.policy, self.time()),
        }
    }
}

impl<'a, P: 'a + key::KeyParts> ValidKeyAmalgamation<'a, P> {
    /// Returns this key's bundle.
    pub fn bundle(&self) -> &'a KeyBundle<P, key::UnspecifiedRole>
        where &'a KeyBundle<P, key::UnspecifiedRole>:
            From<&'a KeyBundle<key::PublicParts, key::PrimaryRole>>
    {
        match self {
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    bundle: KeyAmalgamationBundle::Primary(), ..
                },
                ..
            } =>
                (&self.cert.primary).into(),
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    bundle: KeyAmalgamationBundle::Subordinate(bundle),
                    ..
                },
                ..
            } =>
                (*bundle).into(),
        }
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
    pub fn key_flags(&self) -> Option<KeyFlags> {
        self.binding_signature().key_flags()
            .or_else(|| self.direct_key_signature()
                     .and_then(|sig| sig.key_flags()))
    }

    /// Returns whether the key has at least one of the specified key
    /// flags as of the amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
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
    pub fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_certification(true))
    }

    /// Returns whether key is signing capable as of the amalgamtion's
    /// reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    pub fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_signing(true))
    }

    /// Returns whether key is authentication capable as of the
    /// amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    pub fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption as of
    /// the amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    pub fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_storage_encryption(true))
    }

    /// Returns whether key is intended for transport encryption as of the
    /// amalgamtion's reference time.
    ///
    /// Key flags are computed as described in
    /// [`key_flags()`](#method.key_flags).
    pub fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_transport_encryption(true))
    }

    /// Returns whether the key is alive as of the amalgamtion's
    /// reference time.
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
            let binding = self.binding_signature();
            if binding.key_expiration_time().is_some() {
                Some(binding)
            } else {
                self.direct_key_signature()
            }
        };
        if let Some(sig) = sig {
            sig.key_alive(self.generic_key(), self.time())
        } else {
            // There is no key expiration time on the binding
            // signature.  This key does not expire.
            Ok(())
        }
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
    pub fn key_expiration_time(&self) -> Option<std::time::Duration> {
        self.binding_signature().key_expiration_time()
            .or_else(|| self.direct_key_signature()
                     .and_then(|sig| sig.key_expiration_time()))
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.generic_key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.generic_key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    // NOTE: If you add a method to ValidKeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for ValidPrimaryKeyAmalgamation.
}

/// A `Key` and its associated data.
///
/// This is just a wrapper around `ValidKeyAmalgamation` that
/// preserves the `ValidKeyAmalgamation`'s role.
#[derive(Debug, Clone)]
pub struct ValidPrimaryKeyAmalgamation<'a, P: key::KeyParts> {
    a: ValidKeyAmalgamation<'a, P>,
}

impl<'a, P> From<ValidPrimaryKeyAmalgamation<'a, P>>
    for ValidKeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(a: ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        a.a
    }
}

impl<'a, P: key::KeyParts> Deref for ValidPrimaryKeyAmalgamation<'a, P>
    where &'a Key<P, key::PrimaryRole>: From<&'a key::PublicKey>
{
    type Target = ValidKeyAmalgamation<'a, P>;

    fn deref(&self) -> &Self::Target {
        &self.a
    }
}

impl<'a, P: key::KeyParts> ValidPrimaryKeyAmalgamation<'a, P> {
    /// Constructs a ValidPrimaryKeyAmalgamation from a
    /// ValidKeyAmalgamation.
    ///
    /// Note: This function panics if the `ValidKeyAmalgamation` does
    /// not contain a primary key!
    pub(super) fn new(a: ValidKeyAmalgamation<'a, P>) -> Self {
        assert_match!(
            &ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    bundle: KeyAmalgamationBundle::Primary(),
                    ..
                },
                ..
            } = &a);

        ValidPrimaryKeyAmalgamation {
            a
        }
    }

    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole>
        where &'a Key<P, key::UnspecifiedRole>:
            From<&'a Key<key::PublicParts, key::PrimaryRole>>
    {
        self.a.key().into()
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        Ok(Self::new(self.a.with_policy(policy, time)?))
    }
}
