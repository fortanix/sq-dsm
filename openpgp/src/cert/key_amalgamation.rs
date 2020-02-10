use std::time;
use std::time::SystemTime;
use std::convert::TryFrom;
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

impl<'a, P: key::KeyParts> Deref for KeyAmalgamation<'a, P> {
    type Target = Key<P, key::UnspecifiedRole>;

    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

macro_rules! create_p_conversions {
    ( $Key:ident ) => {
        macro_rules! convert {
            ( $x:ident ) => {
                // XXX: This is ugly, but how can we do better?
                unsafe { std::mem::transmute($x) }
            }
        }

        macro_rules! convert_ref {
            ( $x:ident ) => {
                // XXX: This is ugly, but how can we do better?
                unsafe { std::mem::transmute($x) }
            }
        }

        // Convert between two KeyParts for a constant KeyRole.
        // Unfortunately, we can't let the KeyRole vary as otherwise we
        // get conflicting types when we do the same to convert between
        // two KeyRoles for a constant KeyParts. :(
        macro_rules! p {
            ( <$from_parts:ty> -> <$to_parts:ty>) => {
                impl<'a> From<$Key<'a, $from_parts>> for $Key<'a, $to_parts> {
                    fn from(p: $Key<'a, $from_parts>) -> Self {
                        convert!(p)
                    }
                }

                impl<'a> From<&$Key<'a, $from_parts>> for &$Key<'a, $to_parts> {
                    fn from(p: &$Key<'a, $from_parts>) -> Self {
                        convert_ref!(p)
                    }
                }
            }
        }

        // Likewise, but using TryFrom.
        macro_rules! p_try {
            ( <$from_parts:ty> -> <$to_parts:ty>) => {
                impl<'a> TryFrom<$Key<'a, $from_parts>> for $Key<'a, $to_parts> {
                    type Error = failure::Error;
                    fn try_from(p: $Key<'a, $from_parts>) -> Result<Self> {
                        if p.secret().is_some() {
                            Ok(convert!(p))
                        } else {
                            Err(Error::InvalidArgument("No secret key".into())
                                .into())
                        }
                    }
                }

                impl<'a> TryFrom<&$Key<'a, $from_parts>> for &$Key<'a, $to_parts> {
                    type Error = failure::Error;
                    fn try_from(p: &$Key<'a, $from_parts>) -> Result<Self> {
                        if p.secret().is_some() {
                            Ok(convert_ref!(p))
                        } else {
                            Err(Error::InvalidArgument("No secret key".into())
                                .into())
                        }
                    }
                }
            }
        }


        p_try!(<key::PublicParts> -> <key::SecretParts>);
        p!(<key::PublicParts> -> <key::UnspecifiedParts>);

        p!(<key::SecretParts> -> <key::PublicParts>);
        p!(<key::SecretParts> -> <key::UnspecifiedParts>);

        p!(<key::UnspecifiedParts> -> <key::PublicParts>);
        p_try!(<key::UnspecifiedParts> -> <key::SecretParts>);
    }
}

create_p_conversions!(KeyAmalgamation);
create_p_conversions!(PrimaryKeyAmalgamation);
create_p_conversions!(ValidKeyAmalgamation);
create_p_conversions!(ValidPrimaryKeyAmalgamation);

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
    pub fn key(&self) -> &'a Key<P, key::UnspecifiedRole> {
        match self {
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Primary(), .. } =>
                P::convert_key_ref(self.cert.primary.key().into())
                .expect("secret key amalgamations contain secret keys"),
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Subordinate(bundle), .. } =>
                P::convert_key_ref(bundle.key()
                                   .mark_parts_unspecified_ref()
                                   .mark_role_unspecified_ref())
                .expect("secret key amalgamations contain secret keys"),
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
        self.key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.key().secret() {
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
    pub fn bundle(&self) -> &'a KeyBundle<P, key::UnspecifiedRole> {
        match self {
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Primary(), .. } =>
                P::convert_bundle_ref((&self.cert.primary).into())
                .expect("secret key amalgamations contain secret keys"),
            KeyAmalgamation { bundle: KeyAmalgamationBundle::Subordinate(bundle), .. } =>
                P::convert_bundle_ref((*bundle)
                                      .mark_parts_unspecified_ref()
                                      .mark_role_unspecified_ref())
                .expect("secret key amalgamations contain secret keys"),
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

impl<'a, P: key::KeyParts> Deref for PrimaryKeyAmalgamation<'a, P> {
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
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole> {
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
    pub fn bundle(&self) -> &'a KeyBundle<P, key::UnspecifiedRole> {
        self.a.bundle()
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

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.key().secret() {
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

impl<'a, P: key::KeyParts> Deref for ValidPrimaryKeyAmalgamation<'a, P> {
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
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole> {
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

impl<'a, P: 'a + key::KeyParts> Amalgamation<'a>
    for ValidPrimaryKeyAmalgamation<'a, P>
{
    // NOTE: No docstring, because KeyAmalgamation has the same method.
    // Returns the certificate that the component came from.
    fn cert(&self) -> &'a Cert {
        self.a.cert()
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a key is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidKeyAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    fn time(&self) -> SystemTime {
        self.a.time()
    }

    /// Returns the amalgamation's policy.
    fn policy(&self) -> &'a dyn Policy {
        self.a.policy()
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        Ok(ValidPrimaryKeyAmalgamation {
            a: self.a.with_policy(policy, time)?,
        })
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    fn binding_signature(&self) -> &'a Signature {
        self.a.binding_signature()
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    fn direct_key_signature(&self) -> Option<&'a Signature> {
        self.a.direct_key_signature()
    }

    /// Returns the key's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this function only returns whether the key has been
    /// revoked, it does not return whether the certificate has been
    /// revoked.
    fn revoked(&self) -> RevocationStatus<'a> {
        self.a.revoked()
    }
}

impl<'a, P: key::KeyParts> crate::cert::Preferences<'a>
    for ValidPrimaryKeyAmalgamation<'a, P> {}
