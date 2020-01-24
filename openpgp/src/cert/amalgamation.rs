use std::time;
use std::time::SystemTime;

use crate::{
    Cert,
    cert::components::ComponentBinding,
    Error,
    packet::Signature,
    Result,
    RevocationStatus,
};

/// A certificate's component and its associated data.
#[derive(Debug, Clone)]
pub struct ComponentAmalgamation<'a, C>{
    cert: &'a Cert,
    binding: &'a ComponentBinding<C>,
}

impl<'a, C> std::ops::Deref for ComponentAmalgamation<'a, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        self.binding.component()
    }
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Creates a new amalgamation.
    pub(crate) fn new(cert: &'a Cert, binding: &'a ComponentBinding<C>) -> Self
    {
        Self {
            cert,
            binding,
        }
    }

    /// Returns the certificate that the component came from.
    pub fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns this component's component binding.
    pub fn binding(&self) -> &'a ComponentBinding<C> {
        &self.binding
    }

    /// Returns the components's binding signature as of the reference
    /// time, if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ca.policy(time)?.binding_signature().
    fn binding_signature<T>(&self, time: T) -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.binding.binding_signature(time)
    }

    /// Sets the reference time for the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// This transforms the `ComponentAmalgamation` into a
    /// `ValidComponentAmalgamation`.
    pub fn policy<T>(self, time: T)
        -> Result<ValidComponentAmalgamation<'a, C>>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if let Some(binding_signature) = self.binding_signature(time) {
            Ok(ValidComponentAmalgamation {
                a: self,
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
        self.binding().userid()
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserAttribute> {
    /// Returns a reference to the User Attribute.
    pub fn user_attribute(&self) -> &crate::packet::UserAttribute {
        self.binding().user_attribute()
    }
}

/// A certificate's component and its associated data.
#[derive(Debug, Clone)]
pub struct ValidComponentAmalgamation<'a, C> {
    a: ComponentAmalgamation<'a, C>,
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
                          iter: std::slice::Iter<'a, ComponentBinding<C>>,
                          t: SystemTime)
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
            let sig = c.binding_signature(t)?;

            if !sig.signature_alive(t, std::time::Duration::new(0, 0)).is_ok() {
                return None;
            }

            let revoked = c._revoked(false, Some(sig), t);
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
                      .policy(t).ok())
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

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn policy<T>(self, time: T) -> Result<Self>
        where Self: Sized, T: Into<Option<time::SystemTime>>;

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature;

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a>;

    /// Returns the certificate's revocation status as of the
    /// amalgamtion's reference time.
    fn cert_revoked(&self) -> RevocationStatus<'a> {
        self.cert().revoked(self.time())
    }

    /// Returns whether the certificateis alive as of the
    /// amalgamtion's reference time.
    fn cert_alive(&self) -> Result<()> {
        self.cert().alive(self.time())
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

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    fn policy<T>(self, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.a.policy(time)
    }

    /// Returns the component's binding signature as of the reference time.
    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    fn revoked(&self) -> RevocationStatus<'a> {
        self.binding._revoked(false, Some(self.binding_signature), self.time)
    }
}

