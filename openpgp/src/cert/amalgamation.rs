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

impl<'a, C> ValidComponentAmalgamation<'a, C> {
    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a component is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidComponentAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    pub fn time(&self) -> SystemTime {
        self.time
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn policy<T>(self, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.a.policy(time)
    }

    /// Returns the component's binding signature as of the reference time,
    /// if any.
    pub fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn revoked(&self) -> RevocationStatus<'a> {
        self.binding._revoked(false, Some(self.binding_signature), self.time)
    }

    /// Returns the certificate's revocation status as of the
    /// amalgamtion's reference time.
    pub fn cert_revoked(&self) -> RevocationStatus<'a> {
        self.cert().revoked(self.time())
    }

    /// Returns whether the certificateis alive as of the
    /// amalgamtion's reference time.
    pub fn cert_alive(&self) -> Result<()> {
        self.cert().alive(self.time())
    }

    /// Returns this component's component binding.
    pub fn binding(&self) -> &'a ComponentBinding<C> {
        &self.binding
    }
}
