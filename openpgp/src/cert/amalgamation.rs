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
    time: SystemTime,
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Creates a new amalgamation.
    pub(crate) fn new<T>(cert: &'a Cert, binding: &'a ComponentBinding<C>,
                         time: T) -> Self
        where T: Into<Option<time::SystemTime>>
    {
        Self {
            cert,
            binding,
            time: time.into().unwrap_or_else(SystemTime::now),
        }
    }

    /// Returns the certificate that the component came from.
    pub fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a component is
    /// created at `t_c` and expires at `t_e`, then
    /// `ComponentAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    pub fn time(&self) -> SystemTime {
        self.time
    }

    /// Changes the amalgamation's reference time.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn set_time<T>(mut self, time: T) -> Self
        where T: Into<Option<time::SystemTime>>
    {
        self.time = time.into().unwrap_or_else(SystemTime::now);
        self
    }

    /// Returns the component's binding signature as of the reference time,
    /// if any.
    pub fn binding_signature(&self) -> Option<&'a Signature> {
        self.binding.binding_signature(self.time)
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn revoked(&self) -> RevocationStatus<'a> {
        self.binding._revoked(false, self.binding_signature(), self.time)
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

    /// Returns whether the component is alive as of the amalgamtion's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn alive(&self) -> Result<()> {
        if self.binding_signature().is_some() {
            Ok(())
        } else {
            Err(Error::NoBindingSignature(self.time()).into())
        }
    }

    /// Returns this component's component binding.
    pub fn component_binding(&self) -> &'a ComponentBinding<C> {
        &self.binding
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserID> {
    /// Returns a reference to the User ID.
    pub fn userid(&self) -> &crate::packet::UserID {
        self.component_binding().userid()
    }
}

impl<'a> ComponentAmalgamation<'a, crate::packet::UserAttribute> {
    /// Returns a reference to the User Attribute.
    pub fn user_attribute(&self) -> &crate::packet::UserAttribute {
        self.component_binding().user_attribute()
    }
}
