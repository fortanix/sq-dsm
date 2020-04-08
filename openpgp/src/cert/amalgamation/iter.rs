use std::slice;
use std::fmt;
use std::time::SystemTime;

use crate::{
    types::RevocationStatus,
    cert::prelude::*,
    packet::{
        Unknown,
        UserAttribute,
        UserID,
    },
    policy::Policy,
};

/// An iterator over all component bundles of a given type in a certificate.
///
/// `ComponentAmalgamationIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` trait.
///
/// By default, `ComponentAmalgamationIter` returns each component in turn.
pub struct ComponentAmalgamationIter<'a, C> {
    cert: &'a Cert,
    iter: slice::Iter<'a, ComponentBundle<C>>,
}

/// An iterator over `UserIDAmalgamtion`s.
///
/// This is just a specialized version of `ComponentAmalgamationIter`.
pub type UserIDAmalgamationIter<'a>
    = ComponentAmalgamationIter<'a, UserID>;

/// An iterator over `UserAttributeAmalgamtion`s.
///
/// This is just a specialized version of `ComponentAmalgamationIter`.
pub type UserAttributeAmalgamationIter<'a>
    = ComponentAmalgamationIter<'a, UserAttribute>;

/// An iterator over `UnknownComponentAmalgamtion`s.
///
/// This is just a specialized version of `ComponentAmalgamationIter`.
pub type UnknownComponentAmalgamationIter<'a>
    = ComponentAmalgamationIter<'a, Unknown>;


impl<'a, C> fmt::Debug for ComponentAmalgamationIter<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ComponentAmalgamationIter")
            .finish()
    }
}

impl<'a, C> Iterator for ComponentAmalgamationIter<'a, C>
{
    type Item = ComponentAmalgamation<'a, C>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|c| ComponentAmalgamation::new(self.cert, c))
    }
}

impl<'a, C> ComponentAmalgamationIter<'a, C> {
    /// Returns a new `ComponentAmalgamationIter` instance.
    pub(crate) fn new(cert: &'a Cert,
                      iter: std::slice::Iter<'a, ComponentBundle<C>>) -> Self
        where Self: 'a
    {
        ComponentAmalgamationIter {
            cert, iter,
        }
    }

    /// Changes the iterator to only return components that are valid
    /// for the given policy at the specified time.
    ///
    /// If `time` is None, then the current time is used.
    ///
    /// See `ValidComponentAmalgamationIter` for the definition of a valid component.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> ValidComponentAmalgamationIter<'a, C>
        where T: Into<Option<SystemTime>>
    {
        ValidComponentAmalgamationIter {
            cert: self.cert,
            iter: self.iter,
            time: time.into().unwrap_or_else(SystemTime::now),
            policy,
            revoked: None,
        }
    }
}

/// An iterator over all valid `Component`s of a given type in a
/// certificate.
///
/// A component is valid at time `t` if it was not created after `t`
/// and it has a live self-signature at time `t`.
///
/// `ValidComponentAmalgamationIter` follows the builder pattern.  There is no
/// need to explicitly finalize it, however: it already implements the
/// `Iterator` trait.
pub struct ValidComponentAmalgamationIter<'a, C> {
    // This is an option to make it easier to create an empty ValidComponentAmalgamationIter.
    cert: &'a Cert,
    iter: slice::Iter<'a, ComponentBundle<C>>,

    policy: &'a dyn Policy,
    // The time.
    time: SystemTime,

    // If not None, filters by whether the component is revoked or not
    // at time `t`.
    revoked: Option<bool>,
}

/// An iterator over `ValidUserIDAmalgamtion`s.
///
/// This is just a specialized version of `ValidComponentAmalgamationIter`.
pub type ValidUserIDAmalgamationIter<'a>
    = ValidComponentAmalgamationIter<'a, UserID>;

/// An iterator over `ValidUserAttributeAmalgamtion`s.
///
/// This is just a specialized version of `ValidComponentAmalgamationIter`.
pub type ValidUserAttributeAmalgamationIter<'a>
    = ValidComponentAmalgamationIter<'a, UserAttribute>;

/// An iterator over `ValidUnknownComponentAmalgamtion`s.
///
/// This is just a specialized version of `ValidComponentAmalgamationIter`.
pub type ValidUnknownComponentAmalgamationIter<'a>
    = ValidComponentAmalgamationIter<'a, Unknown>;


impl<'a, C> fmt::Debug for ValidComponentAmalgamationIter<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ValidComponentAmalgamationIter")
            .field("time", &self.time)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl<'a, C> Iterator for ValidComponentAmalgamationIter<'a, C>
    where C: std::fmt::Debug
{
    type Item = ValidComponentAmalgamation<'a, C>;

    fn next(&mut self) -> Option<Self::Item> {
        tracer!(false, "ValidComponentAmalgamationIter::next", 0);
        t!("ValidComponentAmalgamationIter: {:?}", self);

        loop {
            let ca = ComponentAmalgamation::new(self.cert, self.iter.next()?);
            t!("Considering component: {:?}", ca.component());

            let vca = match ca.with_policy(self.policy, self.time) {
                Ok(vca) => vca,
                Err(e) => {
                    t!("Rejected: {}", e);
                    continue;
                },
            };

            if let Some(want_revoked) = self.revoked {
                if let RevocationStatus::Revoked(_) = vca.revoked() {
                    // The component is definitely revoked.
                    if ! want_revoked {
                        t!("Component revoked... skipping.");
                        continue;
                    }
                } else {
                    // The component is probably not revoked.
                    if want_revoked {
                        t!("Component not revoked... skipping.");
                        continue;
                    }
                }
            }

            return Some(vca);
        }
    }
}

impl<'a, C> ExactSizeIterator for ComponentAmalgamationIter<'a, C>
{
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<'a, C> ValidComponentAmalgamationIter<'a, C> {
    /// Filters by whether a component is definitely revoked.
    ///
    /// A value of None disables this filter.
    ///
    /// Note: If you call this function multiple times on the same
    /// iterator, only the last value is used.
    ///
    /// Note: This only checks if the component is not revoked; it does not
    /// check whether the certificate not revoked.
    ///
    /// This filter checks whether a component's revocation status is
    /// `RevocationStatus::Revoked` or not.  The latter (i.e.,
    /// `revoked(false)`) is equivalent to:
    ///
    /// ```rust
    /// extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::types::RevocationStatus;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #     .generate()?;
    /// # let timestamp = None;
    /// let non_revoked_uas = cert
    ///     .user_attributes()
    ///     .with_policy(p, timestamp)
    ///     .filter(|ca| {
    ///         match ca.revoked() {
    ///             RevocationStatus::Revoked(_) =>
    ///                 // It's definitely revoked, skip it.
    ///                 false,
    ///             RevocationStatus::CouldBe(_) =>
    ///                 // There is a designated revoker that we
    ///                 // should check, but don't (or can't).  To
    ///                 // avoid a denial of service arising from fake
    ///                 // revocations, we assume that the component has not
    ///                 // been revoked and return it.
    ///                 true,
    ///             RevocationStatus::NotAsFarAsWeKnow =>
    ///                 // We have no evidence to suggest that the component
    ///                 // is revoked.
    ///                 true,
    ///         }
    ///     })
    ///     .collect::<Vec<_>>();
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// As the example shows, this filter is significantly less
    /// flexible than using `ValidComponentAmalgamation::revoked`.
    /// However, this filter implements a typical policy, and does not
    /// preclude using `filter` to realize alternative policies.
    pub fn revoked<T>(mut self, revoked: T) -> Self
        where T: Into<Option<bool>>
    {
        self.revoked = revoked.into();
        self
    }
}
