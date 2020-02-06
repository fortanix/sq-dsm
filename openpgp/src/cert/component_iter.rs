use std::fmt;
use std::time::SystemTime;

use crate::{
    RevocationStatus,
    cert::{
        Cert,
        components::{
            ComponentBundle,
            ComponentBundleIter,
            Amalgamation,
            ComponentAmalgamation,
            ValidComponentAmalgamation,
        },
    },
    policy::Policy,
};

/// An iterator over all components in a certificate.
///
/// `ComponentIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` trait.
///
/// By default, `ComponentIter` returns all components without context.
pub struct ComponentIter<'a, C> {
    cert: &'a Cert,
    iter: ComponentBundleIter<'a, C>,
}

impl<'a, C> fmt::Debug for ComponentIter<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ComponentIter")
            .finish()
    }
}

impl<'a, C> Iterator for ComponentIter<'a, C> {
    type Item = ComponentAmalgamation<'a, C>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|c| ComponentAmalgamation::new(self.cert, c))
    }
}

impl<'a, C> ComponentIter<'a, C> {
    /// Returns a new `ComponentIter` instance.
    pub(crate) fn new(cert: &'a Cert,
                      iter: std::slice::Iter<'a, ComponentBundle<C>>) -> Self
        where Self: 'a
    {
        ComponentIter {
            cert, iter: ComponentBundleIter { iter: Some(iter), },
        }
    }

    /// Changes the iterator to only return components that are valid at
    /// time `time`.
    ///
    /// If `time` is None, then the current time is used.
    ///
    /// See `ValidComponentIter` for the definition of a valid component.
    pub fn set_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> ValidComponentIter<'a, C>
        where T: Into<Option<SystemTime>>
    {
        ValidComponentIter {
            cert: self.cert,
            iter: self.iter,
            time: time.into().unwrap_or_else(SystemTime::now),
            policy: policy,
            revoked: None,
        }
    }

    /// Changes the iterator to return component bindings.
    ///
    /// A component binding is similar to a component amalgamation,
    /// but is not bound to a specific time.  It contains the
    /// component and all relevant signatures.
    pub fn bundles(self) -> ComponentBundleIter<'a, C> {
        self.iter
    }
}

/// An iterator over all valid `Component`s in a certificate.
///
/// A component is valid at time `t` if it was not created after `t`
/// and it has a live self-signature at time `t`.
///
/// `ValidComponentIter` follows the builder pattern.  There is no
/// need to explicitly finalize it, however: it already implements the
/// `Iterator` trait.
pub struct ValidComponentIter<'a, C> {
    // This is an option to make it easier to create an empty ValidComponentIter.
    cert: &'a Cert,
    iter: ComponentBundleIter<'a, C>,

    policy: &'a dyn Policy,
    // The time.
    time: SystemTime,

    // If not None, filters by whether the component is revoked or not
    // at time `t`.
    revoked: Option<bool>,
}

impl<'a, C> fmt::Debug for ValidComponentIter<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ValidComponentIter")
            .field("time", &self.time)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl<'a, C> Iterator for ValidComponentIter<'a, C>
    where C: std::fmt::Debug
{
    type Item = ValidComponentAmalgamation<'a, C>;

    fn next(&mut self) -> Option<Self::Item> {
        tracer!(false, "ValidComponentIter::next", 0);
        t!("ValidComponentIter: {:?}", self);

        loop {
            let ca = ComponentAmalgamation::new(self.cert, self.iter.next()?);
            t!("Considering component: {:?}", ca.bundle());

            let vca
                = if let Ok(vca) = ca.set_policy(self.policy, self.time) {
                    vca
                } else {
                    t!("No self-signature at time {:?}", self.time);
                    continue;
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

impl<'a, C> ExactSizeIterator for ComponentIter<'a, C> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<'a, C> ValidComponentIter<'a, C> {
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
    /// # use openpgp::cert::CertBuilder;
    /// use openpgp::RevocationStatus;
    /// use openpgp::cert::components::Amalgamation;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// # let timestamp = None;
    /// let non_revoked_uas = cert
    ///     .user_attributes()
    ///     .set_policy(p, timestamp)
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
    ///     .map(|ca| ca.bundle())
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
