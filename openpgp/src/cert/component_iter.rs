use std::fmt;
use std::time::SystemTime;

use crate::{
    RevocationStatus,
    cert::{
        Cert,
        components::{
            ComponentBinding,
            ComponentBindingIter,
        },
        amalgamation::{
            ComponentAmalgamation,
            ValidComponentAmalgamation,
        },
    },
};

/// Returns a fresh iterator for the component bindings.
pub(crate) type IterFactory<C> =
    fn(&Cert) -> std::slice::Iter<ComponentBinding<C>>;

/// An iterator over all components in a certificate.
///
/// `ComponentIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` trait.
///
/// By default, `ComponentIter` returns all components without context.
pub struct ComponentIter<'a, C> {
    cert: &'a Cert,
    make_iter: IterFactory<C>,
    iter: ComponentBindingIter<'a, C>,
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

impl<'a, C> ComponentIter<'a, C>
    where C: Ord
{
    /// Returns a new `ComponentIter` instance.
    pub(crate) fn new(cert: &'a Cert, make_iter: IterFactory<C>) -> Self
        where Self: 'a
    {
        let iter = ComponentBindingIter { iter: Some(make_iter(cert)) };
        ComponentIter {
            cert, make_iter, iter,
        }
    }

    /// Changes the iterator to only return components that are valid at
    /// time `time`.
    ///
    /// If `time` is None, then the current time is used.
    ///
    /// See `ValidComponentIter` for the definition of a valid component.
    pub fn policy<T>(self, time: T) -> ValidComponentIter<'a, C>
        where T: Into<Option<SystemTime>>
    {
        ValidComponentIter {
            cert: self.cert,
            iter: self.iter,
            time: time.into().unwrap_or_else(SystemTime::now),
            revoked: None,
        }
    }

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
    pub fn primary<T>(self, time: T) -> Option<ValidComponentAmalgamation<'a, C>>
        where T: Into<Option<SystemTime>>
    {
        use std::cmp::Ordering;
        use std::time::{Duration, SystemTime};

        let t = time.into()
            .unwrap_or_else(SystemTime::now);
        (self.make_iter)(self.cert)
            // Filter out components that are not alive at time `t`.
            //
            // While we have the binding signature, extract a few
            // properties to avoid recomputing the same thing multiple
            // times.
            .filter_map(|c| {
                // No binding signature at time `t` => not alive.
                let sig = c.binding_signature(t)?;

                if !sig.signature_alive(t, Duration::new(0, 0)).is_ok() {
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
            .and_then(|c| ComponentAmalgamation::new(self.cert, (c.0).0)
                      .policy(t).ok())
    }

    /// Changes the iterator to return component bindings.
    ///
    /// A component binding is similar to a component amalgamation,
    /// but is not bound to a specific time.  It contains the
    /// component and all relevant signatures.
    pub fn bindings(self) -> ComponentBindingIter<'a, C> {
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
    iter: ComponentBindingIter<'a, C>,
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
            t!("Considering component: {:?}", ca.binding());

            let vca
                = if let Ok(vca) = ca.policy(self.time) {
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
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// # let timestamp = None;
    /// let non_revoked_uas = cert
    ///     .user_attributes()
    ///     .policy(timestamp)
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
    ///     .map(|ca| ca.binding())
    ///     .collect::<Vec<_>>();
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// As the example shows, this filter is significantly less
    /// flexible than using `ComponentAmalgamation::revoked`.  However, this
    /// filter implements a typical policy, and does not preclude
    /// using `filter` to realize alternative policies.
    pub fn revoked<T>(mut self, revoked: T) -> Self
        where T: Into<Option<bool>>
    {
        self.revoked = revoked.into();
        self
    }
}
