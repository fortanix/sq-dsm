//! Types for certificate components.

use std::cmp::Ordering;
use std::slice;
use std::time;

use crate::{
    RevocationStatus,
    packet::Signature,
    packet::Key,
    packet::key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    Packet,
    policy::Policy,
};
use crate::types::{
    RevocationType,
};

use super::{
    sig_cmp,
    canonical_signature_order,
};
pub use super::amalgamation::{
    Amalgamation,
    ComponentAmalgamation,
    ValidComponentAmalgamation,
};

/// A key (primary or subkey, public or private) and any associated
/// signatures.
pub type KeyBundle<KeyPart, KeyRole> = ComponentBundle<Key<KeyPart, KeyRole>>;

impl<K: key::KeyParts, R: key::KeyRole> KeyBundle<K, R>
{
    /// Gets the key packet's `SecretKeyMaterial`.
    ///
    /// Note: The key module installs conversion functions on
    /// KeyBundle.  They need to access the key's secret.
    pub(crate) fn secret(&self)
                         -> Option<&crate::packet::key::SecretKeyMaterial> {
        self.key().secret()
    }
}

/// A primary key and any associated signatures.
pub(crate) type PrimaryKeyBundle<KeyPart> =
    KeyBundle<KeyPart, key::PrimaryRole>;

/// A subkey and any associated signatures.
pub type SubkeyBundle<KeyPart> = KeyBundle<KeyPart, key::SubordinateRole>;

/// A key (primary or subkey, public or private) and any associated
/// signatures.
#[allow(dead_code)]
type GenericKeyBinding
    = ComponentBundle<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A User ID and any associated signatures.
pub type UserIDBundle = ComponentBundle<UserID>;

/// A User Attribute and any associated signatures.
pub type UserAttributeBundle = ComponentBundle<UserAttribute>;

/// An unknown component and any associated signatures.
///
/// Note: all signatures are stored as certifications.
pub type UnknownBundle = ComponentBundle<Unknown>;

/// A Cert component binding.
///
/// A Cert component is a primary key, a subkey, a user id, or a user
/// attribute.  A binding is a Cert component and any related
/// signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentBundle<C> {
    pub(crate) component: C,

    // Self signatures.
    pub(crate) self_signatures: Vec<Signature>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    pub(crate) certifications: Vec<Signature>,

    // Self revocations.
    pub(crate) self_revocations: Vec<Signature>,

    // Third-party revocations (e.g., designated revokers).
    pub(crate) other_revocations: Vec<Signature>,
}

impl<C> ComponentBundle<C> {
    /// Returns a reference to the component.
    pub fn component(&self) -> &C {
        &self.component
    }

    /// Returns a mutable reference to the component.
    fn component_mut(&mut self) -> &mut C {
        &mut self.component
    }

    /// Returns the active binding signature at time `t`.
    ///
    /// An active binding signature is a non-revoked, self-signature
    /// that is alive at time `t` (`creation time <= t`, `t <
    /// expiry`).
    ///
    /// This function returns None if there are no active binding
    /// signatures at time `t`.
    pub fn binding_signature<T>(&self, policy: &dyn Policy, t: T) -> Option<&Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(|| time::SystemTime::now());

        // Recall: the signatures are sorted by their creation time in
        // descending order, i.e., newest first.
        //
        // We want the newest signature that is older than t.  So,
        // search for `t`.

        let i =
            // Usually, the first signature is what we are looking for.
            // Short circuit the binary search.
            if Some(t) >= self.self_signatures.get(0)
                              .and_then(|s| s.signature_creation_time())
            {
                0
            } else {
                match self.self_signatures.binary_search_by(
                    |s| canonical_signature_order(
                        s.signature_creation_time(), Some(t)))
                {
                    // If there are multiple matches, then we need to search
                    // backwards to find the first one.  Consider:
                    //
                    //     t: 9 8 8 8 8 7
                    //     i: 0 1 2 3 4 5
                    //
                    // If we are looking for t == 8, then binary_search could
                    // return index 1, 2, 3 or 4.
                    Ok(mut i) => {
                        // XXX: we use PartialOrd to compare Tms due to
                        // https://github.com/rust-lang-deprecated/time/issues/180
                        while i > 0
                            && self.self_signatures[i - 1].signature_creation_time()
                            .cmp(&Some(t)) == Ordering::Equal
                        {
                            i -= 1;
                        }
                        i
                    }

                    // There was no match.  `i` is where a new element could
                    // be inserted while maintaining the sorted order.
                    // Consider:
                    //
                    //    t: 9 8 6 5
                    //    i: 0 1 2 3
                    //
                    // If we are looing for t == 7, then binary_search will
                    // return i == 2.  That's exactly where we should start
                    // looking.
                    Err(i) => i,
                }
            };

        self.self_signatures[i..].iter().filter(|s| {
            s.signature_alive(t, time::Duration::new(0, 0)).is_ok()
                && policy.signature(s).is_ok()
        }).nth(0)
    }

    /// The self-signatures.
    ///
    /// The signatures are validated, and they are reverse sorted by
    /// their creation time (newest first).
    pub fn self_signatures(&self) -> &[Signature] {
        &self.self_signatures
    }

    /// Any third-party certifications.
    ///
    /// The signatures are *not* validated.  They are reverse sorted by
    /// their creation time (newest first).
    pub fn certifications(&self) -> &[Signature] {
        &self.certifications
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations are validated, and they are reverse sorted by
    /// their creation time (newest first).
    pub fn self_revocations(&self) -> &[Signature] {
        &self.self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations are *not* validated.  They are reverse sorted
    /// by their creation time (newest first).
    pub fn other_revocations(&self) -> &[Signature] {
        &self.other_revocations
    }

    /// Returns the component's revocation status at time `t`.
    ///
    /// A component is considered to be revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`.
    ///
    ///   - `hard_revocations_are_final` is true, and there is a hard
    ///     revocation (even if it is not live at time `t`, and even
    ///     if there is a newer self-signature).
    ///
    /// selfsig must be the newest live self signature at time `t`.
    pub(crate) fn _revoked<'a, T>(&'a self, policy: &dyn Policy, t: T,
                                  hard_revocations_are_final: bool,
                                  selfsig: Option<&Signature>)
        -> RevocationStatus<'a>
        where T: Into<Option<time::SystemTime>>
    {
        // Fallback time.
        let time_zero = || time::UNIX_EPOCH;
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now());
        let selfsig_creation_time
            = selfsig.and_then(|s| s.signature_creation_time())
                     .unwrap_or_else(time_zero);

        tracer!(super::TRACE, "ComponentBundle::_revoked", 0);
        t!("hard_revocations_are_final: {}, selfsig: {:?}, t: {:?}",
           hard_revocations_are_final,
           selfsig_creation_time,
           t);
        if let Some(selfsig) = selfsig {
            assert!(
                selfsig.signature_alive(t, time::Duration::new(0, 0)).is_ok());
        }

        let check = |revs: &'a [Signature]| -> Option<Vec<&'a Signature>> {
            let revs = revs.iter().filter_map(|rev| {
                if hard_revocations_are_final
                    && rev.reason_for_revocation()
                    .map(|(r, _)| {
                        r.revocation_type() == RevocationType::Hard
                    })
                // If there is no Reason for Revocation
                // packet, assume that it is a hard
                // revocation.
                    .unwrap_or(true)
                {
                    t!("  got a hard revocation: {:?}, {:?}",
                       rev.signature_creation_time()
                       .unwrap_or_else(time_zero),
                       rev.reason_for_revocation()
                       .map(|r| (r.0, String::from_utf8_lossy(r.1))));
                    Some(rev)
                } else if selfsig_creation_time
                    > rev.signature_creation_time()
                    .unwrap_or_else(time_zero)
                {
                    t!("  ignoring out of date revocation ({:?})",
                       rev.signature_creation_time()
                       .unwrap_or_else(time_zero));
                    None
                } else if
                    ! rev.signature_alive(t, time::Duration::new(0, 0)).is_ok()
                {
                    t!("  ignoring revocation that is not alive ({:?} - {:?})",
                       rev.signature_creation_time()
                       .unwrap_or_else(time_zero),
                       rev.signature_expiration_time()
                       .unwrap_or_else(|| time::Duration::new(0, 0)));
                    None
                } else if let Err(err) = policy.signature(rev) {
                    t!("  revocation rejected by caller policy: {}", err);
                    None
                } else {
                    t!("  got a revocation: {:?} ({:?})",
                       rev.signature_creation_time()
                       .unwrap_or_else(time_zero),
                       rev.reason_for_revocation()
                       .map(|r| (r.0, String::from_utf8_lossy(r.1))));
                    Some(rev)
                }
            }).collect::<Vec<&Signature>>();

            if revs.len() == 0 {
                None
            } else {
                Some(revs)
            }
        };

        if let Some(revs) = check(&self.self_revocations) {
            RevocationStatus::Revoked(revs)
        } else if let Some(revs) = check(&self.other_revocations) {
            RevocationStatus::CouldBe(revs)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
    }

    /// Converts the component into an iterator over the contained
    /// packets.
    ///
    /// The signatures are ordered from authenticated and most
    /// important to not authenticated and most likely to be abused.
    /// The order is:
    ///
    ///   - Self revocations first.  They are authenticated and the
    ///     most important information.
    ///   - Self signatures.  They are authenticated.
    ///   - Other signatures.  They are not authenticated at this point.
    ///   - Other revocations.  They are not authenticated, and likely
    ///     not well supported in other implementations, hence the
    ///     least reliable way of revoking keys and therefore least
    ///     useful and most likely to be abused.
    pub(crate) fn into_packets<'a>(self) -> impl Iterator<Item=Packet>
        where Packet: From<C>
    {
        let p : Packet = self.component.into();
        std::iter::once(p)
            .chain(self.self_revocations.into_iter().map(|s| s.into()))
            .chain(self.self_signatures.into_iter().map(|s| s.into()))
            .chain(self.certifications.into_iter().map(|s| s.into()))
            .chain(self.other_revocations.into_iter().map(|s| s.into()))
    }

    // Sorts and dedups the binding's signatures.
    //
    // This function assumes that the signatures have already been
    // cryptographically checked.
    //
    // Note: this uses Signature::eq to compare signatures.  That
    // function ignores unhashed packets.  If there are two signatures
    // that only differ in their unhashed subpackets, they will be
    // deduped.  The unhashed areas are *not* merged; the one that is
    // kept is undefined.
    pub(crate) fn sort_and_dedup(&mut self)
    {
        self.self_signatures.sort_by(sig_cmp);
        self.self_signatures.dedup();

        // There is no need to sort the certifications, but we do
        // want to remove dups and sorting is a prerequisite.
        self.certifications.sort_by(sig_cmp);
        self.certifications.dedup();

        self.self_revocations.sort_by(sig_cmp);
        self.self_revocations.dedup();

        self.other_revocations.sort_by(sig_cmp);
        self.other_revocations.dedup();
    }
}

impl<P: key::KeyParts, R: key::KeyRole> ComponentBundle<Key<P, R>> {
    /// Returns a reference to the key.
    pub fn key(&self) -> &Key<P, R> {
        self.component()
    }

    /// Returns a mut reference to the key.
    pub(crate) fn key_mut(&mut self) -> &mut Key<P, R> {
        self.component_mut()
    }
}

impl<P: key::KeyParts> ComponentBundle<Key<P, key::SubordinateRole>> {
    /// Returns the subkey's revocation status at time `t`.
    ///
    /// A subkey is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    ///   - There is a hard revocation (even if it is not live at
    ///     time `t`, and even if there is a newer self-signature).
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this subkey is revoked; it
    /// does not imply anything about the Cert or other components.
    pub fn revoked<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self._revoked(policy, t, true, self.binding_signature(policy, t))
    }
}

impl ComponentBundle<UserID> {
    /// Returns a reference to the User ID.
    pub fn userid(&self) -> &UserID {
        self.component()
    }

    /// Returns the User ID's revocation status at time `t`.
    ///
    /// A User ID is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User ID is revoked; it
    /// does not imply anything about the Cert or other components.
    pub fn revoked<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self._revoked(policy, t, false, self.binding_signature(policy, t))
    }
}

impl ComponentBundle<UserAttribute> {
    /// Returns a reference to the User Attribute.
    pub fn user_attribute(&self) -> &UserAttribute {
        self.component()
    }

    /// Returns the User Attribute's revocation status at time `t`.
    ///
    /// A User Attribute is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User Attribute is revoked;
    /// it does not imply anything about the Cert or other components.
    pub fn revoked<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self._revoked(policy, t, false, self.binding_signature(policy, t))
    }
}

impl ComponentBundle<Unknown> {
    /// Returns a reference to the unknown component.
    pub fn unknown(&self) -> &Unknown {
        self.component()
    }
}

/// An iterator over `ComponentBundle`s.
pub struct ComponentBundleIter<'a, C> {
    pub(crate) iter: Option<slice::Iter<'a, ComponentBundle<C>>>,
}

/// An iterator over `KeyBundle`s.
pub type UnfilteredKeyBundleIter<'a, P, R> = ComponentBundleIter<'a, Key<P, R>>;
/// An iterator over `UserIDBundle`s.
pub type UserIDBundleIter<'a> = ComponentBundleIter<'a, UserID>;
/// An iterator over `UserAttributeBundle`s.
pub type UserAttributeBundleIter<'a> = ComponentBundleIter<'a, UserAttribute>;
/// An iterator over `UnknownBundle`s.
pub type UnknownBundleIter<'a> = ComponentBundleIter<'a, Unknown>;

impl<'a, C> Iterator for ComponentBundleIter<'a, C>
{
    type Item = &'a ComponentBundle<C>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter {
            Some(ref mut iter) => iter.next(),
            None => None,
        }
    }
}

impl<'a, C> ExactSizeIterator for ComponentBundleIter<'a, C>
{
    fn len(&self) -> usize {
        match self.iter {
            Some(ref iter) => iter.len(),
            None => 0,
        }
    }
}
