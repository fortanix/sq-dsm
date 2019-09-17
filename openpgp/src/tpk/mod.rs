//! Transferable public keys.

use std::io;
use std::cmp;
use std::cmp::Ordering;
use std::path::Path;
use std::slice;
use std::mem;
use std::fmt;
use std::ops::{Deref, DerefMut};

use time;

use crate::{
    crypto::{hash::Hash, Signer},
    Error,
    Result,
    RevocationStatus,
    SignatureType,
    HashAlgorithm,
    packet,
    packet::Signature,
    packet::signature,
    packet::Key,
    packet::key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    Packet,
    PacketPile,
    KeyID,
    Fingerprint,
};
use crate::parse::{Parse, PacketParserResult, PacketParser};
use crate::constants::{
    ReasonForRevocation,
    RevocationType,
};

mod builder;
mod bindings;
mod keyiter;
mod parser;

pub use self::builder::{TPKBuilder, CipherSuite};

pub use keyiter::KeyIter;

pub use parser::{
    KeyringValidity,
    KeyringValidator,
    TPKParser,
    TPKValidity,
    TPKValidator,
};

const TRACE : bool = false;

// Helper functions.

/// Compare the creation time of two signatures.  Order them so that
/// the more recent signature is first.
fn canonical_signature_order(a: Option<time::Tm>, b: Option<time::Tm>)
                             -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(ref a), Some(ref b)) => a.cmp(b),
    }
}

fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
    match canonical_signature_order(a.signature_creation_time(),
                                    b.signature_creation_time()) {
        Ordering::Equal => a.mpis().cmp(b.mpis()),
        r => r
    }
}

/// A key (primary or subkey, public or private) and any associated
/// signatures.
pub type KeyBinding<KeyPart, KeyRole> = ComponentBinding<Key<KeyPart, KeyRole>>;

/// A primary key and any associated signatures.
pub type PrimaryKeyBinding<KeyPart> = KeyBinding<KeyPart, key::PrimaryRole>;

/// A subkey and any associated signatures.
pub type SubkeyBinding<KeyPart> = KeyBinding<KeyPart, key::SubordinateRole>;

/// A key (primary or subkey, public or private) and any associated
/// signatures.
pub type GenericKeyBinding
    = ComponentBinding<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A User ID and any associated signatures.
pub type UserIDBinding = ComponentBinding<UserID>;

/// A User Attribute and any associated signatures.
pub type UserAttributeBinding = ComponentBinding<UserAttribute>;

/// An unknown component and any associated signatures.
///
/// Note: all signatures are stored as certifications.
pub type UnknownBinding = ComponentBinding<Unknown>;

/// A TPK component binding.
///
/// A TPK component is a primary key, a subkey, a user id, or a user
/// attribute.  A binding is a TPK component and any related
/// signatures.
#[derive(Debug, Clone)]
pub struct ComponentBinding<C> {
    component: C,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    certifications: Vec<Signature>,

    // Self revocations.
    self_revocations: Vec<Signature>,

    // Third-party revocations (e.g., designated revokers).
    other_revocations: Vec<Signature>,
}

impl<C> ComponentBinding<C> {
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
    /// that is alive at time `t` (`creation time <= t`, `t <=
    /// expiry`).
    ///
    /// This function returns None if there are no active binding
    /// signatures at time `t`.
    pub fn binding_signature<T>(&self, t: T) -> Option<&Signature>
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        let time_zero = time::at_utc(time::Timespec::new(0, 0));

        self.selfsigs.iter().filter(|s| {
            s.signature_alive_at(t)
        }).max_by(|a, b| {
            a.signature_creation_time().unwrap_or(time_zero).cmp(
                &b.signature_creation_time().unwrap_or(time_zero))
        })
    }

    /// The self-signatures.
    ///
    /// All self-signatures have been validated, and the newest
    /// self-signature is last.
    pub fn selfsigs(&self) -> &[Signature] {
        &self.selfsigs
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> &[Signature] {
        &self.certifications
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations have been validated, and the newest is last.
    pub fn self_revocations(&self) -> &[Signature] {
        &self.self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations have *not* been validated.
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
    fn _revoked<'a, T>(&'a self, hard_revocations_are_final: bool,
                       selfsig: Option<&Signature>, t: T)
        -> RevocationStatus<'a>
        where T: Into<Option<time::Tm>>
    {
        // Fallback time.
        let time_zero = || time::at_utc(time::Timespec::new(0, 0));
        let t = t.into().unwrap_or_else(time::now_utc);
        let selfsig_creation_time
            = selfsig.and_then(|s| s.signature_creation_time())
                     .unwrap_or_else(time_zero);

        tracer!(TRACE, "ComponentBinding::_revoked", 0);
        t!("hard_revocations_are_final: {}, selfsig: {}, t: {}",
           hard_revocations_are_final,
           selfsig_creation_time.rfc822(),
           t.rfc822());
        if let Some(selfsig) = selfsig {
            assert!(selfsig.signature_alive_at(t));
        }

        macro_rules! check {
            ($revs:expr) => ({
                let revs = $revs.iter().filter_map(|rev| {
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
                        t!("  got a hard revocation: {}, {:?}",
                           rev.signature_creation_time()
                               .unwrap_or_else(time_zero).rfc822(),
                           rev.reason_for_revocation()
                               .map(|r| (r.0, String::from_utf8_lossy(r.1))));
                        Some(rev)
                    } else if selfsig_creation_time
                              > rev.signature_creation_time()
                                    .unwrap_or_else(time_zero)
                    {
                        t!("  ignoring out of date revocation ({})",
                           rev.signature_creation_time()
                               .unwrap_or_else(time_zero).rfc822());
                        None
                    } else if !rev.signature_alive_at(t) {
                        t!("  ignoring revocation that is not alive ({} - {})",
                           rev.signature_creation_time()
                               .unwrap_or_else(time_zero).rfc822(),
                           rev.signature_expiration_time()
                               .unwrap_or_else(time::Duration::zero));
                        None
                    } else {
                        t!("  got a revocation: {} ({:?})",
                           rev.signature_creation_time()
                               .unwrap_or_else(time_zero).rfc822(),
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
            })
        }

        if let Some(revs) = check!(&self.self_revocations) {
            RevocationStatus::Revoked(revs)
        } else if let Some(revs) = check!(&self.other_revocations) {
            RevocationStatus::CouldBe(revs)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
    }

    // Converts the component into an iterator over the contained
    // packets.
    fn into_packets<'a>(self) -> impl Iterator<Item=Packet>
        where Packet: From<C>
    {
        let p : Packet = self.component.into();
        std::iter::once(p)
            .chain(self.selfsigs.into_iter().map(|s| s.into()))
            .chain(self.certifications.into_iter().map(|s| s.into()))
            .chain(self.self_revocations.into_iter().map(|s| s.into()))
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
    fn sort_and_dedup(&mut self)
    {
        self.selfsigs.sort_by(sig_cmp);
        self.selfsigs.dedup();

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

impl<P: key::KeyParts, R: key::KeyRole> ComponentBinding<Key<P, R>> {
    /// Returns a reference to the key.
    pub fn key(&self) -> &Key<P, R> {
        self.component()
    }

    /// Returns a mut reference to the key.
    fn key_mut(&mut self) -> &mut Key<P, R> {
        self.component_mut()
    }
}

impl<P: key::KeyParts> ComponentBinding<Key<P, key::SubordinateRole>> {
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
    /// Note: TPKs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this subkey is revoked; it
    /// does not imply anything about the TPK or other components.
    pub fn revoked<T>(&self, t: T)
        -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into();
        self._revoked(true, self.binding_signature(t), t)
    }
}

impl ComponentBinding<UserID> {
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
    /// Note: TPKs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User ID is revoked; it
    /// does not imply anything about the TPK or other components.
    pub fn revoked<T>(&self, t: T)
        -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into();
        self._revoked(false, self.binding_signature(t), t)
    }
}

impl ComponentBinding<UserAttribute> {
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
    /// Note: TPKs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User Attribute is revoked;
    /// it does not imply anything about the TPK or other components.
    pub fn revoked<T>(&self, t: T)
        -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into();
        self._revoked(false, self.binding_signature(t), t)
    }
}

impl ComponentBinding<Unknown> {
    /// Returns a reference to the unknown component.
    pub fn unknown(&self) -> &Unknown {
        self.component()
    }
}

// Order by:
//
//  - Whether the User IDs are marked as primary.
//
//  - The timestamp (reversed).
//
//  - The User IDs' lexographical order.
//
// Note: Comparing the lexographical order of the serialized form
// is useless since that will be the same as the User IDs'
// lexographical order.
impl PartialOrd for UserIDBinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UserIDBinding {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl Eq for UserIDBinding {
}

impl Ord for UserIDBinding {
    fn cmp(&self, b: &UserIDBinding) -> Ordering {
        // Fallback time.
        let time_zero = time::at_utc(time::Timespec::new(0, 0));


        // Compare their revocation status.  Components known to be
        // revoked come last.
        let a_revoked = self.self_revocations.len() > 0;
        let b_revoked = b.self_revocations.len() > 0;

        if a_revoked && ! b_revoked {
            return Ordering::Greater;
        }
        if ! a_revoked && b_revoked {
            return Ordering::Less;
        }

        let a_selfsig = self.binding_signature(None);
        let b_selfsig = b.binding_signature(None);

        if a_revoked && b_revoked {
            // Both are revoked.

            // Sort user ids that have at least one self signature
            // towards the front.
            if a_selfsig.is_some() && b_selfsig.is_none() {
                return Ordering::Less;
            }
            if a_selfsig.is_none() && b_selfsig.is_some() {
                return Ordering::Greater;
            }

            // Sort by reversed revocation time (i.e., most
            // recently revoked user id first).
            let cmp = b.self_revocations[0].signature_creation_time().cmp(
                &self.self_revocations[0].signature_creation_time());
            if cmp != Ordering::Equal {
                return cmp;
            }

            // They were revoked at the same time.  This is
            // unlikely.  We just need to do something
            // deterministic.
        }

        // Compare their primary status.
        let a_primary =
            a_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);
        let b_primary =
            b_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);

        if a_primary.is_some() && b_primary.is_none() {
            return Ordering::Less;
        } else if a_primary.is_none() && b_primary.is_some() {
            return Ordering::Greater;
        } else if a_primary.is_some() && b_primary.is_some() {
            // Both are marked as primary.  Fallback to the date.
            let mut a_timestamp = time_zero;
            if let Some(sig) = a_selfsig {
                if let Some(ts) = sig.signature_creation_time() {
                    a_timestamp = ts;
                }
            }
            let mut b_timestamp = time_zero;
            if let Some(sig) = a_selfsig {
                if let Some(ts) = sig.signature_creation_time() {
                    b_timestamp = ts;
                }
            }

            // We want the more recent date first.
            let cmp = b_timestamp.cmp(&a_timestamp);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // Fallback to a lexicographical comparison.
        self.userid().value().cmp(&b.userid().value())
    }
}

impl PartialOrd for UserAttributeBinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UserAttributeBinding {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl Eq for UserAttributeBinding {
}

impl Ord for UserAttributeBinding {
    fn cmp(&self, b: &UserAttributeBinding) -> Ordering {
        // Fallback time.
        let time_zero = time::at_utc(time::Timespec::new(0, 0));


        // Compare their revocation status.  Components known be
        // revoked come last.
        let a_revoked = self.self_revocations.len() > 0;
        let b_revoked = b.self_revocations.len() > 0;

        if a_revoked && ! b_revoked {
            return Ordering::Greater;
        }
        if ! a_revoked && b_revoked {
            return Ordering::Less;
        }

        let a_selfsig = self.binding_signature(None);
        let b_selfsig = b.binding_signature(None);

        if a_revoked && b_revoked {
            // Both are revoked.

            // Sort user attributes that have at least one self
            // signature towards the front.
            if a_selfsig.is_some() && b_selfsig.is_none() {
                return Ordering::Less;
            }
            if a_selfsig.is_none() && b_selfsig.is_some() {
                return Ordering::Greater;
            }

            // Sort by reversed revocation time (i.e., most
            // recently revoked user attribute first).
            let cmp = b.self_revocations[0].signature_creation_time().cmp(
                &self.self_revocations[0].signature_creation_time());
            if cmp != Ordering::Equal {
                return cmp;
            }

            // They were revoked at the same time.  This is
            // unlikely.  We just need to do something
            // deterministic.
        }

        // Compare their primary status.
        let a_primary =
            a_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);
        let b_primary =
            b_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);

        if a_primary.is_some() && b_primary.is_none() {
            return Ordering::Less;
        } else if a_primary.is_none() && b_primary.is_some() {
            return Ordering::Greater;
        } else if a_primary.is_some() && b_primary.is_some() {
            // Both are marked as primary.  Fallback to the date.
            let mut a_timestamp = time_zero;
            if let Some(sig) = a_selfsig {
                if let Some(ts) = sig.signature_creation_time() {
                    a_timestamp = ts;
                }
            }
            let mut b_timestamp = time_zero;
            if let Some(sig) = a_selfsig {
                if let Some(ts) = sig.signature_creation_time() {
                    b_timestamp = ts;
                }
            }

            // We want the more recent date first.
            let cmp = b_timestamp.cmp(&a_timestamp);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        // Fallback to a lexicographical comparison.
        self.user_attribute().value()
            .cmp(&b.user_attribute().value())
    }
}


impl<P, R> PartialOrd for KeyBinding<P, R>
    where P: key::KeyParts, R: key::KeyRole
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, R> PartialEq for KeyBinding<P, R>
    where P: key::KeyParts, R: key::KeyRole
{
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl<P, R> Eq for KeyBinding<P, R>
    where P: key::KeyParts, R: key::KeyRole
{
}

impl<P, R> Ord for KeyBinding<P, R>
    where P: key::KeyParts, R: key::KeyRole
{
    fn cmp(&self, b: &KeyBinding<P, R>) -> Ordering {
        // Compare their revocation status.  Components known to be
        // revoked come last.
        let a_revoked = self.self_revocations.len() > 0;
        let b_revoked = b.self_revocations.len() > 0;

        if a_revoked && ! b_revoked {
            return Ordering::Greater;
        }
        if ! a_revoked && b_revoked {
            return Ordering::Less;
        }

        let a_selfsig = self.binding_signature(None);
        let b_selfsig = b.binding_signature(None);

        if a_revoked && b_revoked {
            // Both are revoked.

            // Sort keys that have at least one self signature
            // towards the front.
            if a_selfsig.is_some() && b_selfsig.is_none() {
                return Ordering::Less;
            }
            if a_selfsig.is_none() && b_selfsig.is_some() {
                return Ordering::Greater;
            }

            // Sort by reversed revocation time (i.e., most
            // recently revoked key first).
            let cmp = b.self_revocations[0].signature_creation_time().cmp(
                &self.self_revocations[0].signature_creation_time());
            if cmp != Ordering::Equal {
                return cmp;
            }

            // They were revoked at the same time.  This is
            // unlikely.  We just need to do something
            // deterministic.
        }

        // Features.
        let a_features =
            a_selfsig.map(|sig| sig.features()).unwrap_or(Default::default());
        let b_features =
            b_selfsig.map(|sig| sig.features()).unwrap_or(Default::default());

        let cmp = a_features.as_vec().cmp(&b_features.as_vec());
        if cmp != Ordering::Equal {
            return cmp;
        }

        // Creation time (more recent first).
        let cmp = b.key().creation_time().cmp(&self.key().creation_time());
        if cmp != Ordering::Equal {
            return cmp;
        }

        // Fallback to the lexicographical comparison.
        self.key().mpis().cmp(&b.key().mpis())
    }
}


impl PartialOrd for UnknownBinding
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UnknownBinding
{
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl Eq for UnknownBinding
{
}

impl Ord for UnknownBinding
{
    fn cmp(&self, b: &Self) -> Ordering {
        self.component.cmp(&b.component)
    }
}



impl fmt::Display for TPK {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.primary().key().fingerprint())
    }
}

/// An iterator over `ComponentBinding`s.
pub struct ComponentBindingIter<'a, C> {
    iter: Option<slice::Iter<'a, ComponentBinding<C>>>,
}

/// An iterator over `KeyBinding`s.
pub type KeyBindingIter<'a, P, R> = ComponentBindingIter<'a, Key<P, R>>;
/// An iterator over `UserIDBinding`s.
pub type UserIDBindingIter<'a> = ComponentBindingIter<'a, UserID>;
/// An iterator over `UserAttributeBinding`s.
pub type UserAttributeBindingIter<'a> = ComponentBindingIter<'a, UserAttribute>;
/// An iterator over `UnknownBinding`s.
pub type UnknownBindingIter<'a> = ComponentBindingIter<'a, Unknown>;

impl<'a, C> Iterator for ComponentBindingIter<'a, C>
{
    type Item = &'a ComponentBinding<C>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter {
            Some(ref mut iter) => iter.next(),
            None => None,
        }
    }
}

impl<'a, C> ExactSizeIterator for ComponentBindingIter<'a, C>
{
    fn len(&self) -> usize {
        match self.iter {
            Some(ref iter) => iter.len(),
            None => 0,
        }
    }
}

/// A collection of `ComponentBindings`.
///
/// Note: we need this, because we can't `impl Vec<ComponentBindings>`.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    bindings: Vec<ComponentBinding<C>>,
}

impl<C> Deref for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    type Target = Vec<ComponentBinding<C>>;

    fn deref(&self) -> &Self::Target {
        &self.bindings
    }
}

impl<C> DerefMut for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn deref_mut(&mut self) -> &mut Vec<ComponentBinding<C>> {
        &mut self.bindings
    }
}

impl<C> Into<Vec<ComponentBinding<C>>> for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn into(self) -> Vec<ComponentBinding<C>> {
        self.bindings
    }
}

impl<C> IntoIterator for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    type Item = ComponentBinding<C>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bindings.into_iter()
    }
}

impl<C> ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn new() -> Self {
        Self { bindings: vec![] }
    }
}

impl<C> ComponentBindings<C>
    where ComponentBinding<C>: cmp::Ord
{
    // Sort and dedup the components.
    //
    // `cmp` is a function to sort the components for deduping.
    //
    // `merge` is a function that merges the first component into the
    // second component.
    fn sort_and_dedup<F, F2>(&mut self, cmp: F, merge: F2)
        where F: Fn(&C, &C) -> Ordering,
              F2: Fn(&mut C, &mut C)
    {
        // We dedup by component (not bindings!).  To do this, we need
        // to sort the bindings by the component.

        self.bindings.sort_unstable_by(
            |a, b| cmp(&a.component, &b.component));

        self.bindings.dedup_by(|a, b| {
            if cmp(&a.component, &b.component) == Ordering::Equal {
                // Merge.
                merge(&mut a.component, &mut b.component);

                // Recall: if a and b are equal, a will be dropped.
                b.selfsigs.append(&mut a.selfsigs);
                b.certifications.append(&mut a.certifications);
                b.self_revocations.append(&mut a.self_revocations);
                b.other_revocations.append(&mut a.self_revocations);

                true
            } else {
                false
            }
        });

        // And sort the certificates.
        for b in self.bindings.iter_mut() {
            b.sort_and_dedup();
        }

        // Now, resort the bindings.  When sorting by bindings, we also
        // consider the information on the current self signature.
        self.sort_unstable();
    }
}

/// A vecor of key (primary or subkey, public or private) and any
/// associated signatures.
pub type KeyBindings<KeyPart, KeyRole> = ComponentBindings<Key<KeyPart, KeyRole>>;

/// A vector of subkeys and any associated signatures.
pub type SubkeyBindings<KeyPart> = KeyBindings<KeyPart, key::SubordinateRole>;

/// A vector of key (primary or subkey, public or private) and any
/// associated signatures.
pub type GenericKeyBindings
    = ComponentBindings<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A vector of User ID bindings and any associated signatures.
pub type UserIDBindings = ComponentBindings<UserID>;

/// A vector of User Attribute bindings and any associated signatures.
pub type UserAttributeBindings = ComponentBindings<UserAttribute>;

/// A vector of unknown components and any associated signatures.
///
/// Note: all signatures are stored as certifications.
pub type UnknownBindings = ComponentBindings<Unknown>;


/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// TPKs are always canonicalized in the sense that only elements
/// (user id, user attribute, subkey) with at least one valid
/// self-signature are preserved.  Also, invalid self-signatures are
/// dropped.  The self-signatures are sorted so that the newest
/// self-signature comes first.  User IDs are sorted so that the first
/// `UserID` is the primary User ID.  Third-party certifications are
/// *not* validated, as the keys are not available; they are simply
/// passed through as is.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
///
/// # Secret keys
///
/// Any key in a `TPK` may have a secret key attached to it.  To
/// protect secret keys from being leaked, secret keys are not written
/// out if a `TPK` is serialized.  To also serialize the secret keys,
/// you need to use [`TPK::as_tsk()`] to get an object that writes
/// them out during serialization.
///
/// [`TPK::as_tsk()`]: #method.as_tsk
///
/// # Example
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::TPK;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(&b""[..])?;
/// match TPK::from_packet_parser(ppr) {
///     Ok(tpk) => {
///         println!("Key: {}", tpk.primary().key());
///         for binding in tpk.userids() {
///             println!("User ID: {}", binding.userid());
///         }
///     }
///     Err(err) => {
///         eprintln!("Error parsing TPK: {}", err);
///     }
/// }
///
/// #     Ok(())
/// # }
#[derive(Debug, Clone, PartialEq)]
pub struct TPK {
    primary: PrimaryKeyBinding<key::PublicParts>,

    userids: UserIDBindings,
    user_attributes: UserAttributeBindings,
    subkeys: SubkeyBindings<key::PublicParts>,

    // Unknown components, e.g., some UserAttribute++ packet from the
    // future.
    unknowns: UnknownBindings,
    // Signatures that we couldn't find a place for.
    bad: Vec<packet::Signature>,
}

impl std::str::FromStr for TPK {
    type Err = failure::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl<'a> Parse<'a, TPK> for TPK {
    /// Returns the first TPK encountered in the reader.
    fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_reader(reader)?)
    }

    /// Returns the first TPK encountered in the file.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_file(path)?)
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP-encoded message.
    fn from_bytes(buf: &[u8]) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_bytes(buf)?)
    }
}

impl TPK {
    /// Returns a reference to the primary key binding.
    ///
    /// Note: information about the primary key is often stored on the
    /// primary User ID's self signature.  Since these signatures are
    /// associated with the UserID and not the primary key, that
    /// information is not contained in the key binding.  Instead, you
    /// should use methods like `TPK::primary_key_signature()` to get
    /// information about the primary key.
    pub fn primary(&self) -> &PrimaryKeyBinding<key::PublicParts> {
        &self.primary
    }

    /// Returns the binding for the primary User ID at time `t`.
    ///
    /// See `TPK::primary_userid_full` for a description of how the
    /// primary user id is determined.
    pub fn primary_userid<T>(&self, t: T) -> Option<&UserIDBinding>
        where T: Into<Option<time::Tm>>
    {
        self.primary_userid_full(t).map(|r| r.0)
    }

    /// Returns the binding for the primary User ID at time `t` and
    /// some associated data.
    ///
    /// In addition to the User ID binding, this also returns the
    /// binding signature and the User ID's `RevocationStatus` at time
    /// `t`.
    ///
    /// The primary User ID is determined by taking the User IDs that
    /// are alive at time `t`, and sorting them as follows:
    ///
    ///   - non-revoked first
    ///   - primary first
    ///   - signature creation first
    ///
    /// If there is more than one, than one is selected in a
    /// deterministic, but undefined manner.
    pub fn primary_userid_full<T>(&self, t: T)
        -> Option<(&UserIDBinding, &Signature, RevocationStatus)>
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        self.userids()
            // Filter out User IDs that are not alive at time `t`.
            //
            // While we have the binding signature, extract a few
            // properties to avoid recomputing the same thing multiple
            // times.
            .filter_map(|b| {
                // No binding signature at time `t` => not alive.
                let selfsig = b.binding_signature(t)?;

                if !selfsig.signature_alive_at(t) {
                    return None;
                }

                let revoked = b.revoked(t);
                let primary = selfsig.primary_userid().unwrap_or(false);
                let signature_creation_time = selfsig.signature_creation_time()?;

                Some(((b, selfsig, revoked), primary, signature_creation_time))
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
                match a_signature_creation_time.cmp(&b_signature_creation_time) {
                    Ordering::Less => return Ordering::Less,
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Equal => (),
                }

                // Fallback to a lexographical comparison.  Prefer
                // the "smaller" one.
                match a.0.userid().value().cmp(&b.0.userid().value()) {
                    Ordering::Less => return Ordering::Greater,
                    Ordering::Greater => return Ordering::Less,
                    Ordering::Equal =>
                        panic!("non-canonicalized TPK (duplicate User IDs)"),
                }
            })
            .map(|b| b.0)
    }

    /// Returns the primary key's current self-signature as of `t` and
    /// the corresponding User ID binding, if any.
    ///
    /// The primary key's current self-signature as of `t` is, in
    /// order of preference:
    ///
    ///   - The binding signature of the primary User ID at time `t`,
    ///     if the primary User ID is not revoked at time `t`.
    ///
    ///   - The newest, live, direct self signature at time `t`.
    ///
    ///   - The binding signature of the primary User ID at time `t`
    ///     (this can only happen if there are only revoked User IDs
    ///     at time `t`).
    ///
    /// If there are no applicable signatures, `None` is returned.
    pub fn primary_key_signature_full<T>(&self, t: T)
        -> Option<(Option<&UserIDBinding>, &Signature)>
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);

        // 1. Self-signature from the non-revoked primary UserID.
        let primary_userid = self.primary_userid_full(t);
        if let Some((ref u, ref s, ref r)) = primary_userid {
            if !destructures_to!(RevocationStatus::Revoked(_) = r) {
                return Some((Some(u), s));
            }
        }

        // 2. Direct signature.
        if let Some(s) = self.primary.binding_signature(t) {
            return Some((None, s));
        }

        // 3. All User IDs are revoked.
        if let Some((u, s, r)) = primary_userid {
            assert!(destructures_to!(RevocationStatus::Revoked(_) = r));
            return Some((Some(u), s));
        }

        // 4. No user ids and no direct signatures.
        None
    }

    /// Returns the primary key's current self-signature.
    ///
    /// This function is identical to
    /// `TPK::primary_key_signature_full()`, but it doesn't return the
    /// `UserIDBinding`.
    pub fn primary_key_signature<T>(&self, t: T) -> Option<&Signature>
        where T: Into<Option<time::Tm>>
    {
        if let Some((_, sig)) = self.primary_key_signature_full(t) {
            Some(sig)
        } else {
            None
        }
    }

    /// Returns the TPK's revocation status at time `t`.
    ///
    /// A TPK is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    ///   - There is a hard revocation (even if it is not live at
    ///     time `t`, and even if there is a newer self-signature).
    ///
    /// Note: TPKs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this TPK is revoked; it does
    /// not imply anything about the TPK or other components.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into();
        self.primary._revoked(true, self.primary_key_signature(t), t)
    }

    /// Returns a revocation certificate for the TPK.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::RevocationStatus;
    /// use openpgp::constants::{ReasonForRevocation, SignatureType};
    /// use openpgp::tpk::{CipherSuite, TPKBuilder};
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let (tpk, _) = TPKBuilder::new()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
    ///            tpk.revoked(None));
    ///
    /// let mut keypair = tpk.primary().key().clone()
    ///     .mark_parts_secret().into_keypair()?;
    /// let sig = tpk.revoke(&mut keypair, ReasonForRevocation::KeyCompromised,
    ///                      b"It was the maid :/")?;
    /// assert_eq!(sig.typ(), SignatureType::KeyRevocation);
    ///
    /// let tpk = tpk.merge_packets(vec![sig.clone().into()])?;
    /// assert_eq!(RevocationStatus::Revoked(vec![&sig]),
    ///            tpk.revoked(None));
    /// # Ok(())
    /// # }
    pub fn revoke<R>(&self, primary_signer: &mut Signer<R>,
                     code: ReasonForRevocation, reason: &[u8])
        -> Result<Signature>
        where R: key::KeyRole
    {
        // Recompute the signature.
        let hash_algo = HashAlgorithm::SHA512;
        let mut hash = hash_algo.context()?;
        let pair = self.primary().key();
        pair.hash(&mut hash);

        signature::Builder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(time::now_utc())?
            .set_issuer_fingerprint(primary_signer.public().fingerprint())?
            .set_issuer(primary_signer.public().keyid())?
            .set_reason_for_revocation(code, reason)?
            .sign_hash(primary_signer, hash_algo, hash)
    }

    /// Revokes the TPK.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::RevocationStatus;
    /// use openpgp::constants::{ReasonForRevocation, SignatureType};
    /// use openpgp::tpk::{CipherSuite, TPKBuilder};
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let (mut tpk, _) = TPKBuilder::new()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
    ///            tpk.revoked(None));
    ///
    /// let mut keypair = tpk.primary().key().clone()
    ///     .mark_parts_secret().into_keypair()?;
    /// let tpk = tpk.revoke_in_place(&mut keypair,
    ///                               ReasonForRevocation::KeyCompromised,
    ///                               b"It was the maid :/")?;
    /// if let RevocationStatus::Revoked(sigs) = tpk.revoked(None) {
    ///     assert_eq!(sigs.len(), 1);
    ///     assert_eq!(sigs[0].typ(), SignatureType::KeyRevocation);
    ///     assert_eq!(sigs[0].reason_for_revocation(),
    ///                Some((ReasonForRevocation::KeyCompromised,
    ///                      "It was the maid :/".as_bytes())));
    /// } else {
    ///     unreachable!()
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn revoke_in_place<R>(self, primary_signer: &mut Signer<R>,
                              code: ReasonForRevocation, reason: &[u8])
        -> Result<TPK>
        where R: key::KeyRole
    {
        let sig = self.revoke(primary_signer, code, reason)?;
        self.merge_packets(vec![sig.into()])
    }

    /// Returns whether or not the TPK has expired.
    pub fn expired(&self) -> bool {
        if let Some(Signature::V4(sig)) = self.primary_key_signature(None) {
            sig.key_expired(self.primary().key())
        } else {
            false
        }
    }

    /// Returns whether or not the key is expired at the given time.
    pub fn expired_at(&self, tm: time::Tm) -> bool {
        if let Some(Signature::V4(sig)) = self.primary_key_signature(tm) {
            sig.key_expired_at(self.primary().key(), tm)
        } else {
            false
        }
    }

    /// Returns whether or not the TPK is alive.
    pub fn alive(&self) -> bool {
        if let Some(sig) = self.primary_key_signature(None) {
            sig.key_alive(self.primary().key())
        } else {
            false
        }
    }

    /// Returns whether or not the key is alive at the given time.
    pub fn alive_at(&self, tm: time::Tm) -> bool {
        if let Some(sig) = self.primary_key_signature(tm) {
            sig.key_alive_at(self.primary().key(), tm)
        } else {
            false
        }
    }

    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    fn set_expiry_as_of<R>(self, primary_signer: &mut Signer<R>,
                           expiration: Option<time::Duration>,
                           now: time::Tm)
        -> Result<TPK>
        where R: key::KeyRole
    {
        let sig = {
            let (userid, template) = self
                .primary_key_signature_full(Some(now))
                .ok_or(Error::MalformedTPK("No self-signature".into()))?;

            // Recompute the signature.
            let hash_algo = HashAlgorithm::SHA512;
            let mut hash = hash_algo.context()?;

            self.primary().key().hash(&mut hash);
            if let Some(userid) = userid {
                userid.userid().hash(&mut hash);
            } else {
                assert_eq!(template.typ(), SignatureType::DirectKey);
            }

            // Generate the signature.
            signature::Builder::from(template.clone())
                .set_key_expiration_time(expiration)?
                .set_signature_creation_time(now)?
                .sign_hash(primary_signer, hash_algo, hash)?
        };

        self.merge_packets(vec![sig.into()])
    }

    /// Sets the key to expire in delta.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    pub fn set_expiry<R>(self, primary_signer: &mut Signer<R>,
                         expiration: Option<time::Duration>)
        -> Result<TPK>
        where R: key::KeyRole
    {
        self.set_expiry_as_of(primary_signer, expiration, time::now())
    }

    /// Returns an iterator over the TPK's valid `UserIDBinding`s.
    ///
    /// The primary user id is returned first.  A valid
    /// `UserIDBinding` has at least one good self-signature.
    pub fn userids(&self) -> UserIDBindingIter {
        UserIDBindingIter { iter: Some(self.userids.iter()) }
    }

    /// Returns an iterator over the TPK's valid `UserAttributeBinding`s.
    ///
    /// A valid `UserIDAttributeBinding` has at least one good
    /// self-signature.
    pub fn user_attributes(&self) -> UserAttributeBindingIter {
        UserAttributeBindingIter { iter: Some(self.user_attributes.iter()) }
    }

    /// Returns an iterator over the TPK's valid subkeys.
    ///
    /// A valid `KeyBinding` has at least one good self-signature.
    pub fn subkeys(&self) -> KeyBindingIter<key::PublicParts,
                                            key::SubordinateRole>
    {
        KeyBindingIter { iter: Some(self.subkeys.iter()) }
    }

    /// Returns an iterator over the TPK's valid unknown components.
    ///
    /// A valid `UnknownBinding` has at least one good self-signature.
    pub fn unknowns(&self) -> UnknownBindingIter {
        UnknownBindingIter { iter: Some(self.unknowns.iter()) }
    }

    /// Returns a slice containing all bad signatures.
    ///
    /// Bad signatures are signatures that we could not associate with
    /// one of the components.
    pub fn bad_signatures(&self) -> &[Signature] {
        &self.bad
    }

    /// Returns an iterator over the TPK's valid keys (live and
    /// not-revoked).
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys, along with the corresponding signatures.
    ///
    /// Note: since a primary key is different from a binding, the
    /// iterator is over `Key`s and not `KeyBindings`.
    /// Furthermore, the primary key has no binding signature.  Here,
    /// the signature carrying the primary key's key flags is
    /// returned.  There are corner cases where no such signature
    /// exists (e.g. partial TPKs), therefore this iterator may return
    /// `None` for the primary key's signature.
    ///
    /// A valid `Key` has at least one good self-signature.
    ///
    /// To return all keys, do `keys_all().unfiltered()`.  See the
    /// documentation of `keys` for how to control what keys are
    /// returned.
    pub fn keys_valid(&self)
        -> KeyIter<key::PublicParts, key::UnspecifiedRole>
    {
        KeyIter::new(self).alive().revoked(false)
    }

    /// Returns an iterator over the TPK's keys.
    ///
    /// Unlike `TPK::keys_valid()`, this iterator also returns expired
    /// and revoked keys.
    pub fn keys_all(&self)
        -> KeyIter<key::PublicParts, key::UnspecifiedRole>
    {
        KeyIter::new(self)
    }

    /// Returns the TPK found in the packet stream.
    ///
    /// If there are more packets after the TPK, e.g. because the
    /// packet stream is a keyring, this function will return
    /// `Error::MalformedTPK`.
    pub fn from_packet_parser(ppr: PacketParserResult) -> Result<Self> {
        let mut parser = parser::TPKParser::from_packet_parser(ppr);
        if let Some(tpk_result) = parser.next() {
            if parser.next().is_some() {
                Err(Error::MalformedTPK(
                    "Additional packets found, is this a keyring?".into()
                ).into())
            } else {
                tpk_result
            }
        } else {
            Err(Error::MalformedTPK("No data".into()).into())
        }
    }

    /// Returns the first TPK found in the `PacketPile`.
    pub fn from_packet_pile(p: PacketPile) -> Result<Self> {
        let mut i = parser::TPKParser::from_iter(p.into_children());
        match i.next() {
            Some(Ok(tpk)) => Ok(tpk),
            Some(Err(err)) => Err(err),
            None => Err(Error::MalformedTPK("No data".into()).into()),
        }
    }

    fn canonicalize(mut self) -> Self {
        tracer!(TRACE, "canonicalize", 0);

        // The very first thing that we do is verify the
        // self-signatures.  There are a few things that we need to be
        // aware of:
        //
        //  - Signature may be invalid.  These should be dropped.
        //
        //  - Signature may be out of order.  These should be
        //    reordered so that we have the latest self-signature and
        //    we don't drop a userid or subkey that is actually
        //    valid.

        // We collect bad signatures here in self.bad.  Below, we'll
        // test whether they are just out of order by checking them
        // against all userids and subkeys.  Furthermore, this may be
        // a partial TPK that is merged into an older copy.

        // desc: a description of the component
        // binding: the binding to check
        // sigs: a vector of sigs in $binding to check
        // verify_method: the method to call on a signature to verify it
        // verify_args: additional arguments to pass to verify_method
        macro_rules! check {
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident, $($verify_args:expr),*) => ({
                t!("check!({}, {}, {:?}, {}, ...)",
                   $desc, stringify!($binding), $binding.$sigs,
                   stringify!($verify_method));
                for sig in mem::replace(&mut $binding.$sigs, Vec::new())
                    .into_iter()
                {
                    if let Ok(true) = sig.$verify_method(self.primary.key(),
                                                         self.primary.key(),
                                                         $($verify_args),*) {
                        $binding.$sigs.push(sig);
                    } else {
                        t!("Sig {:02X}{:02X}, type = {} doesn't belong to {}",
                           sig.hash_prefix()[0], sig.hash_prefix()[1],
                           sig.typ(), $desc);

                        self.bad.push(sig);
                    }
                }
            });
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident) => ({
                check!($desc, $binding, $sigs, $verify_method,)
            });
        }

        check!("primary key",
               self.primary, selfsigs, verify_primary_key_binding);
        check!("primary key",
               self.primary, self_revocations, verify_primary_key_revocation);

        for binding in self.userids.iter_mut() {
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, selfsigs, verify_userid_binding,
                   binding.userid());
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, self_revocations, verify_userid_revocation,
                   binding.userid());
        }

        for binding in self.user_attributes.iter_mut() {
            check!("user attribute",
                   binding, selfsigs, verify_user_attribute_binding,
                   binding.user_attribute());
            check!("user attribute",
                   binding, self_revocations, verify_user_attribute_revocation,
                   binding.user_attribute());
        }

        for binding in self.subkeys.iter_mut() {
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, selfsigs, verify_subkey_binding,
                   binding.key());
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, self_revocations, verify_subkey_revocation,
                   binding.key());
        }

        // See if the signatures that didn't validate are just out of
        // place.

        'outer: for sig in mem::replace(&mut self.bad, Vec::new()) {
            macro_rules! check_one {
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident, $($verify_args:expr),*) => ({
                     t!("check!({}, {:?}, {:?}, {}, ...)",
                        $desc, $sigs, $sig,
                        stringify!($verify_method));
                     if let Ok(true)
                         = $sig.$verify_method(self.primary.key(),
                                               self.primary.key(),
                                               $($verify_args),*)
                     {
                         t!("Sig {:02X}{:02X}, {:?} \
                             was out of place.  Belongs to {}.",
                            $sig.hash_prefix()[0],
                            $sig.hash_prefix()[1],
                            $sig.typ(), $desc);

                         $sigs.push($sig);
                         continue 'outer;
                     }
                 });
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident) => ({
                    check_one!($desc, $sigs, $sig, $verify_method,)
                });
            }

            check_one!("primary key", self.primary.selfsigs, sig,
                       verify_primary_key_binding);
            check_one!("primary key", self.primary.self_revocations, sig,
                       verify_primary_key_revocation);

            for binding in self.userids.iter_mut() {
                check_one!(format!("userid \"{}\"",
                                   String::from_utf8_lossy(
                                       binding.userid().value())),
                           binding.selfsigs, sig,
                           verify_userid_binding, binding.userid());
                check_one!(format!("userid \"{}\"",
                                   String::from_utf8_lossy(
                                       binding.userid().value())),
                           binding.self_revocations, sig,
                           verify_userid_revocation, binding.userid());
            }

            for binding in self.user_attributes.iter_mut() {
                check_one!("user attribute",
                           binding.selfsigs, sig,
                           verify_user_attribute_binding,
                           binding.user_attribute());
                check_one!("user attribute",
                           binding.self_revocations, sig,
                           verify_user_attribute_revocation,
                           binding.user_attribute());
            }

            for binding in self.subkeys.iter_mut() {
                check_one!(format!("subkey {}", binding.key().keyid()),
                           binding.selfsigs, sig,
                           verify_subkey_binding, binding.key());
                check_one!(format!("subkey {}", binding.key().keyid()),
                           binding.self_revocations, sig,
                           verify_subkey_revocation, binding.key());
            }

            // Keep them for later.
            t!("Self-sig {:02X}{:02X}, {:?} doesn't belong \
                to any known component or is bad.",
               sig.hash_prefix()[0], sig.hash_prefix()[1],
               sig.typ());
            self.bad.push(sig);
        }

        if self.bad.len() > 0 {
            t!("{}: ignoring {} bad self-signatures",
               self.primary().key().keyid(), self.bad.len());
        }

        // Only keep user ids / user attributes / subkeys with at
        // least one valid self-signature or self-revocation.
        self.userids.retain(|userid| {
            userid.selfsigs.len() > 0 || userid.self_revocations.len() > 0
        });
        t!("Retained {} userids", self.userids.len());

        self.user_attributes.retain(|ua| {
            ua.selfsigs.len() > 0 || ua.self_revocations.len() > 0
        });
        t!("Retained {} user_attributes", self.user_attributes.len());

        self.subkeys.retain(|subkey| {
            subkey.selfsigs.len() > 0 || subkey.self_revocations.len() > 0
        });
        t!("Retained {} subkeys", self.subkeys.len());


        self.primary.sort_and_dedup();

        self.bad.sort_by(sig_cmp);
        self.bad.dedup();

        self.userids.sort_and_dedup(UserID::cmp, |_, _| {});
        self.user_attributes.sort_and_dedup(UserAttribute::cmp, |_, _| {});
        // XXX: If we have two keys with the same public parts and
        // different non-empty secret parts, then one will be dropped
        // (non-deterministicly)!
        //
        // This can happen if:
        //
        //   - One is corrupted
        //   - There are two versions that are encrypted differently
        self.subkeys.sort_and_dedup(Key::public_cmp,
            |ref mut a, ref mut b| {
                // Recall: if a and b are equal, a will be dropped.
                if b.secret().is_none() && a.secret().is_some() {
                    b.set_secret(a.set_secret(None));
                }
            });
        self.unknowns.sort_and_dedup(Unknown::cmp, |_, _| {});

        // In case we have subkeys bound to the primary, it must be
        // certification capable.
        if ! self.subkeys.is_empty() {
            let pk_can_certify =
                self.primary_key_signature(None)
                .map(|sig| sig.key_flags().can_certify())
                .unwrap_or(true);

            if ! pk_can_certify {
                // Primary not certification capable, all binding sigs
                // are invalid.
                t!("Primary key not certification capable, dropping subkeys");
                self.subkeys.clear();
            }
        }


        // XXX: Check if the sigs in other_sigs issuer are actually
        // designated revokers for this key (listed in a "Revocation
        // Key" subpacket in *any* non-revoked self-signature).  Only
        // if that is the case should a sig be considered a potential
        // revocation.  (This applies to
        // self.primary_other_revocations as well as
        // self.userids().other_revocations, etc.)  If not, put the
        // sig on the bad list.
        //
        // Note: just because the TPK doesn't indicate that a key is a
        // designed revoker doesn't mean that it isn't---we might just
        // be missing the signature.  In other words, this is a policy
        // decision, but given how easy it could be to create rouge
        // revocations, is probably the better to reject such
        // signatures than to keep them around and have many keys
        // being shown as "potentially revoked".

        // XXX Do some more canonicalization.

        self
    }

    /// Returns the TPK's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary().key().fingerprint()
    }

    /// Returns the TPK's keyid.
    pub fn keyid(&self) -> KeyID {
        self.primary().key().keyid()
    }

    /// Converts the TPK into an iterator over a sequence of packets.
    ///
    /// This method discards invalid components and bad signatures.
    pub fn into_packets(self) -> impl Iterator<Item=Packet> {
        self.primary.into_packets()
            .chain(self.userids.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.user_attributes.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.subkeys.into_iter().flat_map(|b| b.into_packets()))
    }

    /// Converts the TPK into a `PacketPile`.
    ///
    /// This method discards an invalid components and bad signatures.
    pub fn into_packet_pile(self) -> PacketPile {
        PacketPile::from(self.into_packets().collect::<Vec<Packet>>())
    }

    /// Merges `other` into `self`.
    ///
    /// If `other` is a different key, then an error is returned.
    pub fn merge(mut self, mut other: TPK) -> Result<Self> {
        if self.primary().key().fingerprint()
            != other.primary().key().fingerprint()
        {
            // The primary key is not the same.  There is nothing to
            // do.
            return Err(Error::InvalidArgument(
                "Primary key mismatch".into()).into());
        }

        if self.primary.key().secret().is_none() && other.primary.key().secret().is_some() {
            self.primary.key_mut().set_secret(other.primary.key_mut().set_secret(None));
        }

        self.primary.selfsigs.append(
            &mut other.primary.selfsigs);
        self.primary.certifications.append(
            &mut other.primary.certifications);
        self.primary.self_revocations.append(
            &mut other.primary.self_revocations);
        self.primary.other_revocations.append(
            &mut other.primary.other_revocations);

        self.userids.append(&mut other.userids);
        self.user_attributes.append(&mut other.user_attributes);
        self.subkeys.append(&mut other.subkeys);
        self.bad.append(&mut other.bad);

        Ok(self.canonicalize())
    }

    /// Adds packets to the TPK.
    ///
    /// This recanonicalizes the TPK.  If the packets are invalid,
    /// they are dropped.
    pub fn merge_packets(self, mut packets: Vec<Packet>) -> Result<Self> {
        let mut combined = self.into_packets().collect::<Vec<_>>();
        combined.append(&mut packets);
        TPK::from_packet_pile(PacketPile::from(combined))
    }

    /// Returns whether at least one of the keys includes a secret
    /// part.
    pub fn is_tsk(&self) -> bool {
        if self.primary().key().secret().is_some() {
            return true;
        }
        self.subkeys().any(|sk| {
            sk.binding_signature(None).is_some() && sk.key().secret().is_some()
        })
    }
}

#[cfg(test)]
mod test {
    use crate::serialize::Serialize;
    use super::*;

    use crate::{
        KeyID,
        constants::KeyFlags,
    };

    fn parse_tpk(data: &[u8], as_message: bool) -> Result<TPK> {
        if as_message {
            let pile = PacketPile::from_bytes(data).unwrap();
            TPK::from_packet_pile(pile)
        } else {
            TPK::from_bytes(data)
        }
    }

    #[test]
    fn broken() {
        use crate::conversions::Time;
        for i in 0..2 {
            let tpk = parse_tpk(crate::tests::key("testy-broken-no-pk.pgp"),
                                i == 0);
            assert_match!(Error::MalformedTPK(_)
                          = tpk.err().unwrap().downcast::<Error>().unwrap());

            // According to 4880, a TPK must have a UserID.  But, we
            // don't require it.
            let tpk = parse_tpk(crate::tests::key("testy-broken-no-uid.pgp"),
                                i == 0);
            assert!(tpk.is_ok());

            // We have:
            //
            //   [ pk, user id, sig, subkey ]
            let tpk = parse_tpk(crate::tests::key("testy-broken-no-sig-on-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.key().creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.userids.len(), 1);
            assert_eq!(tpk.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);
            assert_eq!(tpk.user_attributes.len(), 0);
            assert_eq!(tpk.subkeys.len(), 0);
        }
    }

    #[test]
    fn basics() {
        use crate::conversions::Time;
        for i in 0..2 {
            let tpk = parse_tpk(crate::tests::key("testy.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.key().creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
            assert_eq!(tpk.subkeys[0].key().creation_time().to_pgp().unwrap(),
                       1511355130);
            assert_eq!(tpk.subkeys[0].selfsigs[0].hash_prefix(),
                       &[ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(crate::tests::key("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.key().creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 0, "number of subkeys");

            let tpk = parse_tpk(crate::tests::key("testy.asc"), i == 0).unwrap();
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");
        }
    }

    #[test]
    fn only_a_public_key() {
        // Make sure the TPK parser can parse a key that just consists
        // of a public key---no signatures, no user ids, nothing.
        let tpk = TPK::from_bytes(crate::tests::key("testy-only-a-pk.pgp")).unwrap();
        assert_eq!(tpk.userids.len(), 0);
        assert_eq!(tpk.user_attributes.len(), 0);
        assert_eq!(tpk.subkeys.len(), 0);
    }

    #[test]
    fn merge() {
        use crate::tests::key;
        let tpk_base = TPK::from_bytes(key("bannon-base.gpg")).unwrap();

        // When we merge it with itself, we should get the exact same
        // thing.
        let merged = tpk_base.clone().merge(tpk_base.clone()).unwrap();
        assert_eq!(tpk_base, merged);

        let tpk_add_uid_1
            = TPK::from_bytes(key("bannon-add-uid-1-whitehouse.gov.gpg"))
                .unwrap();
        let tpk_add_uid_2
            = TPK::from_bytes(key("bannon-add-uid-2-fox.com.gpg"))
                .unwrap();
        // Duplicate user id, but with a different self-sig.
        let tpk_add_uid_3
            = TPK::from_bytes(key("bannon-add-uid-3-whitehouse.gov-dup.gpg"))
                .unwrap();

        let tpk_all_uids
            = TPK::from_bytes(key("bannon-all-uids.gpg"))
            .unwrap();
        // We have four User ID packets, but one has the same User ID,
        // just with a different self-signature.
        assert_eq!(tpk_all_uids.userids.len(), 3);

        // Merge in order.
        let merged = tpk_base.clone().merge(tpk_add_uid_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_3.clone()).unwrap();
        assert_eq!(tpk_all_uids, merged);

        // Merge in reverse order.
        let merged = tpk_base.clone()
            .merge(tpk_add_uid_3.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_1.clone()).unwrap();
        assert_eq!(tpk_all_uids, merged);

        let tpk_add_subkey_1
            = TPK::from_bytes(key("bannon-add-subkey-1.gpg")).unwrap();
        let tpk_add_subkey_2
            = TPK::from_bytes(key("bannon-add-subkey-2.gpg")).unwrap();
        let tpk_add_subkey_3
            = TPK::from_bytes(key("bannon-add-subkey-3.gpg")).unwrap();

        let tpk_all_subkeys
            = TPK::from_bytes(key("bannon-all-subkeys.gpg")).unwrap();

        // Merge the first user, then the second, then the third.
        let merged = tpk_base.clone().merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        // Merge the third user, then the second, then the first.
        let merged = tpk_base.clone().merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        // Merge alot.
        let merged = tpk_base.clone()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        let tpk_all
            = TPK::from_bytes(key("bannon-all-uids-subkeys.gpg"))
            .unwrap();

        // Merge all the subkeys with all the uids.
        let merged = tpk_all_subkeys.clone()
            .merge(tpk_all_uids.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // Merge all uids with all the subkeys.
        let merged = tpk_all_uids.clone()
            .merge(tpk_all_subkeys.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // All the subkeys and the uids in a mixed up order.
        let merged = tpk_base.clone()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_1.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_3.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // Certifications.
        let tpk_donald_signs_base
            = TPK::from_bytes(key("bannon-the-donald-signs-base.gpg"))
            .unwrap();
        let tpk_donald_signs_all
            = TPK::from_bytes(key("bannon-the-donald-signs-all-uids.gpg"))
            .unwrap();
        let tpk_ivanka_signs_base
            = TPK::from_bytes(key("bannon-ivanka-signs-base.gpg"))
            .unwrap();
        let tpk_ivanka_signs_all
            = TPK::from_bytes(key("bannon-ivanka-signs-all-uids.gpg"))
            .unwrap();

        assert!(tpk_donald_signs_base.userids.len() == 1);
        assert!(tpk_donald_signs_base.userids[0].selfsigs.len() == 1);
        assert!(tpk_base.userids[0].certifications.len() == 0);
        assert!(tpk_donald_signs_base.userids[0].certifications.len() == 1);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_ivanka_signs_base.clone()).unwrap();
        assert!(merged.userids.len() == 1);
        assert!(merged.userids[0].selfsigs.len() == 1);
        assert!(merged.userids[0].certifications.len() == 2);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_donald_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from the Donald on the
        // first user id.
        assert!(merged.userids[0].certifications.len() == 2);
        assert!(merged.userids[1].certifications.len() == 1);
        assert!(merged.userids[2].certifications.len() == 1);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);

        // Same as above, but redundant.
        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);
    }

    #[test]
    fn out_of_order_self_sigs_test() {
        // neal-out-of-order.pgp contains all of the self-signatures,
        // but some are out of order.  The canonicalization step
        // should reorder them.
        //
        // original order/new order:
        //
        //  1/ 1. pk
        //  2/ 2. user id #1: neal@walfield.org (good)
        //  3/ 3. sig over user ID #1
        //
        //  4/ 4. user id #2: neal@gnupg.org (good)
        //  5/ 7. sig over user ID #3
        //  6/ 5. sig over user ID #2
        //
        //  7/ 6. user id #3: neal@g10code.com (bad)
        //
        //  8/ 8. user ID #4: neal@pep.foundation (bad)
        //  9/11. sig over user ID #5
        //
        // 10/10. user id #5: neal@pep-project.org (bad)
        // 11/ 9. sig over user ID #4
        //
        // 12/12. user ID #6: neal@sequoia-pgp.org (good)
        // 13/13. sig over user ID #6
        //
        // ----------------------------------------------
        //
        // 14/14. signing subkey #1: 7223B56678E02528 (good)
        // 15/15. sig over subkey #1
        // 16/16. sig over subkey #1
        //
        // 17/17. encryption subkey #2: C2B819056C652598 (good)
        // 18/18. sig over subkey #2
        // 19/21. sig over subkey #3
        // 20/22. sig over subkey #3
        //
        // 21/20. auth subkey #3: A3506AFB820ABD08 (bad)
        // 22/19. sig over subkey #2

        let tpk = TPK::from_bytes(crate::tests::key("neal-sigs-out-of-order.pgp"))
            .unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Neal H. Walfield <neal@g10code.com>",
                      "Neal H. Walfield <neal@gnupg.org>",
                      "Neal H. Walfield <neal@pep-project.org>",
                      "Neal H. Walfield <neal@pep.foundation>",
                      "Neal H. Walfield <neal@sequoia-pgp.org>",
                      "Neal H. Walfield <neal@walfield.org>",
                   ]);

        let mut subkeys = tpk.subkeys()
            .map(|sk| Some(sk.key().keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex("7223B56678E02528").ok(),
                      KeyID::from_hex("A3506AFB820ABD08").ok(),
                      KeyID::from_hex("C2B819056C652598").ok(),
                   ]);

        // DKG's key has all of the self-signatures moved to the last
        // subkey; all user ids/user attributes/subkeys have nothing.
        let tpk =
            TPK::from_bytes(crate::tests::key("dkg-sigs-out-of-order.pgp")).unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Daniel Kahn Gillmor <dkg-debian.org@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@aclu.org>",
                      "Daniel Kahn Gillmor <dkg@astro.columbia.edu>",
                      "Daniel Kahn Gillmor <dkg@debian.org>",
                      "Daniel Kahn Gillmor <dkg@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@openflows.com>",
                   ]);

        assert_eq!(tpk.user_attributes.len(), 1);

        let mut subkeys = tpk.subkeys()
            .map(|sk| Some(sk.key().keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex(&"1075 8EBD BD7C FAB5"[..]).ok(),
                      KeyID::from_hex(&"1258 68EA 4BFA 08E4"[..]).ok(),
                      KeyID::from_hex(&"1498 ADC6 C192 3237"[..]).ok(),
                      KeyID::from_hex(&"24EC FF5A FF68 370A"[..]).ok(),
                      KeyID::from_hex(&"3714 7292 14D5 DA70"[..]).ok(),
                      KeyID::from_hex(&"3B7A A7F0 14E6 9B5A"[..]).ok(),
                      KeyID::from_hex(&"5B58 DCF9 C341 6611"[..]).ok(),
                      KeyID::from_hex(&"A524 01B1 1BFD FA5C"[..]).ok(),
                      KeyID::from_hex(&"A70A 96E1 439E A852"[..]).ok(),
                      KeyID::from_hex(&"C61B D3EC 2148 4CFF"[..]).ok(),
                      KeyID::from_hex(&"CAEF A883 2167 5333"[..]).ok(),
                      KeyID::from_hex(&"DC10 4C4E 0CA7 57FB"[..]).ok(),
                      KeyID::from_hex(&"E3A3 2229 449B 0350"[..]).ok(),
                   ]);

    }

    // lutz's key is a v3 key.
    //
    // dkg's includes some v3 signatures.
    #[test]
    fn v3_packets() {
        let dkg = crate::tests::key("dkg.gpg");
        let lutz = crate::tests::key("lutz.gpg");

        // v3 primary keys are not supported.
        let tpk = TPK::from_bytes(lutz);
        assert_match!(Error::MalformedTPK(_)
                      = tpk.err().unwrap().downcast::<Error>().unwrap());

        let tpk = TPK::from_bytes(dkg);
        assert!(tpk.is_ok(), "dkg.gpg: {:?}", tpk);
    }

    #[test]
    fn keyring_with_v3_public_keys() {
        let dkg = crate::tests::key("dkg.gpg");
        let lutz = crate::tests::key("lutz.gpg");

        let tpk = TPK::from_bytes(dkg);
        assert!(tpk.is_ok(), "dkg.gpg: {:?}", tpk);

        // Key ring with two good keys
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, true ]);

        // Key ring with a good key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false ]);

        // Key ring with a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ false, true ]);

        // Key ring with a good key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, true ]);

        // Key ring with a good key, a bad key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, false ]);

        // Key ring with a good key, a bad key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, false, true ]);
    }

    #[test]
    fn merge_with_incomplete_update() {
        let tpk = TPK::from_bytes(crate::tests::key("about-to-expire.expired.pgp"))
            .unwrap();
        assert!(tpk.primary_key_signature(None).unwrap()
                .key_expired(tpk.primary().key()));

        let update =
            TPK::from_bytes(crate::tests::key("about-to-expire.update-no-uid.pgp"))
            .unwrap();
        let tpk = tpk.merge(update).unwrap();
        assert!(! tpk.primary_key_signature(None).unwrap()
                .key_expired(tpk.primary().key()));
    }

    #[test]
    fn packet_pile_roundtrip() {
        // Make sure TPK::from_packet_pile(TPK::to_packet_pile(tpk))
        // does a clean round trip.

        let tpk = TPK::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);
    }

    #[test]
    fn merge_packets() {
        use crate::armor;
        use crate::packet::Tag;

        // Merge the revocation certificate into the TPK and make sure
        // it shows up.
        let tpk = TPK::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();

        let rev = crate::tests::key("already-revoked.rev");
        let rev = PacketPile::from_reader(armor::Reader::new(&rev[..], None))
            .unwrap();

        let rev : Vec<Packet> = rev.into_children().collect();
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].tag(), Tag::Signature);

        let packets_pre_merge = tpk.clone().into_packets().count();
        let tpk = tpk.merge_packets(rev).unwrap();
        let packets_post_merge = tpk.clone().into_packets().count();
        assert_eq!(packets_post_merge, packets_pre_merge + 1);
    }

    #[test]
    fn set_expiry() {
        let now = time::now_utc();
        let a_sec = time::Duration::seconds(1);

        let (tpk, _) = TPKBuilder::autocrypt(None, Some("Test"))
            .generate().unwrap();
        let expiry_orig = tpk.primary_key_signature(None).unwrap()
            .key_expiration_time()
            .expect("Keys expire by default.");

        let mut keypair = tpk.primary().key().clone().mark_parts_secret()
            .into_keypair().unwrap();

        // Clear the expiration.
        let as_of1 = now + time::Duration::seconds(10);
        let tpk = tpk.set_expiry_as_of(
            &mut keypair,
            None,
            as_of1).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(tpk.primary_key_signature(now).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            assert_eq!(tpk.primary_key_signature(as_of1 - a_sec).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            // If t >= as_of1, we should get the new expiry.
            assert_eq!(tpk.primary_key_signature(as_of1).unwrap()
                           .key_expiration_time(),
                       None);
        }

        // Shorten the expiry.  (The default expiration should be at
        // least a few weeks, so removing an hour should still keep us
        // over 0.)
        let expiry_new = expiry_orig - time::Duration::hours(1);
        assert!(expiry_new > time::Duration::seconds(0));

        let as_of2 = as_of1 + time::Duration::seconds(10);
        let tpk = tpk.set_expiry_as_of(
            &mut keypair,
            Some(expiry_new),
            as_of2).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(tpk.primary_key_signature(now).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            assert_eq!(tpk.primary_key_signature(as_of1 - a_sec).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            // If as_of1 <= t < as_of2, we should get the second
            // expiry (None).
            assert_eq!(tpk.primary_key_signature(as_of1).unwrap()
                           .key_expiration_time(),
                       None);
            assert_eq!(tpk.primary_key_signature(as_of2 - a_sec).unwrap()
                           .key_expiration_time(),
                       None);
            // If t <= as_of2, we should get the new expiry.
            assert_eq!(tpk.primary_key_signature(as_of2).unwrap()
                           .key_expiration_time(),
                       Some(expiry_new));
        }
    }

    #[test]
    fn direct_key_sig() {
        use crate::constants::SignatureType;
        // XXX: testing sequoia against itself isn't optimal, but I couldn't
        // find a tool to generate direct key signatures :-(

        let (tpk1, _) = TPKBuilder::new().generate().unwrap();
        let mut buf = Vec::default();

        tpk1.serialize(&mut buf).unwrap();
        let tpk2 = TPK::from_bytes(&buf).unwrap();

        assert_eq!(tpk2.primary_key_signature(None).unwrap().typ(),
                   SignatureType::DirectKey);
        assert_eq!(tpk2.userids().count(), 0);
    }

    #[test]
    fn revoked() {
        fn check(tpk: &TPK, direct_revoked: bool,
                 userid_revoked: bool, subkey_revoked: bool) {
            // If we have a user id---even if it is revoked---we have
            // a primary key signature.
            let typ = tpk.primary_key_signature(None).unwrap().typ();
            assert_eq!(typ, SignatureType::PositiveCertificate,
                       "{:#?}", tpk);

            let revoked = tpk.revoked(None);
            if direct_revoked {
                assert_match!(RevocationStatus::Revoked(_) = revoked,
                              "{:#?}", tpk);
            } else {
                assert_eq!(revoked, RevocationStatus::NotAsFarAsWeKnow,
                           "{:#?}", tpk);
            }

            for userid in tpk.userids() {
                let typ = userid.binding_signature(None).unwrap().typ();
                assert_eq!(typ, SignatureType::PositiveCertificate,
                           "{:#?}", tpk);

                let revoked = userid.revoked(None);
                if userid_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", tpk);
                }
            }

            for subkey in tpk.subkeys() {
                let typ = subkey.binding_signature(None).unwrap().typ();
                assert_eq!(typ, SignatureType::SubkeyBinding,
                           "{:#?}", tpk);

                let revoked = subkey.revoked(None);
                if subkey_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", tpk);
                }
            }
        }

        let tpk = TPK::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        check(&tpk, false, false, false);

        let d = TPK::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        check(&d, true, false, false);

        check(&tpk.clone().merge(d.clone()).unwrap(), true, false, false);
        // Make sure the merge order does not matter.
        check(&d.clone().merge(tpk.clone()).unwrap(), true, false, false);

        let u = TPK::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        check(&u, false, true, false);

        check(&tpk.clone().merge(u.clone()).unwrap(), false, true, false);
        check(&u.clone().merge(tpk.clone()).unwrap(), false, true, false);

        let k = TPK::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        check(&k, false, false, true);

        check(&tpk.clone().merge(k.clone()).unwrap(), false, false, true);
        check(&k.clone().merge(tpk.clone()).unwrap(), false, false, true);

        // direct and user id revocation.
        check(&d.clone().merge(u.clone()).unwrap(), true, true, false);
        check(&u.clone().merge(d.clone()).unwrap(), true, true, false);

        // direct and subkey revocation.
        check(&d.clone().merge(k.clone()).unwrap(), true, false, true);
        check(&k.clone().merge(d.clone()).unwrap(), true, false, true);

        // user id and subkey revocation.
        check(&u.clone().merge(k.clone()).unwrap(), false, true, true);
        check(&k.clone().merge(u.clone()).unwrap(), false, true, true);

        // direct, user id and subkey revocation.
        check(&d.clone().merge(u.clone().merge(k.clone()).unwrap()).unwrap(),
              true, true, true);
        check(&d.clone().merge(k.clone().merge(u.clone()).unwrap()).unwrap(),
              true, true, true);
    }

    #[test]
    fn revoke() {
        let (tpk, _) = TPKBuilder::autocrypt(None, Some("Test"))
            .generate().unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   tpk.revoked(None));

        let mut keypair = tpk.primary().key().clone().mark_parts_secret()
            .into_keypair().unwrap();
        let sig = tpk.revoke(&mut keypair,
                             ReasonForRevocation::KeyCompromised,
                             b"It was the maid :/").unwrap();
        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(tpk.primary().key().keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(tpk.primary().key().fingerprint()));

        let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(None));


        // Have other revoke tpk.
        let (other, _) = TPKBuilder::autocrypt(None, Some("Test 2"))
            .generate().unwrap();

        let mut keypair = other.primary().key().clone().mark_parts_secret()
            .into_keypair().unwrap();
        let sig = tpk.revoke(&mut keypair,
                             ReasonForRevocation::KeyCompromised,
                             b"It was the maid :/").unwrap();
        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(other.primary().key().keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(other.primary().key().fingerprint()));
    }

    #[test]
    fn revoke_uid() {
        use std::{thread, time};

        let (tpk, _) = TPKBuilder::new()
            .add_userid("Test1")
            .add_userid("Test2")
            .generate().unwrap();

        thread::sleep(time::Duration::from_secs(2));
        let sig = {
            let uid = tpk.userids().skip(1).next().unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

            let mut keypair = tpk.primary().key().clone().mark_parts_secret()
                .into_keypair().unwrap();
            uid.userid()
                .revoke(&mut keypair, &tpk,
                        ReasonForRevocation::UIDRetired,
                        b"It was the maid :/", None, None).unwrap()
        };
        assert_eq!(sig.typ(), SignatureType::CertificateRevocation);
        let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   tpk.revoked(None));

        let uid = tpk.userids().skip(1).next().unwrap();
        assert_match!(RevocationStatus::Revoked(_) = uid.revoked(None));
    }

    #[test]
    fn key_revoked() {
        use crate::constants::Features;
        use crate::packet::key::Key4;
        use crate::constants::Curve;
        use rand::{thread_rng, Rng, distributions::Open01};
        /*
         * t1: 1st binding sig ctime
         * t2: soft rev sig ctime
         * t3: 2nd binding sig ctime
         * t4: hard rev sig ctime
         *
         * [0,t1): invalid, but not revoked
         * [t1,t2): valid (not revocations)
         * [t2,t3): revoked (soft revocation)
         * [t3,t4): valid again (new self sig)
         * [t4,inf): hard revocation (hard revocation)
         *
         * One the hard revocation is merged, then the TPK is
         * considered revoked at all times.
         */
        let t1 = time::strptime("2000-1-1", "%F").unwrap();
        let t2 = time::strptime("2001-1-1", "%F").unwrap();
        let t3 = time::strptime("2002-1-1", "%F").unwrap();
        let t4 = time::strptime("2003-1-1", "%F").unwrap();
        let key: key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.clone().into_keypair().unwrap();
        let (bind1, rev1, bind2, rev2) = {
            let bind1 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t1).unwrap()
                .set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_primary_key_binding(&mut pair,
                                          HashAlgorithm::SHA512).unwrap();

            let rev1 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t2).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeySuperseded,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_primary_key_binding(&mut pair,
                                          HashAlgorithm::SHA512).unwrap();

            let bind2 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t3).unwrap()
                .set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_primary_key_binding(&mut pair,
                                          HashAlgorithm::SHA512).unwrap();

            let rev2 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t4).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_primary_key_binding(&mut pair,
                                          HashAlgorithm::SHA512).unwrap();

            (bind1, rev1, bind2, rev2)
        };
        let pk : key::PublicKey = key.into();
        let tpk = TPK::from_packet_pile(PacketPile::from(vec![
            pk.into(),
            bind1.into(),
            bind2.into(),
            rev1.into()
        ])).unwrap();

        let f1: f32 = thread_rng().sample(Open01);
        let f2: f32 = thread_rng().sample(Open01);
        let f3: f32 = thread_rng().sample(Open01);
        let te1 = t1 - time::Duration::days((300.0 * f1) as i64);
        let t12 = t1 + time::Duration::days((300.0 * f2) as i64);
        let t23 = t2 + time::Duration::days((300.0 * f3) as i64);
        let t34 = t3 + time::Duration::days((300.0 * f3) as i64);

        assert_eq!(tpk.revoked(te1), RevocationStatus::NotAsFarAsWeKnow);
        assert_eq!(tpk.revoked(t12), RevocationStatus::NotAsFarAsWeKnow);
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(t23));
        assert_eq!(tpk.revoked(t34), RevocationStatus::NotAsFarAsWeKnow);

        // Merge in the hard revocation.
        let tpk = tpk.merge_packets(vec![ rev2.into() ]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(te1));
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(t12));
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(t23));
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(t34));
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(t4));
        assert_match!(RevocationStatus::Revoked(_)
                      = tpk.revoked(time::now_utc()));
    }

    #[test]
    fn key_revoked2() {
        tracer!(true, "tpk_revoked2", 0);

        fn tpk_revoked<T>(tpk: &TPK, t: T) -> bool
            where T: Into<Option<time::Tm>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = tpk.revoked(t))
        }

        fn subkey_revoked<T>(tpk: &TPK, t: T) -> bool
            where T: Into<Option<time::Tm>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = tpk.subkeys().nth(0).unwrap().revoked(t))
        }

        let tests : [(&str, Box<Fn(&TPK, _) -> bool>); 2] = [
            ("tpk", Box::new(tpk_revoked)),
            ("subkey", Box::new(subkey_revoked)),
        ];

        for (f, revoked) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let tpk = TPK::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();
            let selfsig0 = tpk.primary_key_signature(None).unwrap()
                .signature_creation_time().unwrap();

            assert!(!revoked(&tpk, Some(selfsig0)));
            assert!(!revoked(&tpk, None));

            t!("Soft revocation");
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();
            // A soft revocation made after `t` is ignored when
            // determining whether the key is revoked at time `t`.
            assert!(!revoked(&tpk, Some(selfsig0)));
            assert!(revoked(&tpk, None));

            t!("New self signature");
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(!revoked(&tpk, Some(selfsig0)));
            // Newer self-sig override older soft revocations.
            assert!(!revoked(&tpk, None));

            t!("Hard revocation");
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();
            // Hard revocations trump all.
            assert!(revoked(&tpk, Some(selfsig0)));
            assert!(revoked(&tpk, None));

            t!("New self signature");
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(revoked(&tpk, Some(selfsig0)));
            assert!(revoked(&tpk, None));
        }
    }

    #[test]
    fn userid_revoked2() {
        fn check_userids<T>(tpk: &TPK, revoked: bool, t: T)
            where T: Into<Option<time::Tm>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = tpk.revoked(None));

            let mut slim_shady = false;
            let mut eminem = false;
            for b in tpk.userids() {
                if b.userid().value() == b"Slim Shady" {
                    assert!(!slim_shady);
                    slim_shady = true;

                    if revoked {
                        assert_match!(RevocationStatus::Revoked(_)
                                      = b.revoked(t));
                    } else {
                        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                      = b.revoked(t));
                    }
                } else {
                    assert!(!eminem);
                    eminem = true;

                    assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                  = b.revoked(t));
                }
            }

            assert!(slim_shady);
            assert!(eminem);
        }

        fn check_uas<T>(tpk: &TPK, revoked: bool, t: T)
            where T: Into<Option<time::Tm>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = tpk.revoked(None));

            assert_eq!(tpk.user_attributes().count(), 1);
            let ua = tpk.user_attributes().nth(0).unwrap();
            if revoked {
                assert_match!(RevocationStatus::Revoked(_)
                              = ua.revoked(t));
            } else {
                assert_match!(RevocationStatus::NotAsFarAsWeKnow
                              = ua.revoked(t));
            }
        }

        tracer!(true, "userid_revoked2", 0);

        let tests : [(&str, Box<Fn(&TPK, bool, _)>); 2] = [
            ("userid", Box::new(check_userids)),
            ("user-attribute", Box::new(check_uas)),
        ];

        for (f, check) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let tpk = TPK::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();

            let now = time::now_utc();
            let selfsig0
                = tpk.userids().map(|b| {
                    b.binding_signature(now).unwrap()
                        .signature_creation_time().unwrap()
                })
                .max().unwrap();

            check(&tpk, false, selfsig0);
            check(&tpk, false, now);

            // A soft-revocation.
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(&tpk, false, selfsig0);
            check(&tpk, true, now);

            // A new self signature.  This should override the soft-revocation.
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(&tpk, false, selfsig0);
            check(&tpk, false, now);

            // A hard revocation.  Unlike for TPKs, this does NOT trumps
            // everything.
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(&tpk, false, selfsig0);
            check(&tpk, true, now);

            // A newer self siganture.
            let tpk = tpk.merge(
                TPK::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(&tpk, false, selfsig0);
            check(&tpk, false, now);
        }
    }

    #[test]
    fn unrevoked() {
        let tpk =
            TPK::from_bytes(crate::tests::key("un-revoked-userid.pgp")).unwrap();

        for uid in tpk.userids() {
            assert_eq!(uid.revoked(None), RevocationStatus::NotAsFarAsWeKnow);
        }
    }

    #[test]
    fn is_tsk() {
        let tpk = TPK::from_bytes(
            crate::tests::key("already-revoked.pgp")).unwrap();
        assert!(! tpk.is_tsk());

        let tpk = TPK::from_bytes(
            crate::tests::key("already-revoked-private.pgp")).unwrap();
        assert!(tpk.is_tsk());
    }

    #[test]
    fn export_only_exports_public_key() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-new-private.pgp")).unwrap();
        assert!(tpk.is_tsk());

        let mut v = Vec::new();
        tpk.serialize(&mut v).unwrap();
        let tpk = TPK::from_bytes(&v).unwrap();
        assert!(! tpk.is_tsk());
    }

    // Make sure that when merging two TPKs, the primary key and
    // subkeys with and without a private key are merged.
    #[test]
    fn public_private_merge() {
        let (tsk, _) = TPKBuilder::autocrypt(None, Some("foo@example.com"))
            .generate().unwrap();
        // tsk is now a tpk, but it still has its private bits.
        assert!(tsk.primary.key().secret().is_some());
        assert!(tsk.is_tsk());
        let subkey_count = tsk.subkeys().len();
        assert!(subkey_count > 0);
        assert!(tsk.subkeys().all(|k| k.key().secret().is_some()));

        // This will write out the tsk as a tpk, i.e., without any
        // private bits.
        let mut tpk_bytes = Vec::new();
        tsk.serialize(&mut tpk_bytes).unwrap();

        // Reading it back in, the private bits have been stripped.
        let tpk = TPK::from_bytes(&tpk_bytes[..]).unwrap();
        assert!(tpk.primary.key().secret().is_none());
        assert!(!tpk.is_tsk());
        assert!(tpk.subkeys().all(|k| k.key().secret().is_none()));

        let merge1 = tpk.clone().merge(tsk.clone()).unwrap();
        assert!(merge1.is_tsk());
        assert!(merge1.primary.key().secret().is_some());
        assert_eq!(merge1.subkeys().len(), subkey_count);
        assert!(merge1.subkeys().all(|k| k.key().secret().is_some()));

        let merge2 = tsk.clone().merge(tpk.clone()).unwrap();
        assert!(merge2.is_tsk());
        assert!(merge2.primary.key().secret().is_some());
        assert_eq!(merge2.subkeys().len(), subkey_count);
        assert!(merge2.subkeys().all(|k| k.key().secret().is_some()));
    }

    #[test]
    fn issue_120() {
        let tpk = b"
-----BEGIN PGP ARMORED FILE-----

xcBNBFoVcvoBCACykTKOJddF8SSUAfCDHk86cNTaYnjCoy72rMgWJsrMLnz/V16B
J9M7l6nrQ0JMnH2Du02A3w+kNb5q97IZ/M6NkqOOl7uqjyRGPV+XKwt0G5mN/ovg
8630BZAYS3QzavYf3tni9aikiGH+zTFX5pynTNfYRXNBof3Xfzl92yad2bIt4ITD
NfKPvHRko/tqWbclzzEn72gGVggt1/k/0dKhfsGzNogHxg4GIQ/jR/XcqbDFR3RC
/JJjnTOUPGsC1y82Xlu8udWBVn5mlDyxkad5laUpWWg17anvczEAyx4TTOVItLSu
43iPdKHSs9vMXWYID0bg913VusZ2Ofv690nDABEBAAHNJFRlc3R5IE1jVGVzdGZh
Y2UgPHRlc3R5QGV4YW1wbGUub3JnPsLAlAQTAQgAPhYhBD6Id8h3J0aSl1GJ9dA/
b4ZSJv6LBQJaFXL6AhsDBQkDwmcABQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ
ENA/b4ZSJv6Lxo8H/1XMt+Nqa6e0SG/up3ypKe5nplA0p/9j/s2EIsP8S8uPUd+c
WS17XOmPwkNDmHeL3J6hzwL74NlYSLEtyf7WoOV74xAKQA9WkqaKPHCtpll8aFWA
ktQDLWTPeKuUuSlobAoRtO17ZmheSQzmm7JYt4Ahkxt3agqGT05OsaAey6nIKqpq
ArokvdHTZ7AFZeSJIWmuCoT9M1lo3LAtLnRGOhBMJ5dDIeOwflJwNBXlJVi4mDPK
+fumV0MbSPvZd1/ivFjSpQyudWWtv1R1nAK7+a4CPTGxPvAQkLtRsL/V+Q7F3BJG
jAn4QVx8p4t3NOPuNgcoZpLBE3sc4Nfs5/CphMLHwE0EWhVy+gEIALSpjYD+tuWC
rj6FGP6crQjQzVlH+7axoM1ooTwiPs4fzzt2iLw3CJyDUviM5F9ZBQTei635RsAR
a/CJTSQYAEU5yXXxhoe0OtwnuvsBSvVT7Fox3pkfNTQmwMvkEbodhfKpqBbDKCL8
f5A8Bb7aISsLf0XRHWDkHVqlz8LnOR3f44wEWiTeIxLc8S1QtwX/ExyW47oPsjs9
ShCmwfSpcngH/vGBRTO7WeI54xcAtKSm/20B/MgrUl5qFo17kUWot2C6KjuZKkHk
3WZmJwQz+6rTB11w4AXt8vKkptYQCkfat2FydGpgRO5dVg6aWNJefOJNkC7MmlzC
ZrrAK8FJ6jcAEQEAAcLAdgQYAQgAIBYhBD6Id8h3J0aSl1GJ9dA/b4ZSJv6LBQJa
FXL6AhsMAAoJENA/b4ZSJv6Lt7kH/jPr5wg8lcamuLj4lydYiLttvvTtDTlD1TL+
IfwVARB/ruoerlEDr0zX1t3DCEcvJDiZfOqJbXtHt70+7NzFXrYxfaNFmikMgSQT
XqHrMQho4qpseVOeJPWGzGOcrxCdw/ZgrWbkDlAU5KaIvk+M4wFPivjbtW2Ro2/F
J4I/ZHhJlIPmM+hUErHC103b08pBENXDQlXDma7LijH5kWhyfF2Ji7Ft0EjghBaW
AeGalQHjc5kAZu5R76Mwt06MEQ/HL1pIvufTFxkr/SzIv8Ih7Kexb0IrybmfD351
Pu1xwz57O4zo1VYf6TqHJzVC3OMvMUM2hhdecMUe5x6GorNaj6g=
=1Vzu
-----END PGP ARMORED FILE-----
";
        assert!(TPK::from_bytes(tpk).is_err());
    }

    #[test]
    fn missing_uids() {
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();
        assert_eq!(tpk.subkeys().len(), 2);
        let pile = tpk
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    &Packet::PublicKey(_) | &Packet::PublicSubkey(_) => true,
                    &Packet::Signature(ref sig) => {
                        sig.typ() == SignatureType::DirectKey
                            || sig.typ() == SignatureType::SubkeyBinding
                    }
                    e => {
                        eprintln!("{:?}", e);
                        false
                    }
                }
            })
        .collect::<Vec<_>>();
        eprintln!("parse back");
        let tpk = TPK::from_packet_pile(PacketPile::from(pile)).unwrap();

        assert_eq!(tpk.subkeys().len(), 2);
    }

    #[test]
    fn signature_order() {
        let neal = TPK::from_bytes(crate::tests::key("neal.pgp")).unwrap();
        let uidb = neal.userids().nth(0).unwrap();
        // Signatures are sorted in ascending order wrt the signature
        // creation time.
        assert!(uidb.selfsigs()[0].signature_creation_time()
                < uidb.selfsigs()[1].signature_creation_time());
        // Make sure we return the most recent here.
        assert_eq!(uidb.selfsigs().last().unwrap(),
                   uidb.binding_signature(None).unwrap());
    }

    #[test]
    fn tpk_reject_keyrings() {
        let mut keyring = Vec::new();
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        assert!(TPK::from_bytes(&keyring).is_err());
    }

    #[test]
    fn tpk_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f(TPK::from_bytes(crate::tests::key("testy-new.pgp")).unwrap());
    }

    #[test]
    fn primary_userid() {
        // 'really-revoked-userid' has two user ids.  One of them is
        // revoked and then restored.  Neither of the user ids has the
        // primary userid bit set.
        //
        // This test makes sure that TPK::primary_userid prefers
        // unrevoked user ids to revoked user ids, even if the latter
        // have newer self signatures.

        let tpk = TPK::from_bytes(
            crate::tests::key("really-revoked-userid-0-public.pgp")).unwrap();

        let now = time::now_utc();
        let selfsig0
            = tpk.userids().map(|b| {
                b.binding_signature(now).unwrap()
                    .signature_creation_time().unwrap()
            })
            .max().unwrap();

        // The self-sig for:
        //
        //   Slim Shady: 2019-09-14T14:21
        //   Eminem:     2019-09-14T14:22
        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"Eminem");

        // A soft-revocation for "Slim Shady".
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("really-revoked-userid-1-soft-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"Eminem");

        // A new self signature for "Slim Shady".  This should
        // override the soft-revocation.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("really-revoked-userid-2-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"Slim Shady");

        // A hard revocation for "Slim Shady".
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("really-revoked-userid-3-hard-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"Eminem");

        // A newer self siganture for "Slim Shady". Unlike for TPKs, this
        // does NOT trump everything.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("really-revoked-userid-4-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"Slim Shady");

        // Play with the primary user id flag.

        let tpk = TPK::from_bytes(
            crate::tests::key("primary-key-0-public.pgp")).unwrap();
        let selfsig0
            = tpk.userids().map(|b| {
                b.binding_signature(now).unwrap()
                    .signature_creation_time().unwrap()
            })
            .max().unwrap();

        // There is only a single User ID.
        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"aaaaa");


        // Add a second user id.  Since neither is marked primary, the
        // newer one should be considered primary.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-1-add-userid-bbbbb.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"bbbbb");

        // Mark aaaaa as primary.  It is now primary and the newest one.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-2-make-aaaaa-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"aaaaa");

        // Update the preferences on bbbbb.  It is now the newest, but
        // it is not marked as primary.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-3-make-bbbbb-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"aaaaa");

        // Mark bbbbb as primary.  It is now the newest and marked as
        // primary.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-4-make-bbbbb-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"bbbbb");

        // Update the preferences on aaaaa.  It is now has the newest
        // self sig, but that self sig does not say that it is
        // primary.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-5-make-aaaaa-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"bbbbb");

        // Hard revoke aaaaa.  Unlike with TPKs, a hard revocation is
        // not treated specially.
        let tpk = tpk.merge(
            TPK::from_bytes(
                crate::tests::key("primary-key-6-revoked-aaaaa.pgp")
            ).unwrap()).unwrap();

        assert_eq!(tpk.primary_userid(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(tpk.primary_userid(now).unwrap().userid().value(), b"bbbbb");
    }
}
