//! Certificates and related data structures.

use std::io;
use std::cmp;
use std::cmp::Ordering;
use std::path::Path;
use std::mem;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::time;

use anyhow::Context;

use crate::{
    crypto::Signer,
    Error,
    Result,
    SignatureType,
    packet,
    packet::Signature,
    packet::Key,
    packet::key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    Packet,
    PacketPile,
    KeyID,
    Fingerprint,
    KeyHandle,
    policy::Policy,
};
use crate::parse::{Parse, PacketParserResult, PacketParser};
use crate::types::{
    AEADAlgorithm,
    CompressionAlgorithm,
    Features,
    HashAlgorithm,
    KeyServerPreferences,
    ReasonForRevocation,
    RevocationStatus,
    SymmetricAlgorithm,
};

pub mod amalgamation;
mod builder;
mod bindings;
pub mod components;
mod component_iter;
mod keyiter;
pub mod key_amalgamation;
mod parser;
mod revoke;

pub use self::builder::{CertBuilder, CipherSuite};

pub use parser::{
    KeyringValidity,
    KeyringValidator,
    CertParser,
    CertValidity,
    CertValidator,
};

pub use revoke::{
    SubkeyRevocationBuilder,
    CertRevocationBuilder,
    UserAttributeRevocationBuilder,
    UserIDRevocationBuilder,
};

pub mod prelude;
use prelude::*;

const TRACE : bool = false;

// Helper functions.

/// Compare the creation time of two signatures.  Order them so that
/// the more recent signature is first.
fn canonical_signature_order(a: Option<time::SystemTime>, b: Option<time::SystemTime>)
                             -> Ordering {
    // Note: None < Some, so the normal ordering is:
    //
    //   None, Some(old), Some(new)
    //
    // Reversing the ordering puts the signatures without a creation
    // time at the end, which is where they belong.
    a.cmp(&b).reverse()
}

fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
    match canonical_signature_order(a.signature_creation_time(),
                                    b.signature_creation_time()) {
        Ordering::Equal => a.mpis().cmp(b.mpis()),
        r => r
    }
}

impl fmt::Display for Cert {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

/// A collection of `ComponentBundles`.
///
/// Note: we need this, because we can't `impl Vec<ComponentBundles>`.
#[derive(Debug, Clone, PartialEq)]
struct ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    bindings: Vec<ComponentBundle<C>>,
}

impl<C> Deref for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    type Target = Vec<ComponentBundle<C>>;

    fn deref(&self) -> &Self::Target {
        &self.bindings
    }
}

impl<C> DerefMut for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn deref_mut(&mut self) -> &mut Vec<ComponentBundle<C>> {
        &mut self.bindings
    }
}

impl<C> Into<Vec<ComponentBundle<C>>> for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn into(self) -> Vec<ComponentBundle<C>> {
        self.bindings
    }
}

impl<C> IntoIterator for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    type Item = ComponentBundle<C>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bindings.into_iter()
    }
}

impl<C> ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn new() -> Self {
        Self { bindings: vec![] }
    }
}

impl<C> ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
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
        // to sort the bindings by their components.

        self.bindings.sort_unstable_by(
            |a, b| cmp(&a.component, &b.component));

        self.bindings.dedup_by(|a, b| {
            if cmp(&a.component, &b.component) == Ordering::Equal {
                // Merge.
                merge(&mut a.component, &mut b.component);

                // Recall: if a and b are equal, a will be dropped.
                b.self_signatures.append(&mut a.self_signatures);
                b.certifications.append(&mut a.certifications);
                b.self_revocations.append(&mut a.self_revocations);
                b.other_revocations.append(&mut a.other_revocations);

                true
            } else {
                false
            }
        });

        // And sort the certificates.
        for b in self.bindings.iter_mut() {
            b.sort_and_dedup();
        }
    }
}

/// A vecor of key (primary or subkey, public or private) and any
/// associated signatures.
type KeyBundles<KeyPart, KeyRole> = ComponentBundles<Key<KeyPart, KeyRole>>;

/// A vector of subkeys and any associated signatures.
type SubkeyBindings<KeyPart> = KeyBundles<KeyPart, key::SubordinateRole>;

/// A vector of key (primary or subkey, public or private) and any
/// associated signatures.
#[allow(dead_code)]
type GenericKeyBindings
    = ComponentBundles<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A vector of User ID bindings and any associated signatures.
type UserIDBindings = ComponentBundles<UserID>;

/// A vector of User Attribute bindings and any associated signatures.
type UserAttributeBindings = ComponentBundles<UserAttribute>;

/// A vector of unknown components and any associated signatures.
///
/// Note: all signatures are stored as certifications.
type UnknownBindings = ComponentBundles<Unknown>;

/// Queries certificate holder's preferences.
///
/// A certificate's key holder controls the primary key.  Subpackets
/// on self signatures can be used to express preferences for
/// algorithms and key management.  Furthermore, the key holder's
/// OpenPGP implementation can express its feature set.
pub trait Preferences<'a> {
    /// Returns symmetric algorithms that the key holder prefers.
    ///
    /// The algorithms are ordered according by the key holder's
    fn preferred_symmetric_algorithms(&self)
        -> Option<&'a [SymmetricAlgorithm]>;

    /// Returns hash algorithms that the key holder prefers.
    ///
    /// The algorithms are ordered according by the key holder's
    /// preference.
    fn preferred_hash_algorithms(&self) -> Option<&'a [HashAlgorithm]>;

    /// Returns compression algorithms that the key holder prefers.
    ///
    /// The algorithms are ordered according by the key holder's
    /// preference.
    fn preferred_compression_algorithms(&self)
        -> Option<&'a [CompressionAlgorithm]>;

    /// Returns AEAD algorithms that the key holder prefers.
    ///
    /// The algorithms are ordered according by the key holder's
    /// preference.
    fn preferred_aead_algorithms(&self) -> Option<&'a [AEADAlgorithm]>;

    /// Returns the key holder's keyserver preferences.
    fn key_server_preferences(&self) -> Option<KeyServerPreferences>;

    /// Returns the key holder's preferred keyserver for updates.
    fn preferred_key_server(&self) -> Option<&'a [u8]>;

    /// Returns the key holder's feature set.
    fn features(&self) -> Option<Features>;
}

// DOC-HACK: To avoid having a top-level re-export of `Cert`, we move
// it in a submodule `def`.
pub use def::Cert;
mod def {
use super::*;
/// A collection of keys, signatures, and metadata.
///
/// A Certificate (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// Certs are always canonicalized in the sense that only elements
/// (user id, user attribute, subkey) with at least one valid
/// self-signature at a given time under a given policy are used.
/// However, we keep all packets around for re-serialization.  It
/// could be an component that we simply do not understand.
/// The self-signatures are sorted so that the newest
/// self-signature comes first.  Components are sorted, but in an
/// undefined manner (i.e., when parsing the same Cert multiple times,
/// the components will be in the same order, but we reserve the right
/// to change the sort function between versions).  Third-party
/// certifications are *not* validated, as the keys are not available;
/// they are simply passed through as is.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
///
/// # Secret keys
///
/// Any key in a `Cert` may have a secret key attached to it.  To
/// protect secret keys from being leaked, secret keys are not written
/// out if a `Cert` is serialized.  To also serialize the secret keys,
/// you need to use [`Cert::as_tsk()`] to get an object that writes
/// them out during serialization.
///
/// [`Cert::as_tsk()`]: #method.as_tsk
///
/// # Filtering certificates
///
/// To filter certificates, iterate over all components, clone what
/// you want to keep, and reassemble the certificate.  The following
/// example simply copies all the packets, and can be adapted to
/// suit your policy:
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::cert::prelude::*;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// fn identity_filter(cert: &Cert) -> Result<Cert> {
///     // Iterate over all of the Cert components, pushing packets we
///     // want to keep into the accumulator.
///     let mut acc = Vec::new();
///
///     // Primary key and related signatures.
///     let c = cert.primary_key();
///     acc.push(c.key().clone().into());
///     for s in c.self_signatures()   { acc.push(s.clone().into()) }
///     for s in c.certifications()    { acc.push(s.clone().into()) }
///     for s in c.self_revocations()  { acc.push(s.clone().into()) }
///     for s in c.other_revocations() { acc.push(s.clone().into()) }
///
///     // UserIDs and related signatures.
///     for c in cert.userids() {
///         acc.push(c.userid().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // UserAttributes and related signatures.
///     for c in cert.user_attributes() {
///         acc.push(c.user_attribute().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Subkeys and related signatures.
///     for c in cert.keys().subkeys() {
///         acc.push(c.key().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Unknown components and related signatures.
///     for c in cert.unknowns() {
///         acc.push(c.unknown().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Any signatures that we could not associate with a component.
///     for s in cert.bad_signatures()     { acc.push(s.clone().into()) }
///
///     // Finally, parse into Cert.
///     Cert::from_packet_pile(acc.into())
/// }
///
/// let (cert, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///     .generate()?;
/// assert_eq!(cert, identity_filter(&cert)?);
/// #     Ok(())
/// # }
/// ```
///
/// # Example
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::Cert;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(&b""[..])?;
/// match Cert::from_packet_parser(ppr) {
///     Ok(cert) => {
///         println!("Key: {}", cert.fingerprint());
///         for uid in cert.userids() {
///             println!("User ID: {}", uid.userid());
///         }
///     }
///     Err(err) => {
///         eprintln!("Error parsing Cert: {}", err);
///     }
/// }
///
/// #     Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Cert {
    pub(super) // doc-hack, see above
    primary: PrimaryKeyBundle<key::PublicParts>,

    pub(super) // doc-hack, see above
    userids: UserIDBindings,
    pub(super) // doc-hack, see above
    user_attributes: UserAttributeBindings,
    pub(super) // doc-hack, see above
    subkeys: SubkeyBindings<key::PublicParts>,

    // Unknown components, e.g., some UserAttribute++ packet from the
    // future.
    pub(super) // doc-hack, see above
    unknowns: UnknownBindings,
    // Signatures that we couldn't find a place for.
    pub(super) // doc-hack, see above
    bad: Vec<packet::Signature>,
}
} // doc-hack, see above

impl std::str::FromStr for Cert {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl<'a> Parse<'a, Cert> for Cert {
    /// Returns the first Cert encountered in the reader.
    fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_reader(reader)?)
    }

    /// Returns the first Cert encountered in the file.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_file(path)?)
    }

    /// Returns the first Cert found in `buf`.
    ///
    /// `buf` must be an OpenPGP-encoded message.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_bytes(data)?)
    }
}

impl Cert {
    /// Returns the amalgamated primary key.
    pub fn primary_key(&self) -> PrimaryKeyAmalgamation<key::PublicParts>
    {
        PrimaryKeyAmalgamation::new(&self)
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    pub fn direct_key_signature<T>(&self, policy: &dyn Policy, t: T)
        -> Result<&Signature>
        where T: Into<Option<time::SystemTime>>
    {
        self.primary.binding_signature(policy, t)
    }

    /// Returns the Cert's revocation status at time `t`.
    ///
    /// A Cert is revoked at time `t` if:
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
    /// Note: this only returns whether this Cert is revoked; it does
    /// not imply anything about the Cert or other components.
    pub fn revoked<T>(&self, policy: &dyn Policy, t: T) -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        // Both a primary key signature and the primary userid's
        // binding signature can override a soft revocation.  Compute
        // the most recent one.
        let vkao = self.primary_key().with_policy(policy, t).ok();
        let mut sig = vkao.as_ref().map(|vka| vka.binding_signature());
        if let Some(direct) = vkao.as_ref()
            .and_then(|vka| vka.direct_key_signature().ok())
        {
            match (direct.signature_creation_time(),
                   sig.and_then(|s| s.signature_creation_time())) {
                (Some(ds), Some(bs)) if ds > bs =>
                    sig = Some(direct),
                _ => ()
            }
        }
        self.primary_key().bundle()._revoked(policy, t, true, sig)
    }

    /// Revokes the Cert in place.
    ///
    /// Note: to just generate a revocation certificate, use the
    /// `CertRevocationBuilder`.
    ///
    /// If you want to revoke an individual component, use
    /// `SubkeyRevocationBuilder`, `UserIDRevocationBuilder`, or
    /// `UserAttributeRevocationBuilder`, as appropriate.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::RevocationStatus;
    /// use openpgp::types::{ReasonForRevocation, SignatureType};
    /// use openpgp::cert::prelude::*;
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let p = &StandardPolicy::new();
    ///
    /// let (mut cert, _) = CertBuilder::new()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
    ///            cert.revoked(p, None));
    ///
    /// let mut keypair = cert.primary_key().key().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    /// let cert = cert.revoke_in_place(&mut keypair,
    ///                               ReasonForRevocation::KeyCompromised,
    ///                               b"It was the maid :/")?;
    /// if let RevocationStatus::Revoked(sigs) = cert.revoked(p, None) {
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
    pub fn revoke_in_place(self, primary_signer: &mut dyn Signer,
                           code: ReasonForRevocation, reason: &[u8])
        -> Result<Cert>
    {
        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(code, reason)?
            .build(primary_signer, &self, None)?;
        self.merge_packets(vec![sig.into()])
    }

    /// Returns whether or not the Cert is alive at `t`.
    pub fn alive<T>(&self, policy: &dyn Policy, t: T) -> Result<()>

        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self.primary_key()
            .with_policy(policy, t).context(
                "primary key rejected by policy")?
            .alive()
    }

    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    #[cfg(test)]
    fn set_validity_period_as_of(self, policy: &dyn Policy,
                                 primary_signer: &mut dyn Signer,
                                 expiration: Option<time::Duration>,
                                 now: time::SystemTime)
        -> Result<Cert>
    {
        let primary = self.primary_key().with_policy(policy, now)?;
        let sigs = primary.set_validity_period_as_of(primary_signer,
                                                     expiration,
                                                     now)?;
        self.merge_packets(sigs)
    }

    /// Sets the key to expire at the given time.
    ///
    /// A policy is needed, because the expiration is updated by adding
    /// a self-signature to the primary user id.
    pub fn set_expiration_time(self, policy: &dyn Policy,
                               primary_signer: &mut dyn Signer,
                               expiration: Option<time::SystemTime>)
        -> Result<Cert>
    {
        let now = time::SystemTime::now();
        let primary = self.primary_key().with_policy(policy, now)?;
        let sigs = primary.set_expiration_time(primary_signer,
                                               expiration)?;
        self.merge_packets(sigs)
    }

    /// Returns the amalgamated primary userid at `t`, if any.
    fn primary_userid_relaxed<'a, T>(&'a self, policy: &'a dyn Policy, t: T,
                                     valid_cert: bool)
        -> Result<ValidComponentAmalgamation<'a, UserID>>
        where T: Into<Option<std::time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(std::time::SystemTime::now);
        ValidComponentAmalgamation::primary(self, self.userids.iter(),
                                            policy, t, valid_cert)
    }

    /// Returns the amalgamated primary userid at `t`, if any.
    pub fn primary_userid<'a, T>(&'a self, policy: &'a dyn Policy, t: T)
        -> Result<ValidComponentAmalgamation<'a, UserID>>
        where T: Into<Option<std::time::SystemTime>>
    {
        self.primary_userid_relaxed(policy, t, true)
    }

    /// Returns an iterator over the Cert's userids.
    pub fn userids(&self) -> ComponentIter<UserID> {
        ComponentIter::new(self, self.userids.iter())
    }

    /// Returns the amalgamated primary user attribute at `t`, if any.
    pub fn primary_user_attribute<'a, T>(&'a self, policy: &'a dyn Policy, t: T)
        -> Result<ValidComponentAmalgamation<'a, UserAttribute>>
        where T: Into<Option<std::time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(std::time::SystemTime::now);
        ValidComponentAmalgamation::primary(self, self.user_attributes.iter(),
                                            policy, t, true)
    }

    /// Returns an iterator over the Cert's `UserAttributeBundle`s.
    pub fn user_attributes(&self) -> ComponentIter<UserAttribute> {
        ComponentIter::new(self, self.user_attributes.iter())
    }

    /// Returns an iterator over the Cert's subkeys.
    pub(crate) fn subkeys(&self) -> UnfilteredKeyBundleIter<key::PublicParts,
                                            key::SubordinateRole>
    {
        UnfilteredKeyBundleIter { iter: Some(self.subkeys.iter()) }
    }

    /// Returns an iterator over the Cert's unknown components.
    pub fn unknowns(&self) -> UnknownBundleIter {
        UnknownBundleIter { iter: Some(self.unknowns.iter()) }
    }

    /// Returns a slice containing all bad signatures.
    ///
    /// Bad signatures are signatures that we could not associate with
    /// one of the components.
    pub fn bad_signatures(&self) -> &[Signature] {
        &self.bad
    }

    /// Returns an iterator over the certificate's keys.
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys.
    pub fn keys(&self) -> KeyIter<key::PublicParts, key::UnspecifiedRole>
    {
        KeyIter::new(self)
    }

    /// Returns the Cert found in the packet stream.
    ///
    /// If there are more packets after the Cert, e.g. because the
    /// packet stream is a keyring, this function will return
    /// `Error::MalformedCert`.
    pub fn from_packet_parser(ppr: PacketParserResult) -> Result<Self> {
        let mut parser = parser::CertParser::from_packet_parser(ppr);
        if let Some(cert_result) = parser.next() {
            if parser.next().is_some() {
                Err(Error::MalformedCert(
                    "Additional packets found, is this a keyring?".into()
                ).into())
            } else {
                cert_result
            }
        } else {
            Err(Error::MalformedCert("No data".into()).into())
        }
    }

    /// Returns the first Cert found in the `PacketPile`.
    pub fn from_packet_pile(p: PacketPile) -> Result<Self> {
        let mut i = parser::CertParser::from_iter(p.into_children());
        match i.next() {
            Some(Ok(cert)) => Ok(cert),
            Some(Err(err)) => Err(err),
            None => Err(Error::MalformedCert("No data".into()).into()),
        }
    }

    fn canonicalize(mut self) -> Self {
        tracer!(TRACE, "canonicalize", 0);

        // The very first thing that we do is verify the
        // self-signatures.  There are a few things that we need to be
        // aware of:
        //
        //  - Signatures may be invalid.  These should be dropped.
        //
        //  - Signatures may be out of order.  These should be
        //    reordered so that we have the latest self-signature and
        //    we don't drop a userid or subkey that is actually
        //    valid.

        // We collect bad signatures here in self.bad.  Below, we'll
        // test whether they are just out of order by checking them
        // against all userids and subkeys.  Furthermore, this may be
        // a partial Cert that is merged into an older copy.

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
                    if let Ok(()) = sig.$verify_method(self.primary.key(),
                                                       self.primary.key(),
                                                       $($verify_args),*) {
                        $binding.$sigs.push(sig);
                    } else {
                        t!("Sig {:02X}{:02X}, type = {} doesn't belong to {}",
                           sig.digest_prefix()[0], sig.digest_prefix()[1],
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

        // The same as check!, but for third party signatures.  If we
        // do have the key that made the signature, we can verify it
        // like in check!.  Otherwise, we use the hash prefix as
        // heuristic approximating the verification.
        macro_rules! check_3rd_party {
            ($desc:expr,            // a description of the component
             $binding:expr,         // the binding to check
             $sigs:ident,           // a vector of sigs in $binding to check
             $lookup_fn:expr,       // a function to lookup keys
             $verify_method:ident,  // the method to call to verify it
             $hash_method:ident,    // the method to call to compute the hash
             $($verify_args:expr),* // additional arguments to pass to the above
            ) => ({
                t!("check_3rd_party!({}, {}, {:?}, {}, {}, ...)",
                   $desc, stringify!($binding), $binding.$sigs,
                   stringify!($verify_method), stringify!($hash_method));
                for sig in mem::replace(&mut $binding.$sigs, Vec::new())
                    .into_iter()
                {
                    // Use hash prefix as heuristic.
                    if let Ok(hash) = Signature::$hash_method(
                        &sig, self.primary.key(), $($verify_args),*) {
                        if &sig.digest_prefix()[..] == &hash[..2] {
                            // See if we can get the key for a
                            // positive verification.
                            if let Some(key) = $lookup_fn(&sig) {
                                if let Ok(()) = sig.$verify_method(
                                    &key, self.primary.key(), $($verify_args),*)
                                {
                                    $binding.$sigs.push(sig);
                                } else {
                                    t!("Sig {:02X}{:02X}, type = {} \
                                        doesn't belong to {}",
                                       sig.digest_prefix()[0],
                                       sig.digest_prefix()[1],
                                       sig.typ(), $desc);

                                    self.bad.push(sig);
                                }
                            } else {
                                // No key, we need to trust our heuristic.
                                $binding.$sigs.push(sig);
                            }
                        } else {
                            t!("Sig {:02X}{:02X}, type = {} \
                                doesn't belong to {}",
                               sig.digest_prefix()[0], sig.digest_prefix()[1],
                               sig.typ(), $desc);

                            self.bad.push(sig);
                        }
                    } else {
                        // Hashing failed, we likely don't support
                        // the hash algorithm.
                        t!("Sig {:02X}{:02X}, type = {}: \
                            Hashing failed",
                           sig.digest_prefix()[0], sig.digest_prefix()[1],
                           sig.typ());

                        self.bad.push(sig);
                    }
                }
            });
            ($desc:expr, $binding:expr, $sigs:ident, $lookup_fn:expr,
             $verify_method:ident, $hash_method:ident) => ({
                 check_3rd_party!($desc, $binding, $sigs, $lookup_fn,
                                  $verify_method, $hash_method, )
            });
        }

        // Placeholder lookup function.
        fn lookup_fn(_: &Signature)
                     -> Option<Key<key::PublicParts, key::UnspecifiedRole>> {
            None
        }

        check!("primary key",
               self.primary, self_signatures, verify_direct_key);
        check!("primary key",
               self.primary, self_revocations, verify_primary_key_revocation);
        check_3rd_party!("primary key",
                         self.primary, certifications, lookup_fn,
                         verify_direct_key, hash_direct_key);
        check_3rd_party!("primary key",
                         self.primary, other_revocations, lookup_fn,
                         verify_primary_key_revocation, hash_direct_key);

        for binding in self.userids.iter_mut() {
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, self_signatures, verify_userid_binding,
                   binding.userid());
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, self_revocations, verify_userid_revocation,
                   binding.userid());
            check_3rd_party!(
                format!("userid \"{}\"",
                        String::from_utf8_lossy(binding.userid().value())),
                binding, certifications, lookup_fn,
                verify_userid_binding, hash_userid_binding,
                binding.userid());
            check_3rd_party!(
                format!("userid \"{}\"",
                        String::from_utf8_lossy(binding.userid().value())),
                binding, other_revocations, lookup_fn,
                verify_userid_revocation, hash_userid_binding,
                binding.userid());
        }

        for binding in self.user_attributes.iter_mut() {
            check!("user attribute",
                   binding, self_signatures, verify_user_attribute_binding,
                   binding.user_attribute());
            check!("user attribute",
                   binding, self_revocations, verify_user_attribute_revocation,
                   binding.user_attribute());
            check_3rd_party!(
                "user attribute",
                binding, certifications, lookup_fn,
                verify_user_attribute_binding, hash_user_attribute_binding,
                binding.user_attribute());
            check_3rd_party!(
                "user attribute",
                binding, other_revocations, lookup_fn,
                verify_user_attribute_revocation, hash_user_attribute_binding,
                binding.user_attribute());
        }

        for binding in self.subkeys.iter_mut() {
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, self_signatures, verify_subkey_binding,
                   binding.key());
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, self_revocations, verify_subkey_revocation,
                   binding.key());
            check_3rd_party!(
                format!("subkey {}", binding.key().keyid()),
                binding, certifications, lookup_fn,
                verify_subkey_binding, hash_subkey_binding,
                binding.key());
            check_3rd_party!(
                format!("subkey {}", binding.key().keyid()),
                binding, other_revocations, lookup_fn,
                verify_subkey_revocation, hash_subkey_binding,
                binding.key());
        }

        // See if the signatures that didn't validate are just out of
        // place.
        let mut bad_sigs: Vec<(Option<usize>, Signature)> =
            mem::replace(&mut self.bad, Vec::new()).into_iter()
            .map(|sig| (None, sig)).collect();

        // Do the same for signatures on unknown components, but
        // remember where we took them from.
        for (i, c) in self.unknowns.iter_mut().enumerate() {
            for sig in mem::replace(&mut c.certifications, Vec::new()) {
                bad_sigs.push((Some(i), sig));
            }
        }

        'outer: for (unknown_idx, sig) in bad_sigs {
            // Did we find a new place for sig?
            let mut found_component = false;

            macro_rules! check_one {
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident, $($verify_args:expr),*) => ({
                     t!("check_one!({}, {:?}, {:?}, {}, ...)",
                        $desc, $sigs, $sig,
                        stringify!($verify_method));
                     if let Ok(())
                         = $sig.$verify_method(self.primary.key(),
                                               self.primary.key(),
                                               $($verify_args),*)
                     {
                         t!("Sig {:02X}{:02X}, {:?} \
                             was out of place.  Belongs to {}.",
                            $sig.digest_prefix()[0],
                            $sig.digest_prefix()[1],
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

            // The same as check_one!, but for third party signatures.
            // If we do have the key that made the signature, we can
            // verify it like in check!.  Otherwise, we use the hash
            // prefix as heuristic approximating the verification.
            macro_rules! check_one_3rd_party {
                ($desc:expr,            // a description of the component
                 $sigs:expr,            // where to put $sig if successful
                 $sig:ident,            // the signature to check
                 $lookup_fn:expr,       // a function to lookup keys
                 $verify_method:ident,  // the method to verify it
                 $hash_method:ident,    // the method to compute the hash
                 $($verify_args:expr),* // additional arguments for the above
                ) => ({
                    t!("check_one_3rd_party!({}, {}, {:?}, {}, {}, ...)",
                       $desc, stringify!($sigs), $sig,
                       stringify!($verify_method), stringify!($hash_method));
                    if let Some(key) = $lookup_fn(&sig) {
                        if let Ok(()) = sig.$verify_method(&key,
                                                           self.primary.key(),
                                                           $($verify_args),*)
                        {
                            t!("Sig {:02X}{:02X}, {:?} \
                                was out of place.  Belongs to {}.",
                               $sig.digest_prefix()[0],
                               $sig.digest_prefix()[1],
                               $sig.typ(), $desc);

                            $sigs.push($sig);
                            continue 'outer;
                        }
                    } else {
                        // Use hash prefix as heuristic.
                        if let Ok(hash) = Signature::$hash_method(
                            &sig, self.primary.key(), $($verify_args),*) {
                            if &sig.digest_prefix()[..] == &hash[..2] {
                                t!("Sig {:02X}{:02X}, {:?} \
                                    was out of place.  Likely belongs to {}.",
                                   $sig.digest_prefix()[0],
                                   $sig.digest_prefix()[1],
                                   $sig.typ(), $desc);

                                $sigs.push($sig.clone());
                                // The cost of missing a revocation
                                // certificate merely because we put
                                // it into the wrong place seem to
                                // outweigh the cost of duplicating
                                // it.
                                t!("Will keep trying to match this sig to \
                                    other components (found before? {:?})...",
                                   found_component);
                                found_component = true;
                            }
                        }
                    }
                });
                ($desc:expr, $sigs:expr, $sig:ident, $lookup_fn:expr,
                 $verify_method:ident, $hash_method:ident) => ({
                     check_one_3rd_party!($desc, $sigs, $sig, $lookup_fn,
                                          $verify_method, $hash_method, )
                 });
            }

            use SignatureType::*;
            match sig.typ() {
                DirectKey => {
                    check_one!("primary key", self.primary.self_signatures,
                               sig, verify_direct_key);
                    check_one_3rd_party!(
                        "primary key", self.primary.certifications, sig,
                        lookup_fn,
                        verify_direct_key, hash_direct_key);
                },

                KeyRevocation => {
                    check_one!("primary key", self.primary.self_revocations,
                               sig, verify_primary_key_revocation);
                    check_one_3rd_party!(
                        "primary key", self.primary.other_revocations, sig,
                        lookup_fn, verify_primary_key_revocation,
                        hash_direct_key);
                },

                GenericCertification | PersonaCertification
                    | CasualCertification | PositiveCertification =>
                {
                    for binding in self.userids.iter_mut() {
                        check_one!(format!("userid \"{}\"",
                                           String::from_utf8_lossy(
                                               binding.userid().value())),
                                   binding.self_signatures, sig,
                                   verify_userid_binding, binding.userid());
                        check_one_3rd_party!(
                            format!("userid \"{}\"",
                                    String::from_utf8_lossy(
                                        binding.userid().value())),
                            binding.certifications, sig, lookup_fn,
                            verify_userid_binding, hash_userid_binding,
                            binding.userid());
                    }

                    for binding in self.user_attributes.iter_mut() {
                        check_one!("user attribute",
                                   binding.self_signatures, sig,
                                   verify_user_attribute_binding,
                                   binding.user_attribute());
                        check_one_3rd_party!(
                            "user attribute",
                            binding.certifications, sig, lookup_fn,
                            verify_user_attribute_binding,
                            hash_user_attribute_binding,
                            binding.user_attribute());
                    }
                },

                CertificationRevocation => {
                    for binding in self.userids.iter_mut() {
                        check_one!(format!("userid \"{}\"",
                                           String::from_utf8_lossy(
                                               binding.userid().value())),
                                   binding.self_revocations, sig,
                                   verify_userid_revocation,
                                   binding.userid());
                        check_one_3rd_party!(
                            format!("userid \"{}\"",
                                    String::from_utf8_lossy(
                                        binding.userid().value())),
                            binding.other_revocations, sig, lookup_fn,
                            verify_userid_revocation, hash_userid_binding,
                            binding.userid());
                    }

                    for binding in self.user_attributes.iter_mut() {
                        check_one!("user attribute",
                                   binding.self_revocations, sig,
                                   verify_user_attribute_revocation,
                                   binding.user_attribute());
                        check_one_3rd_party!(
                            "user attribute",
                            binding.other_revocations, sig, lookup_fn,
                            verify_user_attribute_revocation,
                            hash_user_attribute_binding,
                            binding.user_attribute());
                    }
                },

                SubkeyBinding => {
                    for binding in self.subkeys.iter_mut() {
                        check_one!(format!("subkey {}", binding.key().keyid()),
                                   binding.self_signatures, sig,
                                   verify_subkey_binding, binding.key());
                        check_one_3rd_party!(
                            format!("subkey {}", binding.key().keyid()),
                            binding.certifications, sig, lookup_fn,
                            verify_subkey_binding, hash_subkey_binding,
                            binding.key());
                    }
                },

                SubkeyRevocation => {
                    for binding in self.subkeys.iter_mut() {
                        check_one!(format!("subkey {}", binding.key().keyid()),
                                   binding.self_revocations, sig,
                                   verify_subkey_revocation, binding.key());
                        check_one_3rd_party!(
                            format!("subkey {}", binding.key().keyid()),
                            binding.other_revocations, sig, lookup_fn,
                            verify_subkey_revocation, hash_subkey_binding,
                            binding.key());
                    }
                },

                typ => {
                    t!("Odd signature type: {:?}", typ);
                },
            }

            if found_component {
                continue;
            }

            // Keep them for later.
            t!("Self-sig {:02X}{:02X}, {:?} doesn't belong \
                to any known component or is bad.",
               sig.digest_prefix()[0], sig.digest_prefix()[1],
               sig.typ());

            if let Some(i) = unknown_idx {
                self.unknowns[i].certifications.push(sig);
            } else {
                self.bad.push(sig);
            }
        }

        if self.bad.len() > 0 {
            t!("{}: ignoring {} bad self-signatures",
               self.keyid(), self.bad.len());
        }

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
            |a, b| {
                // Recall: if a and b are equal, a will be dropped.
                if ! b.has_secret() && a.has_secret() {
                    std::mem::swap(a, b);
                }
            });

        let primary_fp: KeyHandle = self.key_handle();
        let primary_keyid = KeyHandle::KeyID(primary_fp.clone().into());
        for c in self.unknowns.iter_mut() {
            parser::split_sigs(&primary_fp, &primary_keyid, c);
        }
        self.unknowns.sort_and_dedup(Unknown::best_effort_cmp, |_, _| {});

        // XXX: Check if the sigs in other_sigs issuer are actually
        // designated revokers for this key (listed in a "Revocation
        // Key" subpacket in *any* non-revoked self-signature).  Only
        // if that is the case should a sig be considered a potential
        // revocation.  (This applies to
        // self.primary_other_revocations as well as
        // self.userids().other_revocations, etc.)  If not, put the
        // sig on the bad list.
        //
        // Note: just because the Cert doesn't indicate that a key is a
        // designed revoker doesn't mean that it isn't---we might just
        // be missing the signature.  In other words, this is a policy
        // decision, but given how easy it could be to create rogue
        // revocations, is probably the better to reject such
        // signatures than to keep them around and have many keys
        // being shown as "potentially revoked".

        // XXX Do some more canonicalization.

        self
    }

    /// Returns the Cert's fingerprint.
    pub fn key_handle(&self) -> KeyHandle {
        self.primary.key().key_handle()
    }

    /// Returns the Cert's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary.key().fingerprint()
    }

    /// Returns the Cert's keyid.
    pub fn keyid(&self) -> KeyID {
        self.primary.key().keyid()
    }

    /// Converts the Cert into an iterator over a sequence of packets.
    ///
    /// This method discards invalid components and bad signatures.
    pub fn into_packets(self) -> impl Iterator<Item=Packet> {
        self.primary.into_packets()
            .chain(self.userids.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.user_attributes.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.subkeys.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.unknowns.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.bad.into_iter().map(|s| s.into()))
    }

    /// Converts the Cert into a `PacketPile`.
    ///
    /// This method discards invalid components and bad signatures.
    pub fn into_packet_pile(self) -> PacketPile {
        PacketPile::from(self.into_packets().collect::<Vec<Packet>>())
    }

    /// Merges `other` into `self`.
    ///
    /// If `other` is a different key, then an error is returned.
    pub fn merge(mut self, mut other: Cert) -> Result<Self> {
        if self.fingerprint() != other.fingerprint()
        {
            // The primary key is not the same.  There is nothing to
            // do.
            return Err(Error::InvalidArgument(
                "Primary key mismatch".into()).into());
        }

        if ! self.primary.key().has_secret()
            && other.primary.key().has_secret()
        {
            std::mem::swap(self.primary.key_mut(), other.primary.key_mut());
        }

        self.primary.self_signatures.append(
            &mut other.primary.self_signatures);
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

    /// Adds packets to the Cert.
    ///
    /// This recanonicalizes the Cert.  If the packets are invalid,
    /// they are dropped.
    ///
    /// If a key is merged in that already exists in the cert, it
    /// replaces the key.  This way, secret key material can be added,
    /// removed, encrypted, or decrypted.
    pub fn merge_packets(self, packets: Vec<Packet>) -> Result<Self> {
        let mut combined = self.into_packets().collect::<Vec<_>>();

        fn replace_or_push<P, R>(acc: &mut Vec<Packet>, k: Key<P, R>)
            where P: key::KeyParts,
                  R: key::KeyRole,
                  Packet: From<packet::Key<P, R>>,
        {
            for q in acc.iter_mut() {
                let replace = match q {
                    Packet::PublicKey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::SecretKey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::PublicSubkey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::SecretSubkey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    _ => false,
                };

                if replace {
                    *q = k.into();
                    return;
                }
            }
            acc.push(k.into());
        };

        for p in packets.into_iter() {
            match p {
                Packet::PublicKey(k) => replace_or_push(&mut combined, k),
                Packet::SecretKey(k) => replace_or_push(&mut combined, k),
                Packet::PublicSubkey(k) => replace_or_push(&mut combined, k),
                Packet::SecretSubkey(k) => replace_or_push(&mut combined, k),
                p => combined.push(p),
            }
        }

        Cert::from_packet_pile(PacketPile::from(combined))
    }

    /// Returns whether at least one of the keys includes a secret
    /// part.
    pub fn is_tsk(&self) -> bool {
        if self.primary_key().has_secret() {
            return true;
        }
        self.subkeys().any(|sk| {
            sk.key().has_secret()
        })
    }

    /// Fixes a time and policy for use with this certificate.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// Returns an error if the certificate is not valid for the given
    /// policy at the given time.
    pub fn with_policy<'a, T>(&'a self, policy: &'a dyn Policy, time: T)
                              -> Result<ValidCert<'a>>
        where T: Into<Option<time::SystemTime>>,
    {
        let time = time.into().unwrap_or_else(time::SystemTime::now);
        self.primary_key().with_policy(policy, time)?;

        Ok(ValidCert {
            cert: self,
            policy,
            time,
        })
    }
}

/// A certificate under a given policy at a given time.
#[derive(Debug, Clone)]
pub struct ValidCert<'a> {
    cert: &'a Cert,
    policy: &'a dyn Policy,
    // The reference time.
    time: time::SystemTime,
}

impl<'a> std::ops::Deref for ValidCert<'a> {
    type Target = Cert;

    fn deref(&self) -> &Self::Target {
        self.cert
    }
}

impl<'a> fmt::Display for ValidCert<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl<'a> ValidCert<'a> {
    /// Returns the certificate.
    pub fn cert(&self) -> &'a Cert {
        self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.
    pub fn time(&self) -> time::SystemTime {
        self.time
    }

    /// Returns the amalgamation's policy.
    pub fn policy(&self) -> &'a dyn Policy {
        self.policy
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// Returns an error if the certificate is not valid for the given
    /// policy at the given time.
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<ValidCert<'a>>
        where T: Into<Option<time::SystemTime>>,
    {
        self.cert.with_policy(policy, time)
    }

    /// Returns the Certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate.
    pub fn direct_key_signature(&self) -> Result<&'a Signature>
    {
        self.cert.direct_key_signature(self.policy(), self.time())
    }

    /// Returns the Cert's revocation status.
    ///
    /// A Cert is revoked if:
    ///
    ///   - There is a live revocation that is newer than all live
    ///     self signatures, or
    ///
    ///   - There is a hard revocation (even if it is not live at time
    ///     `t`, and even if there is a newer self-signature).
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this Cert is revoked; it does
    /// not imply anything about the Cert or other components.
    pub fn revoked(&self) -> RevocationStatus<'a> {
        self.cert.revoked(self.policy, self.time)
    }

    /// Returns whether or not the Cert is alive.
    pub fn alive(&self) -> Result<()> {
        self.cert.alive(self.policy, self.time)
    }

    /// Returns the amalgamated primary key.
    pub fn primary_key(&self)
        -> ValidPrimaryKeyAmalgamation<'a, key::PublicParts>
    {
        self.cert.primary_key().with_policy(self.policy, self.time)
            .expect("A ValidKeyAmalgamation must have a ValidPrimaryKeyAmalgamation")
    }

    /// Returns an iterator over the certificate's keys.
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys.
    pub fn keys(&self) -> ValidKeyIter<key::PublicParts, key::UnspecifiedRole> {
        self.cert.keys().with_policy(self.policy, self.time)
    }

    /// Returns the amalgamated primary userid, if any.
    pub fn primary_userid(&self)
        -> Result<ValidComponentAmalgamation<'a, UserID>>
    {
        self.cert.primary_userid(self.policy, self.time)
    }

    /// Returns an iterator over the Cert's userids.
    pub fn userids(&self) -> ValidComponentIter<UserID> {
        self.cert.userids().with_policy(self.policy, self.time)
    }

    /// Returns the amalgamated primary user attribute, if any.
    pub fn primary_user_attribute(&self)
        -> Result<ValidComponentAmalgamation<'a, UserAttribute>>
    {
        self.cert.primary_user_attribute(self.policy, self.time)
    }

    /// Returns an iterator over the Cert's `UserAttributeBundle`s.
    pub fn user_attributes(&self) -> ValidComponentIter<UserAttribute> {
        self.cert.user_attributes().with_policy(self.policy, self.time)
    }
}

macro_rules! impl_pref {
    ($subpacket:ident, $rt:ty) => {
        fn $subpacket(&self) -> Option<$rt>
        {
            // When addressed by the fingerprint or keyid, we first
            // look on the primary User ID and then fall back to the
            // direct key signature.  We need to be careful to handle
            // the case where there are no User IDs.
            if let Ok(u) = self.primary_userid() {
                u.$subpacket()
            } else if let Ok(sig) = self.direct_key_signature() {
                sig.$subpacket()
            } else {
                None
            }
        }
    }
}

impl<'a> crate::cert::Preferences<'a> for ValidCert<'a>
{
    impl_pref!(preferred_symmetric_algorithms, &'a [SymmetricAlgorithm]);
    impl_pref!(preferred_hash_algorithms, &'a [HashAlgorithm]);
    impl_pref!(preferred_compression_algorithms, &'a [CompressionAlgorithm]);
    impl_pref!(preferred_aead_algorithms, &'a [AEADAlgorithm]);
    impl_pref!(key_server_preferences, KeyServerPreferences);
    impl_pref!(preferred_key_server, &'a [u8]);
    impl_pref!(features, Features);
}

#[cfg(test)]
mod test {
    use crate::serialize::Serialize;
    use crate::policy::StandardPolicy as P;
    use crate::types::Curve;
    use crate::packet::signature;
    use super::*;

    use crate::{
        KeyID,
        types::KeyFlags,
    };

    fn parse_cert(data: &[u8], as_message: bool) -> Result<Cert> {
        if as_message {
            let pile = PacketPile::from_bytes(data).unwrap();
            Cert::from_packet_pile(pile)
        } else {
            Cert::from_bytes(data)
        }
    }

    #[test]
    fn broken() {
        use crate::types::Timestamp;
        for i in 0..2 {
            let cert = parse_cert(crate::tests::key("testy-broken-no-pk.pgp"),
                                i == 0);
            assert_match!(Error::MalformedCert(_)
                          = cert.err().unwrap().downcast::<Error>().unwrap());

            // According to 4880, a Cert must have a UserID.  But, we
            // don't require it.
            let cert = parse_cert(crate::tests::key("testy-broken-no-uid.pgp"),
                                i == 0);
            assert!(cert.is_ok());

            // We have:
            //
            //   [ pk, user id, sig, subkey ]
            let cert = parse_cert(crate::tests::key("testy-broken-no-sig-on-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.userids.len(), 1);
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);
            assert_eq!(cert.user_attributes.len(), 0);
            assert_eq!(cert.subkeys.len(), 1);
        }
    }

    #[test]
    fn basics() {
        use crate::types::Timestamp;
        for i in 0..2 {
            let cert = parse_cert(crate::tests::key("testy.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(format!("{:X}", cert.fingerprint()),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(cert.userids.len(), 1, "number of userids");
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(cert.user_attributes.len(), 0);

            assert_eq!(cert.subkeys.len(), 1, "number of subkeys");
            assert_eq!(cert.subkeys[0].key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.subkeys[0].self_signatures[0].digest_prefix(),
                       &[ 0xb7, 0xb9 ]);

            let cert = parse_cert(crate::tests::key("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(format!("{:X}", cert.fingerprint()),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(cert.user_attributes.len(), 0);

            assert_eq!(cert.userids.len(), 1, "number of userids");
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(cert.subkeys.len(), 0, "number of subkeys");

            let cert = parse_cert(crate::tests::key("testy.asc"), i == 0).unwrap();
            assert_eq!(format!("{:X}", cert.fingerprint()),
                       "3E8877C877274692975189F5D03F6F865226FE8B");
        }
    }

    #[test]
    fn only_a_public_key() {
        // Make sure the Cert parser can parse a key that just consists
        // of a public key---no signatures, no user ids, nothing.
        let cert = Cert::from_bytes(crate::tests::key("testy-only-a-pk.pgp")).unwrap();
        assert_eq!(cert.userids.len(), 0);
        assert_eq!(cert.user_attributes.len(), 0);
        assert_eq!(cert.subkeys.len(), 0);
    }

    #[test]
    fn merge() {
        use crate::tests::key;
        let cert_base = Cert::from_bytes(key("bannon-base.gpg")).unwrap();

        // When we merge it with itself, we should get the exact same
        // thing.
        let merged = cert_base.clone().merge(cert_base.clone()).unwrap();
        assert_eq!(cert_base, merged);

        let cert_add_uid_1
            = Cert::from_bytes(key("bannon-add-uid-1-whitehouse.gov.gpg"))
                .unwrap();
        let cert_add_uid_2
            = Cert::from_bytes(key("bannon-add-uid-2-fox.com.gpg"))
                .unwrap();
        // Duplicate user id, but with a different self-sig.
        let cert_add_uid_3
            = Cert::from_bytes(key("bannon-add-uid-3-whitehouse.gov-dup.gpg"))
                .unwrap();

        let cert_all_uids
            = Cert::from_bytes(key("bannon-all-uids.gpg"))
            .unwrap();
        // We have four User ID packets, but one has the same User ID,
        // just with a different self-signature.
        assert_eq!(cert_all_uids.userids.len(), 3);

        // Merge in order.
        let merged = cert_base.clone().merge(cert_add_uid_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_3.clone()).unwrap();
        assert_eq!(cert_all_uids, merged);

        // Merge in reverse order.
        let merged = cert_base.clone()
            .merge(cert_add_uid_3.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_1.clone()).unwrap();
        assert_eq!(cert_all_uids, merged);

        let cert_add_subkey_1
            = Cert::from_bytes(key("bannon-add-subkey-1.gpg")).unwrap();
        let cert_add_subkey_2
            = Cert::from_bytes(key("bannon-add-subkey-2.gpg")).unwrap();
        let cert_add_subkey_3
            = Cert::from_bytes(key("bannon-add-subkey-3.gpg")).unwrap();

        let cert_all_subkeys
            = Cert::from_bytes(key("bannon-all-subkeys.gpg")).unwrap();

        // Merge the first user, then the second, then the third.
        let merged = cert_base.clone().merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        // Merge the third user, then the second, then the first.
        let merged = cert_base.clone().merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        // Merge a lot.
        let merged = cert_base.clone()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        let cert_all
            = Cert::from_bytes(key("bannon-all-uids-subkeys.gpg"))
            .unwrap();

        // Merge all the subkeys with all the uids.
        let merged = cert_all_subkeys.clone()
            .merge(cert_all_uids.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // Merge all uids with all the subkeys.
        let merged = cert_all_uids.clone()
            .merge(cert_all_subkeys.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // All the subkeys and the uids in a mixed up order.
        let merged = cert_base.clone()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_1.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_3.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // Certifications.
        let cert_donald_signs_base
            = Cert::from_bytes(key("bannon-the-donald-signs-base.gpg"))
            .unwrap();
        let cert_donald_signs_all
            = Cert::from_bytes(key("bannon-the-donald-signs-all-uids.gpg"))
            .unwrap();
        let cert_ivanka_signs_base
            = Cert::from_bytes(key("bannon-ivanka-signs-base.gpg"))
            .unwrap();
        let cert_ivanka_signs_all
            = Cert::from_bytes(key("bannon-ivanka-signs-all-uids.gpg"))
            .unwrap();

        assert!(cert_donald_signs_base.userids.len() == 1);
        assert!(cert_donald_signs_base.userids[0].self_signatures.len() == 1);
        assert!(cert_base.userids[0].certifications.len() == 0);
        assert!(cert_donald_signs_base.userids[0].certifications.len() == 1);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_ivanka_signs_base.clone()).unwrap();
        assert!(merged.userids.len() == 1);
        assert!(merged.userids[0].self_signatures.len() == 1);
        assert!(merged.userids[0].certifications.len() == 2);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_donald_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
        // There should be two certifications from the Donald on the
        // first user id.
        assert!(merged.userids[0].certifications.len() == 2);
        assert!(merged.userids[1].certifications.len() == 1);
        assert!(merged.userids[2].certifications.len() == 1);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);

        // Same as above, but redundant.
        let merged = cert_donald_signs_base.clone()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
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

        let cert = Cert::from_bytes(crate::tests::key("neal-sigs-out-of-order.pgp"))
            .unwrap();

        let mut userids = cert.userids()
            .map(|u| String::from_utf8_lossy(u.value()).into_owned())
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

        let mut subkeys = cert.subkeys()
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
        let cert =
            Cert::from_bytes(crate::tests::key("dkg-sigs-out-of-order.pgp")).unwrap();

        let mut userids = cert.userids()
            .map(|u| String::from_utf8_lossy(u.value()).into_owned())
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

        assert_eq!(cert.user_attributes.len(), 1);

        let mut subkeys = cert.subkeys()
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
        let cert = Cert::from_bytes(lutz);
        assert_match!(Error::MalformedCert(_)
                      = cert.err().unwrap().downcast::<Error>().unwrap());

        let cert = Cert::from_bytes(dkg);
        assert!(cert.is_ok(), "dkg.gpg: {:?}", cert);
    }

    #[test]
    fn keyring_with_v3_public_keys() {
        let dkg = crate::tests::key("dkg.gpg");
        let lutz = crate::tests::key("lutz.gpg");

        let cert = Cert::from_bytes(dkg);
        assert!(cert.is_ok(), "dkg.gpg: {:?}", cert);

        // Key ring with two good keys
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, true ]);

        // Key ring with a good key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false ]);

        // Key ring with a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ false, true ]);

        // Key ring with a good key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, true ]);

        // Key ring with a good key, a bad key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, false ]);

        // Key ring with a good key, a bad key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, false, true ]);
    }

    #[test]
    fn merge_with_incomplete_update() {
        let p = &P::new();

        let cert = Cert::from_bytes(crate::tests::key("about-to-expire.expired.pgp"))
            .unwrap();
        cert.primary_key().with_policy(p, None).unwrap().alive().unwrap_err();

        let update =
            Cert::from_bytes(crate::tests::key("about-to-expire.update-no-uid.pgp"))
            .unwrap();
        let cert = cert.merge(update).unwrap();
        cert.primary_key().with_policy(p, None).unwrap().alive().unwrap();
    }

    #[test]
    fn packet_pile_roundtrip() {
        // Make sure Cert::from_packet_pile(Cert::to_packet_pile(cert))
        // does a clean round trip.

        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);
    }

    #[test]
    fn merge_packets() {
        use crate::armor;
        use crate::packet::Tag;

        // Merge the revocation certificate into the Cert and make sure
        // it shows up.
        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();

        let rev = crate::tests::key("already-revoked.rev");
        let rev = PacketPile::from_reader(armor::Reader::new(&rev[..], None))
            .unwrap();

        let rev : Vec<Packet> = rev.into_children().collect();
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].tag(), Tag::Signature);

        let packets_pre_merge = cert.clone().into_packets().count();
        let cert = cert.merge_packets(rev).unwrap();
        let packets_post_merge = cert.clone().into_packets().count();
        assert_eq!(packets_post_merge, packets_pre_merge + 1);
    }

    #[test]
    fn set_validity_period() {
        let p = &P::new();

        let (cert, _) = CertBuilder::general_purpose(None, Some("Test"))
            .generate().unwrap();
        assert_eq!(cert.clone().into_packet_pile().children().count(),
                   1 // primary key
                   + 1 // direct key signature
                   + 1 // userid
                   + 1 // binding signature
                   + 1 // subkey
                   + 1 // binding signature
        );
        let cert = check_set_validity_period(p, cert);
        assert_eq!(cert.clone().into_packet_pile().children().count(),
                   1 // primary key
                   + 1 // direct key signature
                   + 2 // two new direct key signatures
                   + 1 // userid
                   + 1 // binding signature
                   + 2 // two new binding signatures
                   + 1 // subkey
                   + 1 // binding signature
        );
    }
    #[test]
    fn set_validity_period_uidless() {
        use crate::types::{Duration, Timestamp};
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .set_expiration_time(None) // Just to assert this works.
            .set_expiration_time(
                Some(Timestamp::now().checked_add(
                    Duration::weeks(52).unwrap()).unwrap().into()))
            .generate().unwrap();
        assert_eq!(cert.clone().into_packet_pile().children().count(),
                   1 // primary key
                   + 1 // direct key signature
        );
        let cert = check_set_validity_period(p, cert);
        assert_eq!(cert.clone().into_packet_pile().children().count(),
                   1 // primary key
                   + 1 // direct key signature
                   + 2 // two new direct key signatures
        );
    }
    fn check_set_validity_period(policy: &dyn Policy, cert: Cert) -> Cert {
        let now = cert.primary_key().creation_time();
        let a_sec = time::Duration::new(1, 0);

        let expiry_orig = cert.primary_key().with_policy(policy, now).unwrap()
            .key_validity_period()
            .expect("Keys expire by default.");

        let mut keypair = cert.primary_key().key().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        // Clear the expiration.
        let as_of1 = now + time::Duration::new(10, 0);
        let cert = cert.set_validity_period_as_of(
            policy, &mut keypair, None, as_of1).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(cert.primary_key().with_policy(policy, now).unwrap()
                           .key_validity_period(),
                       Some(expiry_orig));
            assert_eq!(cert.primary_key().with_policy(policy, as_of1 - a_sec).unwrap()
                           .key_validity_period(),
                       Some(expiry_orig));
            // If t >= as_of1, we should get the new expiry.
            assert_eq!(cert.primary_key().with_policy(policy, as_of1).unwrap()
                           .key_validity_period(),
                       None);
        }

        // Shorten the expiry.  (The default expiration should be at
        // least a few weeks, so removing an hour should still keep us
        // over 0.)
        let expiry_new = expiry_orig - time::Duration::new(60 * 60, 0);
        assert!(expiry_new > time::Duration::new(0, 0));

        let as_of2 = as_of1 + time::Duration::new(10, 0);
        let cert = cert.set_validity_period_as_of(
            policy, &mut keypair, Some(expiry_new), as_of2).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(cert.primary_key().with_policy(policy, now).unwrap()
                           .key_validity_period(),
                       Some(expiry_orig));
            assert_eq!(cert.primary_key().with_policy(policy, as_of1 - a_sec).unwrap()
                           .key_validity_period(),
                       Some(expiry_orig));
            // If as_of1 <= t < as_of2, we should get the second
            // expiry (None).
            assert_eq!(cert.primary_key().with_policy(policy, as_of1).unwrap()
                           .key_validity_period(),
                       None);
            assert_eq!(cert.primary_key().with_policy(policy, as_of2 - a_sec).unwrap()
                           .key_validity_period(),
                       None);
            // If t <= as_of2, we should get the new expiry.
            assert_eq!(cert.primary_key().with_policy(policy, as_of2).unwrap()
                           .key_validity_period(),
                       Some(expiry_new));
        }
        cert
    }

    #[test]
    fn direct_key_sig() {
        use crate::types::SignatureType;
        // XXX: testing sequoia against itself isn't optimal, but I couldn't
        // find a tool to generate direct key signatures :-(

        let p = &P::new();

        let (cert1, _) = CertBuilder::new().generate().unwrap();
        let mut buf = Vec::default();

        cert1.serialize(&mut buf).unwrap();
        let cert2 = Cert::from_bytes(&buf).unwrap();

        assert_eq!(
            cert2.primary_key().with_policy(p, None).unwrap()
                .direct_key_signature().unwrap().typ(),
            SignatureType::DirectKey);
        assert_eq!(cert2.userids().count(), 0);
    }

    #[test]
    fn revoked() {
        fn check(cert: &Cert, direct_revoked: bool,
                 userid_revoked: bool, subkey_revoked: bool) {
            let p = &P::new();

            // If we have a user id---even if it is revoked---we have
            // a primary key signature.
            let typ = cert.primary_key().with_policy(p, None).unwrap()
                .binding_signature().typ();
            assert_eq!(typ, SignatureType::PositiveCertification,
                       "{:#?}", cert);

            let revoked = cert.revoked(p, None);
            if direct_revoked {
                assert_match!(RevocationStatus::Revoked(_) = revoked,
                              "{:#?}", cert);
            } else {
                assert_eq!(revoked, RevocationStatus::NotAsFarAsWeKnow,
                           "{:#?}", cert);
            }

            for userid in cert.userids().with_policy(p, None) {
                let typ = userid.binding_signature().typ();
                assert_eq!(typ, SignatureType::PositiveCertification,
                           "{:#?}", cert);

                let revoked = userid.revoked();
                if userid_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", cert);
                }
            }

            for subkey in cert.subkeys() {
                let typ = subkey.binding_signature(p, None).unwrap().typ();
                assert_eq!(typ, SignatureType::SubkeyBinding,
                           "{:#?}", cert);

                let revoked = subkey.revoked(p, None);
                if subkey_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", cert);
                }
            }
        }

        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        check(&cert, false, false, false);

        let d = Cert::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        check(&d, true, false, false);

        check(&cert.clone().merge(d.clone()).unwrap(), true, false, false);
        // Make sure the merge order does not matter.
        check(&d.clone().merge(cert.clone()).unwrap(), true, false, false);

        let u = Cert::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        check(&u, false, true, false);

        check(&cert.clone().merge(u.clone()).unwrap(), false, true, false);
        check(&u.clone().merge(cert.clone()).unwrap(), false, true, false);

        let k = Cert::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        check(&k, false, false, true);

        check(&cert.clone().merge(k.clone()).unwrap(), false, false, true);
        check(&k.clone().merge(cert.clone()).unwrap(), false, false, true);

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
        let p = &P::new();

        let (cert, _) = CertBuilder::general_purpose(None, Some("Test"))
            .generate().unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(p, None));

        let mut keypair = cert.primary_key().key().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyCompromised,
                b"It was the maid :/").unwrap()
            .build(&mut keypair, &cert, None)
            .unwrap();
        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(&cert.keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(&cert.fingerprint()));

        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, None));


        // Have other revoke cert.
        let (other, _) = CertBuilder::general_purpose(None, Some("Test 2"))
            .generate().unwrap();

        let mut keypair = other.primary_key().key().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyCompromised,
                b"It was the maid :/").unwrap()
            .build(&mut keypair, &cert, None)
            .unwrap();

        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(&other.keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(&other.fingerprint()));
    }

    #[test]
    fn revoke_subkey() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        let sig = {
            let subkey = cert.subkeys().nth(0).unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                       subkey.revoked(p, None));

            let mut keypair = cert.primary_key().key().clone().mark_parts_secret()
                .unwrap().into_keypair().unwrap();
            SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::UIDRetired,
                    b"It was the maid :/").unwrap()
                .build(&mut keypair, &cert, subkey.key(), None)
                .unwrap()
        };
        assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);
        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(p, None));

        let subkey = cert.subkeys().nth(0).unwrap();
        assert_match!(RevocationStatus::Revoked(_)
                      = subkey.revoked(p, None));
    }

    #[test]
    fn revoke_uid() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_userid("Test1")
            .add_userid("Test2")
            .generate().unwrap();

        let sig = {
            let uid = cert.userids().with_policy(p, None).nth(1).unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked());

            let mut keypair = cert.primary_key().key().clone().mark_parts_secret()
                .unwrap().into_keypair().unwrap();
            UserIDRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::UIDRetired,
                    b"It was the maid :/").unwrap()
                .build(&mut keypair, &cert, uid.userid(), None)
                .unwrap()
        };
        assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(p, None));

        let uid = cert.userids().with_policy(p, None).nth(1).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = uid.revoked());
    }

    #[test]
    fn key_revoked() {
        use crate::types::Features;
        use crate::packet::key::Key4;
        use rand::{thread_rng, Rng, distributions::Open01};

        let p = &P::new();

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
         * One the hard revocation is merged, then the Cert is
         * considered revoked at all times.
         */
        let t1 = time::UNIX_EPOCH + time::Duration::new(946681200, 0);  // 2000-1-1
        let t2 = time::UNIX_EPOCH + time::Duration::new(978303600, 0);  // 2001-1-1
        let t3 = time::UNIX_EPOCH + time::Duration::new(1009839600, 0); // 2002-1-1
        let t4 = time::UNIX_EPOCH + time::Duration::new(1041375600, 0); // 2003-1-1

        let mut key: key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        key.set_creation_time(t1).unwrap();
        let mut pair = key.clone().into_keypair().unwrap();
        let (bind1, rev1, bind2, rev2) = {
            let bind1 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t1).unwrap()
                .set_key_validity_period(Some(time::Duration::new(10 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let rev1 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t2).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeySuperseded,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let bind2 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t3).unwrap()
                .set_key_validity_period(Some(time::Duration::new(10 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let rev2 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t4).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            (bind1, rev1, bind2, rev2)
        };
        let pk : key::PublicKey = key.into();
        let cert = Cert::from_packet_pile(PacketPile::from(vec![
            pk.into(),
            bind1.into(),
            bind2.into(),
            rev1.into()
        ])).unwrap();

        let f1: f32 = thread_rng().sample(Open01);
        let f2: f32 = thread_rng().sample(Open01);
        let f3: f32 = thread_rng().sample(Open01);
        let f4: f32 = thread_rng().sample(Open01);
        let te1 = t1 - time::Duration::new((60. * 60. * 24. * 300.0 * f1) as u64, 0);
        let t12 = t1 + time::Duration::new((60. * 60. * 24. * 300.0 * f2) as u64, 0);
        let t23 = t2 + time::Duration::new((60. * 60. * 24. * 300.0 * f3) as u64, 0);
        let t34 = t3 + time::Duration::new((60. * 60. * 24. * 300.0 * f4) as u64, 0);

        assert_eq!(cert.revoked(p, te1), RevocationStatus::NotAsFarAsWeKnow);
        assert_eq!(cert.revoked(p, t12), RevocationStatus::NotAsFarAsWeKnow);
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, t23));
        assert_eq!(cert.revoked(p, t34), RevocationStatus::NotAsFarAsWeKnow);

        // Merge in the hard revocation.
        let cert = cert.merge_packets(vec![ rev2.into() ]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, te1));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, t12));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, t23));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, t34));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(p, t4));
        assert_match!(RevocationStatus::Revoked(_)
                      = cert.revoked(p, time::SystemTime::now()));
    }

    #[test]
    fn key_revoked2() {
        tracer!(true, "cert_revoked2", 0);

        let p = &P::new();

        fn cert_revoked<T>(p: &dyn Policy, cert: &Cert, t: T) -> bool
            where T: Into<Option<time::SystemTime>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = cert.revoked(p, t))
        }

        fn subkey_revoked<T>(p: &dyn Policy, cert: &Cert, t: T) -> bool
            where T: Into<Option<time::SystemTime>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = cert.subkeys().nth(0).unwrap().revoked(p, t))
        }

        let tests : [(&str, Box<dyn Fn(&dyn Policy, &Cert, _) -> bool>); 2] = [
            ("cert", Box::new(cert_revoked)),
            ("subkey", Box::new(subkey_revoked)),
        ];

        for (f, revoked) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let cert = Cert::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();
            let selfsig0 = cert.primary_key().with_policy(p, None).unwrap()
                .binding_signature().signature_creation_time().unwrap();

            assert!(!revoked(p, &cert, Some(selfsig0)));
            assert!(!revoked(p, &cert, None));

            t!("Soft revocation");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();
            // A soft revocation made after `t` is ignored when
            // determining whether the key is revoked at time `t`.
            assert!(!revoked(p, &cert, Some(selfsig0)));
            assert!(revoked(p, &cert, None));

            t!("New self signature");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(!revoked(p, &cert, Some(selfsig0)));
            // Newer self-sig override older soft revocations.
            assert!(!revoked(p, &cert, None));

            t!("Hard revocation");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();
            // Hard revocations trump all.
            assert!(revoked(p, &cert, Some(selfsig0)));
            assert!(revoked(p, &cert, None));

            t!("New self signature");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(revoked(p, &cert, Some(selfsig0)));
            assert!(revoked(p, &cert, None));
        }
    }

    #[test]
    fn userid_revoked2() {
        fn check_userids<T>(p: &dyn Policy, cert: &Cert, revoked: bool, t: T)
            where T: Into<Option<time::SystemTime>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = cert.revoked(p, None));

            let mut slim_shady = false;
            let mut eminem = false;
            for b in cert.userids().with_policy(p, t) {
                if b.userid().value() == b"Slim Shady" {
                    assert!(!slim_shady);
                    slim_shady = true;

                    if revoked {
                        assert_match!(RevocationStatus::Revoked(_)
                                      = b.revoked());
                    } else {
                        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                      = b.revoked());
                    }
                } else {
                    assert!(!eminem);
                    eminem = true;

                    assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                  = b.revoked());
                }
            }

            assert!(slim_shady);
            assert!(eminem);
        }

        fn check_uas<T>(p: &dyn Policy, cert: &Cert, revoked: bool, t: T)
            where T: Into<Option<time::SystemTime>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = cert.revoked(p, None));

            assert_eq!(cert.user_attributes().count(), 1);
            let ua = cert.user_attributes().nth(0).unwrap();
            if revoked {
                assert_match!(RevocationStatus::Revoked(_)
                              = ua.revoked(p, t));
            } else {
                assert_match!(RevocationStatus::NotAsFarAsWeKnow
                              = ua.revoked(p, t));
            }
        }

        tracer!(true, "userid_revoked2", 0);

        let p = &P::new();
        let tests : [(&str, Box<dyn Fn(&dyn Policy, &Cert, bool, _)>); 2] = [
            ("userid", Box::new(check_userids)),
            ("user-attribute", Box::new(check_uas)),
        ];

        for (f, check) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let cert = Cert::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();

            let now = time::SystemTime::now();
            let selfsig0
                = cert.userids().with_policy(p, now).map(|b| {
                    b.binding_signature().signature_creation_time().unwrap()
                })
                .max().unwrap();

            check(p, &cert, false, selfsig0);
            check(p, &cert, false, now);

            // A soft-revocation.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(p, &cert, false, selfsig0);
            check(p, &cert, true, now);

            // A new self signature.  This should override the soft-revocation.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(p, &cert, false, selfsig0);
            check(p, &cert, false, now);

            // A hard revocation.  Unlike for Certs, this does NOT trumps
            // everything.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(p, &cert, false, selfsig0);
            check(p, &cert, true, now);

            // A newer self siganture.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(p, &cert, false, selfsig0);
            check(p, &cert, false, now);
        }
    }

    #[test]
    fn unrevoked() {
        let p = &P::new();
        let cert =
            Cert::from_bytes(crate::tests::key("un-revoked-userid.pgp")).unwrap();

        for uid in cert.userids().with_policy(p, None) {
            assert_eq!(uid.revoked(), RevocationStatus::NotAsFarAsWeKnow);
        }
    }

    #[test]
    fn is_tsk() {
        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked.pgp")).unwrap();
        assert!(! cert.is_tsk());

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-private.pgp")).unwrap();
        assert!(cert.is_tsk());
    }

    #[test]
    fn export_only_exports_public_key() {
        let cert = Cert::from_bytes(
            crate::tests::key("testy-new-private.pgp")).unwrap();
        assert!(cert.is_tsk());

        let mut v = Vec::new();
        cert.serialize(&mut v).unwrap();
        let cert = Cert::from_bytes(&v).unwrap();
        assert!(! cert.is_tsk());
    }

    // Make sure that when merging two Certs, the primary key and
    // subkeys with and without a private key are merged.
    #[test]
    fn public_private_merge() {
        let (tsk, _) = CertBuilder::general_purpose(None, Some("foo@example.com"))
            .generate().unwrap();
        // tsk is now a cert, but it still has its private bits.
        assert!(tsk.primary.key().has_secret());
        assert!(tsk.is_tsk());
        let subkey_count = tsk.subkeys().len();
        assert!(subkey_count > 0);
        assert!(tsk.subkeys().all(|k| k.key().has_secret()));

        // This will write out the tsk as a cert, i.e., without any
        // private bits.
        let mut cert_bytes = Vec::new();
        tsk.serialize(&mut cert_bytes).unwrap();

        // Reading it back in, the private bits have been stripped.
        let cert = Cert::from_bytes(&cert_bytes[..]).unwrap();
        assert!(! cert.primary.key().has_secret());
        assert!(!cert.is_tsk());
        assert!(cert.subkeys().all(|k| ! k.key().has_secret()));

        let merge1 = cert.clone().merge(tsk.clone()).unwrap();
        assert!(merge1.is_tsk());
        assert!(merge1.primary.key().has_secret());
        assert_eq!(merge1.subkeys().len(), subkey_count);
        assert!(merge1.subkeys().all(|k| k.key().has_secret()));

        let merge2 = tsk.clone().merge(cert.clone()).unwrap();
        assert!(merge2.is_tsk());
        assert!(merge2.primary.key().has_secret());
        assert_eq!(merge2.subkeys().len(), subkey_count);
        assert!(merge2.subkeys().all(|k| k.key().has_secret()));
    }

    #[test]
    fn issue_120() {
        let cert = "
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
        assert!(Cert::from_bytes(cert).is_err());
    }

    #[test]
    fn missing_uids() {
        let (cert, _) = CertBuilder::new()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();
        assert_eq!(cert.subkeys().len(), 2);
        let pile = cert
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
        let cert = Cert::from_packet_pile(PacketPile::from(pile)).unwrap();

        assert_eq!(cert.subkeys().len(), 2);
    }

    #[test]
    fn signature_order() {
        let p = &P::new();
        let neal = Cert::from_bytes(crate::tests::key("neal.pgp")).unwrap();

        // This test is useless if we don't have some lists with more
        // than one signature.
        let mut cmps = 0;

        for uid in neal.userids() {
            for sigs in [
                uid.self_signatures(),
                    uid.certifications(),
                uid.self_revocations(),
                uid.other_revocations()
            ].iter() {
                for sigs in sigs.windows(2) {
                    cmps += 1;
                    assert!(sigs[0].signature_creation_time()
                            >= sigs[1].signature_creation_time());
                }
            }

            // Make sure we return the most recent first.
            assert_eq!(uid.self_signatures().first().unwrap(),
                       uid.binding_signature(p, None).unwrap());
        }

        assert!(cmps > 0);
    }

    #[test]
    fn cert_reject_keyrings() {
        let mut keyring = Vec::new();
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        assert!(Cert::from_bytes(&keyring).is_err());
    }

    #[test]
    fn cert_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f(Cert::from_bytes(crate::tests::key("testy-new.pgp")).unwrap());
    }

    #[test]
    fn primary_userid() {
        // 'really-revoked-userid' has two user ids.  One of them is
        // revoked and then restored.  Neither of the user ids has the
        // primary userid bit set.
        //
        // This test makes sure that Cert::primary_userid prefers
        // unrevoked user ids to revoked user ids, even if the latter
        // have newer self signatures.

        let p = &P::new();
        let cert = Cert::from_bytes(
            crate::tests::key("really-revoked-userid-0-public.pgp")).unwrap();

        let now = time::SystemTime::now();
        let selfsig0
            = cert.userids().with_policy(p, now).map(|b| {
                b.binding_signature().signature_creation_time().unwrap()
            })
            .max().unwrap();

        // The self-sig for:
        //
        //   Slim Shady: 2019-09-14T14:21
        //   Eminem:     2019-09-14T14:22
        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"Eminem");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"Eminem");

        // A soft-revocation for "Slim Shady".
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-1-soft-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"Eminem");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"Eminem");

        // A new self signature for "Slim Shady".  This should
        // override the soft-revocation.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-2-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"Eminem");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"Slim Shady");

        // A hard revocation for "Slim Shady".
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-3-hard-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"Eminem");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"Eminem");

        // A newer self siganture for "Slim Shady". Unlike for Certs, this
        // does NOT trump everything.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-4-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"Eminem");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"Slim Shady");

        // Play with the primary user id flag.

        let cert = Cert::from_bytes(
            crate::tests::key("primary-key-0-public.pgp")).unwrap();
        let selfsig0
            = cert.userids().with_policy(p, now).map(|b| {
                b.binding_signature().signature_creation_time().unwrap()
            })
            .max().unwrap();

        // There is only a single User ID.
        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"aaaaa");


        // Add a second user id.  Since neither is marked primary, the
        // newer one should be considered primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-1-add-userid-bbbbb.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"bbbbb");

        // Mark aaaaa as primary.  It is now primary and the newest one.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-2-make-aaaaa-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"aaaaa");

        // Update the preferences on bbbbb.  It is now the newest, but
        // it is not marked as primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-3-make-bbbbb-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"aaaaa");

        // Mark bbbbb as primary.  It is now the newest and marked as
        // primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-4-make-bbbbb-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"bbbbb");

        // Update the preferences on aaaaa.  It is now has the newest
        // self sig, but that self sig does not say that it is
        // primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-5-make-aaaaa-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"bbbbb");

        // Hard revoke aaaaa.  Unlike with Certs, a hard revocation is
        // not treated specially.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-6-revoked-aaaaa.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.primary_userid(p, selfsig0).unwrap().userid().value(),
                   b"aaaaa");
        assert_eq!(cert.primary_userid(p, now).unwrap().userid().value(),
                   b"bbbbb");
    }

    #[test]
    fn binding_signature_lookup() {
        // Check that searching for the right binding signature works
        // even when there are signatures with the same time.

        use crate::types::Features;
        use crate::packet::key::Key4;

        let p = &P::new();

        let a_sec = time::Duration::new(1, 0);
        let time_zero = time::UNIX_EPOCH;

        let t1 = time::UNIX_EPOCH + time::Duration::new(946681200, 0);  // 2000-1-1
        let t2 = time::UNIX_EPOCH + time::Duration::new(978303600, 0);  // 2001-1-1
        let t3 = time::UNIX_EPOCH + time::Duration::new(1009839600, 0); // 2002-1-1
        let t4 = time::UNIX_EPOCH + time::Duration::new(1041375600, 0); // 2003-1-1

        let mut key: key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        key.set_creation_time(t1).unwrap();
        let mut pair = key.clone().into_keypair().unwrap();
        let pk : key::PublicKey = key.clone().into();
        let mut cert = Cert::from_packet_pile(PacketPile::from(vec![
            pk.into(),
        ])).unwrap();
        let uid: UserID = "foo@example.org".into();
        let sig = uid.certify(&mut pair, &cert,
                              SignatureType::PositiveCertification,
                              None,
                              t1).unwrap();
        cert = cert.merge_packets(vec![uid.into(), sig.into()]).unwrap();

        const N: usize = 5;
        for (t, offset) in &[ (t2, 0), (t4, 0), (t3, 1 * N), (t1, 3 * N) ] {
            for i in 0..N {
                let binding = signature::Builder::new(SignatureType::DirectKey)
                    .set_features(&Features::sequoia()).unwrap()
                    .set_key_flags(&KeyFlags::default()).unwrap()
                    .set_signature_creation_time(t1).unwrap()
                    // Vary this...
                    .set_key_validity_period(Some(
                        time::Duration::new((1 + i as u64) * 24 * 60 * 60, 0)))
                    .unwrap()
                    .set_issuer_fingerprint(key.fingerprint()).unwrap()
                    .set_issuer(key.keyid()).unwrap()
                    .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                    .set_signature_creation_time(*t).unwrap()
                    .sign_direct_key(&mut pair).unwrap();

                let binding : Packet = binding.into();

                cert = cert.merge_packets(vec![ binding ]).unwrap();
                // A time that matches multiple signatures.
                let direct_signatures =
                    cert.primary_key().bundle().self_signatures();
                assert_eq!(cert.primary_key().with_policy(p, *t).unwrap()
                           .direct_key_signature().ok(),
                           direct_signatures.get(*offset));
                // A time that doesn't match any signature.
                assert_eq!(cert.primary_key().with_policy(p, *t + a_sec).unwrap()
                           .direct_key_signature().ok(),
                           direct_signatures.get(*offset));

                // The current time, which should use the first signature.
                assert_eq!(cert.primary_key().with_policy(p, None).unwrap()
                           .direct_key_signature().ok(),
                           direct_signatures.get(0));

                // The beginning of time, which should return no
                // binding signatures.
                assert!(cert.primary_key().with_policy(p, time_zero).is_err());
            }
        }
    }

    #[test]
    fn keysigning_party() {
        use crate::packet::signature;

        for cs in &[ CipherSuite::Cv25519,
                     CipherSuite::RSA3k,
                     CipherSuite::P256,
                     CipherSuite::P384,
                     CipherSuite::P521,
                     CipherSuite::RSA2k,
                     CipherSuite::RSA4k ]
        {
            let (alice, _) = CertBuilder::new()
                .set_cipher_suite(*cs)
                .add_userid("alice@foo.com")
                .generate().unwrap();

            let (bob, _) = CertBuilder::new()
                .set_cipher_suite(*cs)
                .add_userid("bob@bar.com")
                .add_signing_subkey()
                .generate().unwrap();

            assert_eq!(bob.userids().len(), 1);
            let bob_userid_binding = bob.userids().nth(0).unwrap();
            assert_eq!(bob_userid_binding.userid().value(), b"bob@bar.com");

            let sig_template
                = signature::Builder::new(SignatureType::GenericCertification)
                      .set_trust_signature(255, 120)
                      .unwrap();

            // Have alice cerify the binding "bob@bar.com" and bob's key.
            let alice_certifies_bob
                = bob_userid_binding.userid().bind(
                    &mut alice.primary_key().key().clone().mark_parts_secret()
                        .unwrap().into_keypair().unwrap(),
                    &bob,
                    sig_template).unwrap();

            let bob
                = bob.merge_packets(vec![ alice_certifies_bob.clone().into() ])
                .unwrap();

            // Make sure the certification is merged, and put in the right
            // place.
            assert_eq!(bob.userids().len(), 1);
            let bob_userid_binding = bob.userids().nth(0).unwrap();
            assert_eq!(bob_userid_binding.userid().value(), b"bob@bar.com");

            // Canonicalizing Bob's cert without having Alice's key
            // has to resort to a heuristic to order third party
            // signatures.  However, since we know the signature's
            // type (GenericCertification), we know that it can only
            // go to the only userid, so there is no ambiguity in this
            // case.
            assert_eq!(bob_userid_binding.certifications(),
                       &[ alice_certifies_bob.clone() ]);

            // Make sure the certification is correct.
            alice_certifies_bob
                .verify_userid_binding(alice.primary_key().key(),
                                       bob.primary_key().key(),
                                       bob_userid_binding.userid()).unwrap();
        }
   }

    #[test]
    fn decrypt_secrets() {
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .set_password(Some(String::from("streng geheim").into()))
            .generate().unwrap();
        assert_eq!(cert.keys().secret().count(), 2);
        assert_eq!(cert.keys().unencrypted_secret().count(), 0);

        let mut primary = cert.primary_key().key().clone()
            .mark_parts_secret().unwrap();
        let algo = primary.pk_algo();
        primary.secret_mut()
            .decrypt_in_place(algo, &"streng geheim".into()).unwrap();
        let cert = cert.merge_packets(vec![
            primary.mark_parts_secret().unwrap().mark_role_primary().into()
        ]).unwrap();

        assert_eq!(cert.keys().secret().count(), 2);
        assert_eq!(cert.keys().unencrypted_secret().count(), 1);
    }

    /// Tests that Cert::into_packets() and Cert::serialize(..) agree.
    #[test]
    fn test_into_packets() -> Result<()> {
        use crate::serialize::SerializeInto;

        let dkg = Cert::from_bytes(crate::tests::key("dkg.gpg"))?;
        let mut buf = Vec::new();
        for p in dkg.clone().into_packets() {
            p.serialize(&mut buf)?;
        }
        let dkg = dkg.to_vec()?;
        if false && buf != dkg {
            std::fs::write("/tmp/buf", &buf)?;
            std::fs::write("/tmp/dkg", &dkg)?;
        }
        assert_eq!(buf, dkg);
        Ok(())
    }

    #[test]
    fn test_canonicalization() -> Result<()> {
        let p = crate::policy::StandardPolicy::new();

        let primary: Key<_, key::PrimaryRole> =
            key::Key4::generate_ecc(true, Curve::Ed25519)?.into();
        let mut primary_pair = primary.clone().into_keypair()?;
        let cert = Cert::from_packet_pile(vec![primary.into()].into())?;

        // We now add components without binding signatures.  They
        // should be kept, be enumerable, but ignored if a policy is
        // applied.

        // Add a bare userid.
        let uid = UserID::from("foo@example.org");
        let cert = cert.merge_packets(vec![uid.into()])?;
        assert_eq!(cert.userids().count(), 1);
        assert_eq!(cert.userids().with_policy(&p, None).count(), 0);

        // Add a bare user attribute.
        use packet::user_attribute::{Subpacket, Image};
        let ua = UserAttribute::new(&[
            Subpacket::Image(
                Image::Private(100, vec![0, 1, 2].into_boxed_slice())),
        ])?;
        let cert = cert.merge_packets(vec![ua.into()])?;
        assert_eq!(cert.user_attributes().count(), 1);
        assert_eq!(cert.user_attributes().with_policy(&p, None).count(), 0);

        // Add a bare signing subkey.
        let signing_subkey: Key<_, key::SubordinateRole> =
            key::Key4::generate_ecc(true, Curve::Ed25519)?.into();
        let _signing_subkey_pair = signing_subkey.clone().into_keypair()?;
        let cert = cert.merge_packets(vec![signing_subkey.into()])?;
        assert_eq!(cert.keys().subkeys().count(), 1);
        assert_eq!(cert.keys().subkeys().with_policy(&p, None).count(), 0);

        // Add a component that Sequoia doesn't understand.
        let mut fake_key = packet::Unknown::new(
            packet::Tag::PublicSubkey, anyhow::anyhow!("fake key"));
        fake_key.set_body("fake key".into());
        let fake_binding = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_issuer(primary_pair.public().keyid())?
            .set_issuer_fingerprint(primary_pair.public().fingerprint())?
            .sign_standalone(&mut primary_pair)?;
        let cert = cert.merge_packets(vec![fake_key.into(),
                                           fake_binding.clone().into()])?;
        assert_eq!(cert.unknowns().count(), 1);
        assert_eq!(cert.unknowns().nth(0).unwrap().unknown().tag(),
                   packet::Tag::PublicSubkey);
        assert_eq!(cert.unknowns().nth(0).unwrap().self_signatures(),
                   &[fake_binding]);

        Ok(())
    }

    #[test]
    fn canonicalize_with_v3_sig() -> Result<()> {
        // This test relies on being able to validate SHA-1
        // signatures.  The standard policy reject SHA-1.  So, use a
        // custom policy.
        let p = &P::new();
        let sha1 = p.hash_cutoffs(HashAlgorithm::SHA1).0.unwrap();
        let p = &P::at(sha1 - std::time::Duration::from_secs(1));

        let cert = Cert::from_bytes(
            crate::tests::key("eike-v3-v4.pgp"))?;
        dbg!(&cert);
        assert_eq!(cert.userids()
                   .with_policy(p, None)
                   .count(), 1);
        Ok(())
    }

    /// Asserts that key expiration times on direct key signatures are
    /// honored.
    #[test]
    fn issue_215() {
        let p = &P::new();
         let cert = Cert::from_bytes(crate::tests::key(
            "issue-215-expiration-on-direct-key-sig.pgp")).unwrap();
        assert_match!(
            Error::Expired(_)
                = cert.alive(p, None).unwrap_err().downcast().unwrap());
        assert_match!(
            Error::Expired(_)
                = cert.primary_key().with_policy(p, None).unwrap()
                    .alive().unwrap_err().downcast().unwrap());
    }

    /// Tests that secrets are kept when merging.
    #[test]
    fn merge_keeps_secrets() -> Result<()> {
        let primary_sec: Key<_, key::PrimaryRole> =
            key::Key4::generate_ecc(true, Curve::Ed25519)?.into();
        let primary_pub = primary_sec.clone().take_secret().0;

        let cert_p =
            Cert::from_packet_pile(vec![primary_pub.clone().into()].into())?;
        let cert_s =
            Cert::from_packet_pile(vec![primary_sec.clone().into()].into())?;
        let cert = cert_p.merge(cert_s)?;
        assert!(cert.primary_key().has_secret());

        let cert_p =
            Cert::from_packet_pile(vec![primary_pub.clone().into()].into())?;
        let cert_s =
            Cert::from_packet_pile(vec![primary_sec.clone().into()].into())?;
        let cert = cert_s.merge(cert_p)?;
        assert!(cert.primary_key().has_secret());
        Ok(())
    }

    /// Tests that secrets are kept when canonicalizing.
    #[test]
    fn canonicalizing_keeps_secrets() -> Result<()> {
        let primary: Key<_, key::PrimaryRole> =
            key::Key4::generate_ecc(true, Curve::Ed25519)?.into();
        let mut primary_pair = primary.clone().into_keypair()?;
        let cert = Cert::from_packet_pile(vec![primary.clone().into()].into())?;

        let subkey_sec: Key<_, key::SubordinateRole> =
            key::Key4::generate_ecc(false, Curve::Cv25519)?.into();
        let subkey_pub = subkey_sec.clone().take_secret().0;
        let builder = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_key_flags(&KeyFlags::default()
                           .set_transport_encryption(true))?;
        let binding = subkey_sec.bind(&mut primary_pair, &cert, builder)?;

        let cert = Cert::from_packet_pile(vec![
            primary.clone().into(),
            subkey_pub.clone().into(),
            binding.clone().into(),
            subkey_sec.clone().into(),
            binding.clone().into(),
        ].into())?;
        assert_eq!(cert.keys().subkeys().count(), 1);
        assert_eq!(cert.keys().unencrypted_secret().subkeys().count(), 1);

        let cert = Cert::from_packet_pile(vec![
            primary.clone().into(),
            subkey_sec.clone().into(),
            binding.clone().into(),
            subkey_pub.clone().into(),
            binding.clone().into(),
        ].into())?;
        assert_eq!(cert.keys().subkeys().count(), 1);
        assert_eq!(cert.keys().unencrypted_secret().subkeys().count(), 1);
        Ok(())
    }

    /// Demonstrates that subkeys are kept if a userid is later added
    /// without any keyflags.
    #[test]
    fn issue_361() -> Result<()> {
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate()?;
        let p = &P::new();
        let cert_at = cert.with_policy(p,
                                       cert.primary_key().creation_time()
                                       + time::Duration::new(60, 0))
            .unwrap();
        assert_eq!(cert_at.userids().count(), 0);
        assert_eq!(cert_at.keys().count(), 2);

        let mut primary_pair = cert.primary_key().key().clone()
            .mark_parts_secret()?.into_keypair()?;
        let uid: UserID = "foo@example.org".into();
        let sig = uid.bind(
            &mut primary_pair, &cert,
            signature::Builder::new(SignatureType::PositiveCertification))?;
        let cert = cert.merge_packets(vec![
            uid.into(),
            sig.into(),
        ])?;

        let cert_at = cert.with_policy(p,
                                       cert.primary_key().creation_time()
                                       + time::Duration::new(60, 0))
            .unwrap();
        assert_eq!(cert_at.userids().count(), 1);
        assert_eq!(cert_at.keys().count(), 2);
        Ok(())
    }

    /// Demonstrates that binding signatures are considered valid even
    /// if the primary key is not marked as certification-capable.
    #[test]
    fn issue_321() -> Result<()> {
        let cert = Cert::from_bytes(
            crate::tests::file("contrib/pep/pEpkey-netpgp.asc"))?;
        assert_eq!(cert.userids().count(), 1);
        assert_eq!(cert.keys().count(), 1);

        let mut p = P::new();
        p.accept_hash(HashAlgorithm::SHA1);
        let cert_at = cert.with_policy(&p, cert.primary_key().creation_time())
            .unwrap();
        assert_eq!(cert_at.userids().count(), 1);
        assert_eq!(cert_at.keys().count(), 1);
        Ok(())
    }

    #[test]
    fn different_preferences() -> Result<()> {
        use crate::cert::Preferences;
        let p = &crate::policy::StandardPolicy::new();

        // This key returns different preferences depending on how you
        // address it.  (It has two user ids and the user ids have
        // different preference packets on their respective self
        // signatures.)

        let cert = Cert::from_bytes(
            crate::tests::key("different-preferences.asc"))?;
        assert_eq!(cert.userids().count(), 2);

        if let Some(userid) = cert.userids().nth(0) {
            assert_eq!(userid.userid().value(),
                       &b"Alice Confusion <alice@example.com>"[..]);

            let userid = userid.with_policy(p, None).expect("valid");

            use crate::types::SymmetricAlgorithm::*;
            assert_eq!(userid.preferred_symmetric_algorithms(),
                       Some(&[ AES256, AES192, AES128, TripleDES ][..]));

            use crate::types::HashAlgorithm::*;
            assert_eq!(userid.preferred_hash_algorithms(),
                       Some(&[ SHA512, SHA384, SHA256, SHA224, SHA1 ][..]));

            use crate::types::CompressionAlgorithm::*;
            assert_eq!(userid.preferred_compression_algorithms(),
                       Some(&[ Zlib, BZip2, Zip ][..]));

            assert_eq!(userid.preferred_aead_algorithms(), None);

            // assert_eq!(userid.key_server_preferences(),
            //            Some(KeyServerPreferences::new(&[])));

            assert_eq!(userid.features(),
                       Some(Features::new(&[]).set_mdc(true)));
        } else {
            panic!("two user ids");
        }

        if let Some(userid) = cert.userids().nth(0) {
            assert_eq!(userid.userid().value(),
                       &b"Alice Confusion <alice@example.com>"[..]);

            let userid = userid.with_policy(p, None).expect("valid");

            use crate::types::SymmetricAlgorithm::*;
            assert_eq!(userid.preferred_symmetric_algorithms(),
                       Some(&[ AES256, AES192, AES128, TripleDES ][..]));

            use crate::types::HashAlgorithm::*;
            assert_eq!(userid.preferred_hash_algorithms(),
                       Some(&[ SHA512, SHA384, SHA256, SHA224, SHA1 ][..]));

            use crate::types::CompressionAlgorithm::*;
            assert_eq!(userid.preferred_compression_algorithms(),
                       Some(&[ Zlib, BZip2, Zip ][..]));

            assert_eq!(userid.preferred_aead_algorithms(), None);

            assert_eq!(userid.key_server_preferences(),
                       Some(KeyServerPreferences::new(&[0x80])));

            assert_eq!(userid.features(),
                       Some(Features::new(&[]).set_mdc(true)));

            // Using the certificate should choose the primary user
            // id, which is this one (because it is lexicographically
            // earlier).
            let cert = cert.with_policy(p, None).expect("valid");
            assert_eq!(userid.preferred_symmetric_algorithms(),
                       cert.preferred_symmetric_algorithms());
            assert_eq!(userid.preferred_hash_algorithms(),
                       cert.preferred_hash_algorithms());
            assert_eq!(userid.preferred_compression_algorithms(),
                       cert.preferred_compression_algorithms());
            assert_eq!(userid.preferred_aead_algorithms(),
                       cert.preferred_aead_algorithms());
            assert_eq!(userid.key_server_preferences(),
                       cert.key_server_preferences());
            assert_eq!(userid.features(),
                       cert.features());
        } else {
            panic!("two user ids");
        }

        if let Some(userid) = cert.userids().nth(1) {
            assert_eq!(userid.userid().value(),
                       &b"Alice Confusion <alice@example.net>"[..]);

            let userid = userid.with_policy(p, None).expect("valid");

            use crate::types::SymmetricAlgorithm::*;
            assert_eq!(userid.preferred_symmetric_algorithms(),
                       Some(&[ AES192, AES256, AES128, TripleDES ][..]));

            use crate::types::HashAlgorithm::*;
            assert_eq!(userid.preferred_hash_algorithms(),
                       Some(&[ SHA384, SHA512, SHA256, SHA224, SHA1 ][..]));

            use crate::types::CompressionAlgorithm::*;
            assert_eq!(userid.preferred_compression_algorithms(),
                       Some(&[ BZip2, Zlib, Zip ][..]));

            assert_eq!(userid.preferred_aead_algorithms(), None);

            assert_eq!(userid.key_server_preferences(),
                       Some(KeyServerPreferences::new(&[0x80])));

            assert_eq!(userid.features(),
                       Some(Features::new(&[]).set_mdc(true)));
        } else {
            panic!("two user ids");
        }

        Ok(())
    }
}
