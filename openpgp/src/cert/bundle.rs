//! A certificate component and its associated signatures.
//!
//! Certificates ([`Cert`]s) are a collection of components where each
//! component corresponds to a [`Packet`], and each component has zero
//! or more associated [`Signature`]s.  A [`ComponentBundle`]
//! encapsulates a component and its associated signatures.
//!
//! Sequoia supports four different kinds of components: [`Key`]s,
//! [`UserID`]s, [`UserAttribute`]s, and [`Unknown`] components.  The
//! `Unknown` component has two purposes.  First, it is used to store
//! packets that appear in a certificate and have an unknown [`Tag`].
//! By not silently dropping these packets, it is possible to round
//! trip certificates without losing any information.  This provides a
//! measure of future compatibility.  Second, the `Unknown` component
//! is used to store unsupported components.  For instance, Sequoia
//! doesn't support v3 `Key`s, which are deprecated, or v5 `Key`s,
//! which are still being standardized.  Because these keys are
//! effectively unusable, they are stored as `Unknown` components
//! instead of `Key`s.
//!
//! There are four types of signatures associated with a component:
//! self signatures, self revocations, third-party signatures, and
//! third-party revocations.  When parsing a certificate, self
//! signatures and self revocations are checked for validity and
//! invalid signatures and revocations are discarded.  Since the keys
//! are not normally available, third-party signatures and third-party
//! revocations cannot be rigorously (i.e., cryptographically) checked
//! for validity.
//!
//! With the exception of the primary key, a component's self
//! signatures are binding signatures.  A binding signature firstly
//! binds the component to the certificate.  That is, it provides
//! cryptographic evidence that the certificate holder intended for
//! the component to be associated with the certificate.  Binding
//! signatures also provide information about the component.  For
//! instance, the binding signature for a subkey includes its
//! capabilities, and its expiry time.
//!
//! Since the primary key is the embodiment of the certificate, there
//! is nothing to bind it to.  Correspondingly, self signatures on a
//! primary key are called direct key signatures.  Direct key
//! signatures are used to provide information about the whole
//! certificate.  For instance, they can include the default `Key`
//! expiry time.  This is used if a subkey's binding signature doesn't
//! include an expiry.
//!
//! Self-revocations are revocation certificates issued by the key
//! certificate holder.
//!
//! Third-party signatures are typically signatures certifying that a
//! `User ID` or `User Attribute` accurately describes the certificate
//! holder.  This information is used by trust models, like the Web of
//! Trust, to indirectly authenticate keys.
//!
//! Third-party revocations are revocations issued by another
//! certificate.  They should normally only be respected if the
//! certificate holder made the issuer a so-called [designated
//! revoker].
//!
//! # Important
//!
//! When looking up information about a component, it is generally
//! better to use the [`ComponentAmalgamation`] or [`KeyAmalgamation`]
//! data structures.  These data structures provide convenience
//! methods that implement the [complicated semantics] for correctly
//! locating information.
//!
//! [`Cert`]: super
//! [`Packet`]: crate::packet
//! [`Signature`]: crate::packet::signature
//! [`Key`]: crate::packet::key
//! [`UserID`]: crate::packet::UserID
//! [`UserAttribute`]: crate::packet::user_attribute
//! [`Unknown`]: crate::packet::Unknown
//! [`Tag`]: crate::packet::Tag
//! [designated revoker]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.23
//! [`ComponentAmalgamation`]: super::amalgamation
//! [`KeyAmalgamation`]: super::amalgamation::key::KeyAmalgamation
//! [complicated semantics]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10

use std::time;
use std::cmp::{self, Ordering};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::{
    cert::lazysigs::{LazySignatures, SigState},
    Error,
    packet::Signature,
    packet::Key,
    packet::key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    Packet,
    policy::HashAlgoSecurity,
    policy::Policy,
    Result,
};
use crate::types::{
    RevocationType,
    RevocationStatus,
};

use super::{
    sig_cmp,
    canonical_signature_order,
};

/// A certificate component and its associated signatures.
///
/// [See the module level documentation](self) for a detailed
/// description.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentBundle<C> {
    component: C,

    pub(super) hash_algo_security: HashAlgoSecurity,

    // Self signatures.
    pub(super) self_signatures: LazySignatures,

    /// If set, is equal to `component`, and provides context to
    /// verify primary key binding signatures.
    backsig_signer: Option<Key<key::PublicParts, key::SubordinateRole>>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    pub(super) certifications: Vec<Signature>,

    // Attestation key signatures.
    pub(super) attestations: LazySignatures,

    // Self revocations.
    pub(super) self_revocations: LazySignatures,

    // Third-party revocations (e.g., designated revokers).
    pub(super) other_revocations: Vec<Signature>,
}
assert_send_and_sync!(ComponentBundle<C> where C);

/// A key (primary or subkey, public or private) and any associated
/// signatures.
///
/// [See the module level documentation.](self)
pub type KeyBundle<KeyPart, KeyRole> = ComponentBundle<Key<KeyPart, KeyRole>>;

/// A primary key and any associated signatures.
///
/// [See the module level documentation.](self)
pub type PrimaryKeyBundle<KeyPart> =
    KeyBundle<KeyPart, key::PrimaryRole>;

/// A subkey and any associated signatures.
///
/// [See the module level documentation.](self)
pub type SubkeyBundle<KeyPart>
    = KeyBundle<KeyPart, key::SubordinateRole>;

/// A User ID and any associated signatures.
///
/// [See the module level documentation.](self)
pub type UserIDBundle = ComponentBundle<UserID>;

/// A User Attribute and any associated signatures.
///
/// [See the module level documentation.](self)
pub type UserAttributeBundle = ComponentBundle<UserAttribute>;

/// An unknown component and any associated signatures.
///
/// Note: all signatures are stored as certifications.
///
/// [See the module level documentation.](self)
pub type UnknownBundle = ComponentBundle<Unknown>;


impl<C> ComponentBundle<C> {
    /// Creates a new component.
    ///
    /// Should only be used from the cert parser.  However, we cannot
    /// use `pub(in ...)` because the cert parser isn't an ancestor of
    /// this module.
    pub(crate) fn new(component: C,
                      hash_algo_security: HashAlgoSecurity,
                      sigs: Vec<Signature>,
                      primary_key: Arc<Key<key::PublicParts, key::PrimaryRole>>)
           -> ComponentBundle<C>
    {
        ComponentBundle {
            component,
            hash_algo_security,
            self_signatures: LazySignatures::new(primary_key.clone()),
            backsig_signer: None,
            certifications: sigs,
            attestations: LazySignatures::new(primary_key.clone()),
            self_revocations: LazySignatures::new(primary_key),
            other_revocations: vec![],
        }
    }

    /// Returns a reference to the bundle's component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about any unknown components.
    /// for u in cert.unknowns() {
    ///     eprintln!(" - {:?}", u.bundle().component());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn component(&self) -> &C {
        &self.component
    }

    /// Returns a mutable reference to the component.
    pub(crate) fn component_mut(&mut self) -> &mut C {
        &mut self.component
    }

    /// Returns the active binding signature at time `t`.
    ///
    /// The active binding signature is the most recent, non-revoked
    /// self-signature that is valid according to the `policy` and
    /// alive at time `t` (`creation time <= t`, `t < expiry`).  If
    /// there are multiple such signatures then the signatures are
    /// ordered by their MPIs interpreted as byte strings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display information about each User ID's current active
    /// // binding signature (the `time` parameter is `None`), if any.
    /// for ua in cert.userids() {
    ///     eprintln!("{:?}", ua.bundle().binding_signature(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn binding_signature<T>(&self, policy: &dyn Policy, t: T)
                                -> Result<&Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into().unwrap_or_else(crate::now);

      /// Finds the active binding signature.
      ///
      /// This function does not depend on the type of `C`, but it
      /// is unfortunately monomorphized for every `C`.  Prevent
      /// this by moving the code to a function independent of `C`.
      fn find_binding_signature<'s>(policy: &dyn Policy,
                                    self_signatures: &'s LazySignatures,
                                    backsig_signer:
                                    Option<&Key<key::PublicParts, key::SubordinateRole>>,
                                    hash_algo_security: HashAlgoSecurity,
                                    t: time::SystemTime)
                                    -> Result<&'s Signature>
      {
        // Recall: the signatures are sorted by their creation time in
        // descending order, i.e., newest first.
        //
        // We want the newest signature that is older than `t`, or
        // that has been created at `t`.  So, search for `t`.

        // We search all signatures without triggering the signature
        // verification.  Later, we will verify the candidates, and
        // reject bad signatures.
        let unverified_self_signatures = self_signatures.as_slice_unverified();

        let i =
            // Usually, the first signature is what we are looking for.
            // Short circuit the binary search.
              if unverified_self_signatures.get(0)
              .filter(|s| s.signature_creation_time().map(|c| t >= c)
                      .unwrap_or(false))
              .filter(
                  // Verify the signature now.
                  |_| matches!(self_signatures.verify_sig(0, backsig_signer),
                               Ok(SigState::Good)))
              .is_some()
            {
                0
            } else {
                match unverified_self_signatures.binary_search_by(
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
                        while i > 0
                            && unverified_self_signatures[i - 1].signature_creation_time()
                            == Some(t)
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

        let mut sig = None;

        // Prefer the first error, which is the error arising from the
        // most recent binding signature that wasn't created after
        // `t`.
        let mut error = None;

        'next_sig: for (j, s) in unverified_self_signatures[i..].iter()
            .enumerate()
        {
            if let Err(e) = s.signature_alive(t, time::Duration::new(0, 0)) {
                // We know that t >= signature's creation time.  So,
                // it is expired.  But an older signature might not
                // be.  So, keep trying.
                if error.is_none() {
                    error = Some(e);
                }
                continue;
            }

            if let Err(e) = policy.signature(s, hash_algo_security)
            {
                if error.is_none() {
                    error = Some(e);
                }
                continue;
            }

            // Verify the signature now.
            if ! matches!(self_signatures.verify_sig(i + j, backsig_signer),
                          Ok(SigState::Good)) {
                // Reject bad signatures.
                continue;
            }

            // The signature is good, but we may still need to verify the
            // back sig.
            if s.typ() == crate::types::SignatureType::SubkeyBinding &&
                s.key_flags().map(|kf| kf.for_signing()).unwrap_or(false)
            {
                let mut n = 0;
                let mut one_good_backsig = false;
                'next_backsig: for backsig in s.embedded_signatures() {
                    n += 1;
                    if let Err(e) = backsig.signature_alive(
                        t, time::Duration::new(0, 0))
                    {
                        // The primary key binding signature is not
                        // alive.
                        if error.is_none() {
                            error = Some(e);
                        }
                        continue 'next_backsig;
                    }

                    if let Err(e) = policy
                        .signature(backsig, hash_algo_security)
                    {
                        if error.is_none() {
                            error = Some(e);
                        }
                        continue 'next_backsig;
                    }

                    one_good_backsig = true;
                }

                if n == 0 {
                    // This shouldn't happen because
                    // Signature::verify_subkey_binding checks for the
                    // primary key binding signature.  But, better be
                    // safe.
                    if error.is_none() {
                        error = Some(Error::BadSignature(
                            "Primary key binding signature missing".into())
                                     .into());
                    }
                    continue 'next_sig;
                }

                if ! one_good_backsig {
                    continue 'next_sig;
                }
            }

            sig = Some(s);
            break;
        }

        if let Some(sig) = sig {
            Ok(sig)
        } else if let Some(err) = error {
            Err(err)
        } else {
            Err(Error::NoBindingSignature(t).into())
        }
      }

        find_binding_signature(
            policy,
            &self.self_signatures,
            self.backsig_signer.as_ref(),
            self.hash_algo_security, t)
    }

    /// Returns the component's self-signatures.
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} self signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.bundle().self_signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_signatures(&self)
                           -> impl Iterator<Item=&Signature> + Send + Sync {
        self.self_signatures.iter_verified(self.backsig_signer.as_ref())
    }

    /// Returns the component's third-party certifications.
    ///
    /// The signatures are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for ua in cert.userids() {
    ///     eprintln!("User ID {} has {:?} unverified, third-party certifications",
    ///               String::from_utf8_lossy(ua.userid().value()),
    ///               ua.bundle().certifications().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn certifications(&self)
                          -> impl Iterator<Item=&Signature> + Send + Sync {
        self.certifications.iter()
    }

    /// Returns the component's revocations that were issued by the
    /// certificate holder.
    ///
    /// The revocations are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for u in cert.userids() {
    ///     eprintln!("User ID {} has {:?} revocation certificates.",
    ///               String::from_utf8_lossy(u.userid().value()),
    ///               u.bundle().self_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_revocations(&self)
                            -> impl Iterator<Item=&Signature> + Send + Sync {
        self.self_revocations.iter_verified(self.backsig_signer.as_ref())
    }

    /// Returns the component's revocations that were issued by other
    /// certificates.
    ///
    /// The revocations are *not* validated.  They are sorted by their
    /// creation time, most recent first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for u in cert.userids() {
    ///     eprintln!("User ID {} has {:?} unverified, third-party revocation certificates.",
    ///               String::from_utf8_lossy(u.userid().value()),
    ///               u.bundle().other_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn other_revocations(&self)
                             -> impl Iterator<Item=&Signature> + Send + Sync {
        self.other_revocations.iter()
    }

    /// Returns all the component's Certification Approval Key
    /// Signatures.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// A certificate owner can use Certification Approval Key
    /// Signatures to approve of third party certifications.
    /// Currently, only user ID and user attribute certifications can
    /// be approved.  See [Approved Certifications subpacket] for
    /// details.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # fn main() -> openpgp::Result<()> {
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, uid) in cert.userids().enumerate() {
    ///     eprintln!("UserID #{} ({:?}) has {:?} certification approval key signatures",
    ///               i, uid.userid().email(),
    ///               uid.bundle().approvals().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn approvals(&self)
                     -> impl Iterator<Item = &Signature> + Send + Sync
    {
        self.attestations.iter_verified(None)
    }

    /// Returns all the component's signatures.
    ///
    /// Only the self-signatures are validated.  The signatures are
    /// sorted first by type, then by creation time.  The self
    /// revocations come first, then the self signatures,
    /// then any certification approval key signatures,
    /// certifications, and third-party revocations coming last.  This
    /// function may return additional types of signatures that could
    /// be associated to this component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for (i, ka) in cert.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.bundle().signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn signatures(&self)
                      -> impl Iterator<Item = &Signature> + Send + Sync
    {
        self.self_revocations()
            .chain(self.self_signatures())
            .chain(self.approvals())
            .chain(self.certifications())
            .chain(self.other_revocations())
    }

    /// Returns all the bundles' bad signatures.
    pub(crate) fn bad_signatures(&self)
        -> impl Iterator<Item = &Signature> + Send + Sync
    {
        self.self_signatures.iter_bad(self.backsig_signer.as_ref())
            .chain(self.self_revocations.iter_bad(self.backsig_signer.as_ref()))
    }

    /// Returns the component's revocation status at time `t`.
    ///
    /// A component is considered to be revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`.
    ///
    ///   - `hard_revocations_are_final` is true, and there is a hard
    ///     revocation (even if it is not yet live at time `t`, and
    ///     even if there is a newer self-signature).
    ///
    /// selfsig must be the newest live self signature at time `t`.
    pub(crate) fn revocation_status_intern<'a>(&'a self, policy: &dyn Policy,
                                               t: Option<time::SystemTime>,
                                               hard_revocations_are_final: bool,
                                               selfsig: Option<&Signature>)
        -> RevocationStatus<'a>
    {
        // Fallback time.
        let time_zero = || time::UNIX_EPOCH;
        let t = t.unwrap_or_else(crate::now);
        let selfsig_creation_time
            = selfsig.and_then(|s| s.signature_creation_time())
                     .unwrap_or_else(time_zero);

        tracer!(super::TRACE, "ComponentBundle::_revocation_status", 0);
        t!("hard_revocations_are_final: {}, selfsig: {:?}, t: {:?}",
           hard_revocations_are_final,
           selfsig_creation_time,
           t);
        if let Some(selfsig) = selfsig {
            assert!(
                selfsig.signature_alive(t, time::Duration::new(0, 0)).is_ok());
        }

        let check = |revs: &mut dyn Iterator<Item=&'a Signature>, sec: HashAlgoSecurity|
            -> Option<Vec<&'a Signature>>
        {
            let revs = revs.filter(|rev| {
                if let Err(err) = policy.signature(rev, sec) {
                    t!("  revocation rejected by caller policy: {}", err);
                    false
                } else if hard_revocations_are_final
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
                    true
                } else if selfsig_creation_time
                    > rev.signature_creation_time().unwrap_or_else(time_zero)
                {
                    // This comes after the hard revocation check,
                    // because a hard revocation is always valid.
                    t!("  newer binding signature trumps soft revocation ({:?} > {:?})",
                       selfsig_creation_time,
                       rev.signature_creation_time().unwrap_or_else(time_zero));
                    false
                } else if let Err(err)
                    = rev.signature_alive(t, time::Duration::new(0, 0))
                {
                    // This comes after the hard revocation check,
                    // because a hard revocation is always valid.
                    t!("  revocation not alive ({:?} - {:?}): {}",
                       rev.signature_creation_time().unwrap_or_else(time_zero),
                       rev.signature_validity_period()
                           .unwrap_or_else(|| time::Duration::new(0, 0)),
                       err);
                    false
                } else {
                    t!("  got a revocation: {:?} ({:?})",
                       rev.signature_creation_time().unwrap_or_else(time_zero),
                       rev.reason_for_revocation()
                           .map(|r| (r.0, String::from_utf8_lossy(r.1))));
                    true
                }
            }).collect::<Vec<&Signature>>();

            if revs.is_empty() {
                None
            } else {
                Some(revs)
            }
        };

        if let Some(revs)
            = check(&mut self.self_revocations.iter_verified(self.backsig_signer.as_ref()),
                    self.hash_algo_security)
        {
            t!("-> RevocationStatus::Revoked({})", revs.len());
            RevocationStatus::Revoked(revs)
        } else if let Some(revs)
            = check(&mut self.other_revocations.iter(), Default::default())
        {
            t!("-> RevocationStatus::CouldBe({})", revs.len());
            RevocationStatus::CouldBe(revs)
        } else {
            t!("-> RevocationStatus::NotAsFarAsWeKnow");
            RevocationStatus::NotAsFarAsWeKnow
        }
    }

    /// Turns the `ComponentBundle` into an iterator over its
    /// `Packet`s.
    ///
    /// The signatures are ordered as follows:
    ///
    ///   - Self revocations,
    ///   - Self signatures,
    ///   - Third-party signatures, and
    ///   - Third-party revocations.
    ///
    /// For a given type of signature, the signatures are ordered by
    /// their creation time, most recent first.
    ///
    /// When turning the `Key` in a `KeyBundle` into a `Packet`, this
    /// function uses the component's type (`C`) to determine the
    /// packet's type; the type is not a function of whether the key
    /// has secret key material.
    pub(crate) fn into_packets(self)
                               -> impl Iterator<Item=Packet> + Send + Sync
        where Packet: From<C>
    {
        let p : Packet = self.component.into();
        std::iter::once(p)
            .chain(self.self_revocations.into_unverified().map(|s| s.into()))
            .chain(self.self_signatures.into_unverified().map(|s| s.into()))
            .chain(self.attestations.into_unverified().map(|s| s.into()))
            .chain(self.certifications.into_iter().map(|s| s.into()))
            .chain(self.other_revocations.into_iter().map(|s| s.into()))
    }

    // Sorts and dedups the binding's signatures.
    //
    // Note: this uses Signature::normalized_eq to compare signatures.
    // That function ignores unhashed packets.  If there are two
    // signatures that only differ in their unhashed subpackets, they
    // will be deduped.  The unhashed areas are merged as discussed in
    // Signature::merge.
    pub(crate) fn sort_and_dedup(&mut self)
    {
        // `same_bucket` function for Vec::dedup_by that compares
        // signatures and merges them if they are equal modulo
        // unhashed subpackets.
        fn sig_merge(a: &mut Signature, b: &mut Signature) -> bool {
            // If a == b, a is removed.  Hence, we merge into b.
            if a.normalized_eq(b) {
                b.merge_internal(a)
                    .expect("checked for equality above");
                true
            } else {
                false
            }
        }

        // If two signatures are merged, we also do some fixups.  Make
        // sure we also do this to signatures that are not merged, so
        // that `cert.merge(cert) == cert`.
        fn sig_fixup(sig: &mut Signature) {
            // Add missing issuer information.  This is a best effort
            // though.  If the unhashed area is full, there is nothing
            // we can do.
            let _ = sig.add_missing_issuers();

            // Merging Signatures sorts the unhashed subpacket area.
            // Do the same.
            sig.unhashed_area_mut().sort();
        }

        self.self_signatures.sort_by(Signature::normalized_cmp);
        self.self_signatures.dedup_by(sig_merge);
        // Order self signatures so that the most recent one comes
        // first.
        self.self_signatures.sort_by(sig_cmp);
        self.self_signatures.iter_mut_unverified().for_each(sig_fixup);

        self.attestations.sort_by(Signature::normalized_cmp);
        self.attestations.dedup_by(sig_merge);
        self.attestations.sort_by(sig_cmp);
        self.attestations.iter_mut_unverified().for_each(sig_fixup);

        self.certifications.sort_by(Signature::normalized_cmp);
        self.certifications.dedup_by(sig_merge);
        // There is no need to sort the certifications, but doing so
        // has the advantage that the most recent ones (and therefore
        // presumably the more relevant ones) come first.  Also,
        // cert::test::signature_order checks that the signatures are
        // sorted.
        self.certifications.sort_by(sig_cmp);
        self.certifications.iter_mut().for_each(sig_fixup);

        self.self_revocations.sort_by(Signature::normalized_cmp);
        self.self_revocations.dedup_by(sig_merge);
        self.self_revocations.sort_by(sig_cmp);
        self.self_revocations.iter_mut_unverified().for_each(sig_fixup);

        self.other_revocations.sort_by(Signature::normalized_cmp);
        self.other_revocations.dedup_by(sig_merge);
        self.other_revocations.sort_by(sig_cmp);
        self.other_revocations.iter_mut().for_each(sig_fixup);
    }
}

impl<P: key::KeyParts, R: key::KeyRole> ComponentBundle<Key<P, R>> {
    /// Returns a reference to the key.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentBundle::component`].
    ///
    /// [`ComponentBundle::component`]: ComponentBundle::component()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about the keys.
    /// for ka in cert.keys() {
    ///     eprintln!(" - {:?}", ka.bundle().key());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn key(&self) -> &Key<P, R> {
        self.component()
    }

    /// Returns a mut reference to the key.
    pub(crate) fn key_mut(&mut self) -> &mut Key<P, R> {
        self.component_mut()
    }

    pub(crate) fn set_role(&mut self, role: key::KeyRoleRT) {
        self.key_mut().set_role(role);
    }

    /// Forwarder for the conversion macros.
    pub(crate) fn has_secret(&self) -> bool {
        self.key().has_secret()
    }
}

impl<P: key::KeyParts> ComponentBundle<Key<P, key::SubordinateRole>> {
    /// Creates a new subkey component.
    ///
    /// Should only be used from the cert parser.  However, we cannot
    /// use `pub(in ...)` because the cert parser isn't an ancestor of
    /// this module.
    pub(crate) fn new_subkey(component: Key<P, key::SubordinateRole>,
                             hash_algo_security: HashAlgoSecurity,
                             sigs: Vec<Signature>,
                             primary_key: Arc<Key<key::PublicParts, key::PrimaryRole>>)
           -> Self
    {
        let backsig_signer = component.pk_algo().for_signing()
            .then(|| component.parts_as_public().clone());
        ComponentBundle {
            component,
            hash_algo_security,
            self_signatures: LazySignatures::new(primary_key.clone()),
            backsig_signer,
            certifications: sigs,
            attestations: LazySignatures::new(primary_key.clone()),
            self_revocations: LazySignatures::new(primary_key),
            other_revocations: vec![],
        }
    }

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
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display the subkeys' revocation status.
    /// for ka in cert.keys().subkeys() {
    ///     eprintln!(" Revocation status of {}: {:?}",
    ///               ka.key().fingerprint(),
    ///               ka.bundle().revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self.revocation_status_intern(policy, t, true,
                                      self.binding_signature(policy, t).ok())
    }
}

impl ComponentBundle<UserID> {
    /// Returns a reference to the User ID.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentBundle::component`].
    ///
    /// [`ComponentBundle::component`]: ComponentBundle::component()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about the User IDs.
    /// for ua in cert.userids() {
    ///     eprintln!(" - {:?}", ua.bundle().userid());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn userid(&self) -> &UserID {
        self.component()
    }

    /// Returns the User ID's revocation status at time `t`.<a
    /// name="userid_revocation_status"></a>
    ///
    /// <!-- Why we have the above anchor:
    ///      https://github.com/rust-lang/rust/issues/71912 -->
    ///
    /// A User ID is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`.
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User ID is revoked; it
    /// does not imply anything about the Cert or other components.
    //
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display the User IDs' revocation status.
    /// for ua in cert.userids() {
    ///     eprintln!(" Revocation status of {}: {:?}",
    ///               String::from_utf8_lossy(ua.userid().value()),
    ///               ua.bundle().revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self.revocation_status_intern(policy, t, false, self.binding_signature(policy, t).ok())
    }
}

impl ComponentBundle<UserAttribute> {
    /// Returns a reference to the User Attribute.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentBundle::component`].
    ///
    /// [`ComponentBundle::component`]: ComponentBundle::component()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about the User Attributes
    /// for ua in cert.user_attributes() {
    ///     eprintln!(" - {:?}", ua.bundle().user_attribute());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn user_attribute(&self) -> &UserAttribute {
        self.component()
    }

    /// Returns the User Attribute's revocation status at time `t`.
    ///
    /// A User Attribute is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`.
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this User Attribute is revoked;
    /// it does not imply anything about the Cert or other components.
    //
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display the User Attributes' revocation status.
    /// for (i, ua) in cert.user_attributes().enumerate() {
    ///     eprintln!(" Revocation status of User Attribute #{}: {:?}",
    ///               i, ua.bundle().revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
        -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self.revocation_status_intern(policy, t, false,
                                      self.binding_signature(policy, t).ok())
    }
}

impl ComponentBundle<Unknown> {
    /// Returns a reference to the unknown component.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentBundle::component`].
    ///
    /// [`ComponentBundle::component`]: ComponentBundle::component()
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// // Display some information about the User Attributes
    /// for u in cert.unknowns() {
    ///     eprintln!(" - {:?}", u.unknown());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn unknown(&self) -> &Unknown {
        self.component()
    }
}

/// A collection of `ComponentBundles`.
///
/// Note: we need this, because we can't `impl Vec<ComponentBundles>`.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    bundles: Vec<ComponentBundle<C>>,
}

impl<C> Default for ComponentBundles<C>
where
    ComponentBundle<C>: cmp::PartialEq,
{
        fn default() -> Self {
        ComponentBundles {
            bundles: vec![],
        }
    }
}

impl<C> Deref for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    type Target = Vec<ComponentBundle<C>>;

    fn deref(&self) -> &Self::Target {
        &self.bundles
    }
}

impl<C> DerefMut for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn deref_mut(&mut self) -> &mut Vec<ComponentBundle<C>> {
        &mut self.bundles
    }
}

impl<C> From<ComponentBundles<C>> for Vec<ComponentBundle<C>>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn from(cb: ComponentBundles<C>) -> Vec<ComponentBundle<C>> {
        cb.bundles
    }
}

impl<C> From<Vec<ComponentBundle<C>>> for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    fn from(bundles: Vec<ComponentBundle<C>>) -> ComponentBundles<C> {
        ComponentBundles {
            bundles,
        }
    }
}

impl<C> IntoIterator for ComponentBundles<C>
    where ComponentBundle<C>: cmp::PartialEq
{
    type Item = ComponentBundle<C>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bundles.into_iter()
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
    pub(super) fn sort_and_dedup<F, F2>(&mut self, cmp: F, merge: F2)
        where F: Fn(&C, &C) -> Ordering,
              F2: Fn(&mut C, &mut C)
    {
        // We dedup by component (not bundles!).  To do this, we need
        // to sort the bundles by their components.

        self.bundles.sort_by(
            |a, b| cmp(&a.component, &b.component));

        self.bundles.dedup_by(|a, b| {
            if cmp(&a.component, &b.component) == Ordering::Equal {
                // Merge.
                merge(&mut a.component, &mut b.component);

                // Recall: if a and b are equal, a will be dropped.
                // Also, the elements are given in the opposite order
                // from their order in the vector.
                b.self_signatures.append(&mut a.self_signatures);
                b.attestations.append(&mut a.attestations);
                b.certifications.append(&mut a.certifications);
                b.self_revocations.append(&mut a.self_revocations);
                b.other_revocations.append(&mut a.other_revocations);

                true
            } else {
                false
            }
        });

        // And sort the certificates.
        for b in self.bundles.iter_mut() {
            b.sort_and_dedup();
        }
    }
}

/// A vecor of key (primary or subkey, public or private) and any
/// associated signatures.
pub(super) type KeyBundles<KeyPart, KeyRole>
    = ComponentBundles<Key<KeyPart, KeyRole>>;

/// A vector of subkeys and any associated signatures.
pub(super) type SubkeyBundles<KeyPart>
    = KeyBundles<KeyPart, key::SubordinateRole>;

/// A vector of key (primary or subkey, public or private) and any
/// associated signatures.
#[allow(dead_code)]
pub(super) type GenericKeyBundles
    = ComponentBundles<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A vector of User ID bundles and any associated signatures.
pub(super) type UserIDBundles = ComponentBundles<UserID>;

/// A vector of User Attribute bundles and any associated signatures.
pub(super) type UserAttributeBundles = ComponentBundles<UserAttribute>;

/// A vector of unknown components and any associated signatures.
///
/// Note: all signatures are stored as certifications.
pub(super) type UnknownBundles = ComponentBundles<Unknown>;
