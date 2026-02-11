//! Components, their associated signatures, and some useful methods.
//!
//! Whereas a [`ComponentBundle`] owns a `Component` and its
//! associated [`Signature`]s, a [`ComponentAmalgamation`] references
//! a `ComponentBundle` and its containing [`Cert`].  This additional
//! context means that a `ComponentAmalgamation` can implement more of
//! OpenPGP's high-level semantics than a `ComponentBundle` can.  For
//! instance, most of the information about a primary key, such as its
//! capabilities, is on the primary User ID's binding signature.  A
//! `ComponentAmalgamation` can find the certificate's primary User
//! ID; a `ComponentBundle` can't.  Similarly, when looking up a
//! subpacket, if it isn't present in the component's binding
//! signature, then an OpenPGP implementation [is supposed to] consult
//! the certificate's direct key signatures.  A
//! `ComponentAmalgamation` has access to this information; a
//! `ComponentBundle` doesn't.
//!
//! Given the limitations of a `ComponentBundle`, it would seem more
//! useful to just change it to include a reference to its containing
//! certificate.  That change would make `ComponentAmalgamation`s
//! redundant.  Unfortunately, this isn't possible, because it would
//! result in a self-referential data structure, which Rust doesn't
//! allow.  To understand how this arises, consider a certificate `C`,
//! which contains a `ComponentBundle` `B`.  If `B` contains a
//! reference to `C`, then `C` references itself, because `C` contains
//! `B`!
//!
//! ```text
//! Cert:[ Bundle:[ &Cert ] ]
//!      ^            |
//!      `------------'
//! ```
//!
//! # Policy
//!
//! Although a `ComponentAmalgamation` contains the information
//! necessary to realize high-level OpenPGP functionality, components
//! can have multiple self signatures, and functions that consult the
//! binding signature need to determine the best one to use.  There
//! are two main concerns here.
//!
//! First, we need to protect the user from forgeries.  As attacks
//! improve, cryptographic algorithms that were once considered secure
//! now provide insufficient security margins.  For instance, in 2007
//! it was possible to find [MD5 collisions] using just a few seconds
//! of computing time on a desktop computer.  Sequoia provides a
//! flexible mechanism, called [`Policy`] objects, that allow users to
//! implement this type of filtering: before a self signature is used,
//! a policy object is queried to determine whether the `Signature`
//! should be rejected.  If so, then it is skipped.
//!
//! Second, we need an algorithm to determine the most appropriate
//! self signature.  Obvious non-candidate self signatures are self
//! signatures whose creation time is in the future.  We don't assume
//! that these self signatures are bad per se, but that they represent
//! a policy that should go into effect some time in the future.
//!
//! We extend this idea of a self signature representing a policy for
//! a certain period of time to all self signatures.  In particular,
//! Sequoia takes the view that *a binding signature represents a
//! policy that is valid from its creation time until its expiry*.
//! Thus, when considering what self signature to use, we need a
//! reference time.  Given the reference time, we then use the self
//! signature that was in effect at that time, i.e., the most recent,
//! non-expired, non-revoked self signature that was created at or
//! prior to the reference time.  In other words, we ignore self
//! signatures created after the reference time.  We take the position
//! that if the certificate holder wants a new policy to apply to
//! existing signatures, then the new self signature should be
//! backdated, and existing self signatures revoked, if necessary.
//!
//! Consider evaluating a signature over a document.  Sequoia's
//! [streaming verifier] uses the signature's creation time as the
//! reference time.  Thus, if the signature was created on June 9th,
//! 2011, then, when evaluating that signature, the streaming verifier
//! uses a self signature that was live at that time, since that was
//! the self signature that represented the signer's policy at the
//! time the signature over the document was created.
//!
//! A consequence of this approach is that even if the self signature
//! were considered expired at the time the signature was evaluated
//! (e.g., "now"), this fact doesn't invalidate the signature.  That
//! is, a self signature's lifetime does not impact a signature's
//! lifetime; a signature's lifetime is defined by its own creation
//! time and expiry.  Similarly, a key's lifetime is defined by its
//! own creation time and expiry.
//!
//! This interpretation of lifetimes removes a major disadvantage that
//! comes with fast rotation of subkeys: if an implementation binds
//! the lifetime of signatures to the signing key, and the key
//! expires, then old signatures are considered invalid.  Consider a
//! user who generates a new signature subkey each week, and sets it
//! to expire after exactly one week.  If we use the policy that the
//! signature is only valid while the key *and* the self signature are
//! live, then if someone checks the signature a week after receiving
//! it, the signature will be considered invalid, because the key has
//! expired.  The practical result is that all old messages from this
//! user will be considered invalid!  Unfortunately, this will result
//! in users becoming accustomed to seeing invalid signatures, and
//! cause them to be less suspcious of them.
//!
//! Sequoia's low-level mechanisms support this interpretation of self
//! signatures, but they do *not* enforce it.  It is still possible to
//! realize other policies using this low-level API.
//!
//! The possibility of abuse of this interpretation of signature
//! lifetimes is limited.  If a key has been compromised, then the
//! right thing to do is to revoke it.  Expiry doesn't help: the
//! attacker can simply create self-signatures that say whatever she
//! wants.  Assuming the secret key material has not been compromised,
//! then an attacker could still reuse a message that would otherwise
//! be considered expired.  However, the attacker will not be able to
//! change the signature's creation time, so, assuming a mail context
//! and MUAs that check that the time in the message's headers matches
//! the signature's creation time, the mails will appear old.
//! Further, this type of attack will be mitigated by the proposed
//! "[Intended Recipients]" subpacket, which more tightly binds the
//! message to its context.
//!
//! # [`ValidComponentAmalgamation`]
//!
//! Most operations need to query a `ComponentAmalgamation` for
//! multiple pieces of information.  Accidentally using a different
//! `Policy` or a different reference time for one of the queries is
//! easy, especially when the queries are spread across multiple
//! functions.  Further, using `None` for the reference time can
//! result in subtle timing bugs as each function translates it to the
//! current time on demand.  In these cases, the correct approach
//! would be for the user of the library to get the current time at
//! the start of the operation.  But, this is less convenient.
//! Finally, passing a `Policy` and a reference time to most function
//! calls clutters the code.
//!
//! To mitigate these issues, we have a separate data structure,
//! `ValidComponentAmalgamation`, which combines a
//! `ComponetAmalgamation`, a `Policy` and a reference time.  It
//! implements methods that require a `Policy` and reference time, but
//! instead of requiring the caller to pass them in, it uses the ones
//! embedded in the data structure.  Further, when the
//! `ValidComponentAmalgamation` constructor is passed `None` for the
//! reference time, it eagerly stores the current time, and uses that
//! for all operations.  This approach elegantly solves all the
//! aforementioned problems.
//!
//! [`ComponentBundle`]: super::bundle
//! [`Signature`]: crate::packet::signature
//! [`Cert`]: super
//! [is supposed to]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
//! [`std::iter::map`]: std::iter::Map
//! [MD5 collisions]: https://en.wikipedia.org/wiki/MD5
//! [`Policy`]: crate::policy::Policy
//! [streaming verifier]: crate::parse::stream
//! [Intended Recipients]: https://www.rfc-editor.org/rfc/rfc9580.html#intended-recipient-fingerprint
//! [signature expirations]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.18
use std::time;
use std::time::{
    Duration,
    SystemTime,
};
use std::clone::Clone;
use std::borrow::Borrow;

use crate::{
    cert::prelude::*,
    crypto::{Signer, hash::Hash},
    Error,
    KeyHandle,
    packet,
    packet::{
        Key,
        Signature,
        Unknown,
        UserAttribute,
        UserID,
        key::{PrimaryRole, PublicParts},
    },
    Result,
    policy::{
        HashAlgoSecurity,
        Policy,
    },
    seal,
    types::{
        AEADAlgorithm,
        CompressionAlgorithm,
        Features,
        HashAlgorithm,
        KeyServerPreferences,
        RevocationKey,
        RevocationStatus,
        RevocationType,
        SignatureType,
        SymmetricAlgorithm,
    },
};

mod iter;
pub use iter::{
    ComponentAmalgamationIter,
    UnknownComponentAmalgamationIter,
    UserAttributeAmalgamationIter,
    UserIDAmalgamationIter,
    ValidComponentAmalgamationIter,
    ValidUserAttributeAmalgamationIter,
    ValidUserIDAmalgamationIter,
};

pub mod key;

/// Embeds a policy and a reference time in an amalgamation.
///
/// This is used to turn a [`ComponentAmalgamation`] into a
/// [`ValidComponentAmalgamation`], and a [`KeyAmalgamation`] into a
/// [`ValidKeyAmalgamation`].
///
/// A certificate or a component is considered valid if:
///
///   - It has a self signature that is live at time `t`.
///
///   - The policy considers it acceptable.
///
///   - The certificate is valid.
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
///
/// # Examples
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::{Policy, StandardPolicy};
///
/// const POLICY: &dyn Policy = &StandardPolicy::new();
///
/// fn f(ua: UserIDAmalgamation) -> openpgp::Result<()> {
///     let ua = ua.with_policy(POLICY, None)?;
///     // ...
/// #   Ok(())
/// }
/// # fn main() -> openpgp::Result<()> {
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(Some("alice@example.org"))
/// #         .generate()?;
/// #     let ua = cert.userids().nth(0).expect("User IDs");
/// #     f(ua);
/// #     Ok(())
/// # }
/// ```
///
pub trait ValidateAmalgamation<'a, C: 'a>: seal::Sealed {
    /// The type returned by `with_policy`.
    ///
    /// This is either a [`ValidComponentAmalgamation`] or
    /// a [`ValidKeyAmalgamation`].
    ///
    type V;

    /// Uses the specified `Policy` and reference time with the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// Applies a policy to an amalgamation.
///
/// This is an internal variant of `ValidateAmalgamation`, which
/// allows validating a component for an otherwise invalid
/// certificate.  See `ValidComponentAmalgamation::primary` for an
/// explanation.
trait ValidateAmalgamationRelaxed<'a, C: 'a> {
    /// The type returned by `with_policy`.
    type V;

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only expose to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    fn with_policy_relaxed<T>(&self, policy: &'a dyn Policy, time: T,
                              valid_cert: bool) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// Methods for valid amalgamations.
///
/// The methods exposed by a `ValidComponentAmalgamation` are similar
/// to those exposed by a `ComponentAmalgamation`, but the policy and
/// reference time are included in the `ValidComponentAmalgamation`.
/// This helps prevent using different policies or different reference
/// times when using a component, which can easily happen when the
/// checks span multiple functions.
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside this crate.
/// Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate
/// you also need to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait ValidAmalgamation<'a, C: 'a>: seal::Sealed
{
    /// Returns the valid amalgamation's associated certificate.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let vcert = ua.valid_cert();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let fpr = cert.fingerprint();
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     assert_eq!(ua.cert().fingerprint(), fpr);
    /// #     f(&ua.with_policy(p, None)?);
    /// #     Ok(())
    /// # }
    /// ```
    fn valid_cert(&self) -> &ValidCert<'a>;

    /// Returns the amalgamation's reference time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::{SystemTime, Duration, UNIX_EPOCH};
    /// #
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let t = ua.time();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let t = UNIX_EPOCH + Duration::from_secs(1554542220);
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .set_creation_time(t)
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, t)?;
    /// #     assert_eq!(t, ua.time());
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn time(&self) -> SystemTime;

    /// Returns the amalgamation's policy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let policy = ua.policy();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p: &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, None)?;
    /// #     assert!(std::ptr::eq(p, ua.policy()));
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn policy(&self) -> &'a dyn Policy;

    /// Returns the component's binding signature as of the reference time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let sig = ua.binding_signature();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p: &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, None)?;
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn binding_signature(&self) -> &'a Signature;

    /// Returns the certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate, cf. [Section 5.2.3.10 of RFC 9580].
    ///
    /// [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let sig = ua.direct_key_signature();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p: &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     assert!(std::ptr::eq(ua.direct_key_signature().unwrap(),
    /// #                          cert.direct_key_signature().unwrap()));
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn direct_key_signature(&self) -> Result<&'a Signature> {
        self.valid_cert().cert().primary_key()
            .binding_signature(self.policy(), self.time())
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// This does *not* check whether the certificate has been
    /// revoked.  For that, use `Cert::revocation_status()`.
    ///
    /// Note, as per [Section 5.2.3.31 of RFC 9580], a key is considered to be revoked at
    /// some time if there were no soft revocations created as of that
    /// time, and no hard revocations:
    ///
    /// > If a key has been revoked because of a compromise, all signatures
    /// > created by that key are suspect.  However, if it was merely
    /// > superseded or retired, old signatures are still valid.
    ///
    /// [Section 5.2.3.31 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationStatus;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// match ua.revocation_status() {
    ///     RevocationStatus::Revoked(revs) => {
    ///         // The certificate holder revoked the User ID.
    /// #       unreachable!();
    ///     }
    ///     RevocationStatus::CouldBe(revs) => {
    ///         // There are third-party revocations.  You still need
    ///         // to check that they are valid (this is necessary,
    ///         // because without the Certificates are not normally
    ///         // available to Sequoia).
    /// #       unreachable!();
    ///     }
    ///     RevocationStatus::NotAsFarAsWeKnow => {
    ///         // We have no evidence that the User ID is revoked.
    ///     }
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    fn revocation_status(&self) -> RevocationStatus<'a>;

    /// Returns a list of any designated revokers for this component.
    ///
    /// This function returns the designated revokers listed on the
    /// components' binding signatures and the certificate's direct
    /// key signatures.
    ///
    /// Note: the returned list is deduplicated.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationKey;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (alice, _) =
    ///     CertBuilder::general_purpose(Some("alice@example.org"))
    ///     .generate()?;
    /// // Make Alice a designated revoker for Bob.
    /// let (bob, _) =
    ///     CertBuilder::general_purpose(Some("bob@example.org"))
    ///     .set_revocation_keys(vec![(&alice).into()])
    ///     .generate()?;
    ///
    /// // Make sure Alice is listed as a designated revoker for Bob's
    /// // primary user id.
    /// assert_eq!(bob.with_policy(p, None)?.primary_userid()?
    ///            .revocation_keys().collect::<Vec<&RevocationKey>>(),
    ///            vec![&(&alice).into()]);
    ///
    /// // Make sure Alice is listed as a designated revoker for Bob's
    /// // encryption subkey.
    /// assert_eq!(bob.with_policy(p, None)?
    ///            .keys().for_transport_encryption().next().unwrap()
    ///            .revocation_keys().collect::<Vec<&RevocationKey>>(),
    ///            vec![&(&alice).into()]);
    /// # Ok(()) }
    /// ```
    fn revocation_keys(&self)
                       -> Box<dyn Iterator<Item = &'a RevocationKey> + 'a>;
}

#[test]
fn valid_amalgamation_is_dyn_compatible() {
    let _t: Option<Box<dyn ValidAmalgamation<()>>> = None;
}

/// Locates information on the active binding signature or direct key
/// signature.
///
/// # Sealed trait
///
/// This trait is [sealed] and cannot be implemented for types outside
/// this crate.  Therefore it can be extended in a non-breaking way.
/// If you want to implement the trait inside the crate you also need
/// to implement the `seal::Sealed` marker trait.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait ValidBindingSignature<'a, C: 'a>: ValidAmalgamation<'a, C> + seal::Sealed
{
    /// Maps the given function over binding and direct key signature.
    ///
    /// Makes `f` consider both the binding signature and the direct
    /// key signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.10 of RFC 9580].
    ///
    ///   [Section 5.2.3.10 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10
    fn map<F: Fn(&'a Signature) -> Option<T>, T>(&self, f: F) -> Option<T> {
        f(self.binding_signature())
            .or_else(|| self.direct_key_signature().ok().and_then(f))
    }
}

/// A certificate component, its associated data, and useful methods.
///
/// [`Cert::userids`], [`ValidCert::primary_userid`], [`Cert::user_attributes`], and
/// [`Cert::unknowns`] return `ComponentAmalgamation`s.
///
/// `ComponentAmalgamation` implements [`ValidateAmalgamation`], which
/// allows you to turn a `ComponentAmalgamation` into a
/// [`ValidComponentAmalgamation`] using
/// [`ComponentAmalgamation::with_policy`].
///
/// [See the module's documentation] for more details.
///
/// # Examples
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// // Iterate over all User IDs.
/// for ua in cert.userids() {
///     // ua is a `ComponentAmalgamation`, specifically, a `UserIDAmalgamation`.
/// }
/// #     Ok(())
/// # }
/// ```
///
/// [`Cert`]: super::Cert
/// [`Cert::userids`]: super::Cert::userids()
/// [`ValidCert::primary_userid`]: super::ValidCert::primary_userid()
/// [`Cert::user_attributes`]: super::Cert::user_attributes()
/// [`Cert::unknowns`]: super::Cert::unknowns()
/// [`ComponentAmalgamation::with_policy`]: ValidateAmalgamation::with_policy()
/// [See the module's documentation]: self
#[derive(Debug, PartialEq)]
pub struct ComponentAmalgamation<'a, C> {
    cert: &'a Cert,
    bundle: &'a ComponentBundle<C>,
}
assert_send_and_sync!(ComponentAmalgamation<'_, C> where C);

/// A User ID and its associated data.
///
/// A specialized version of [`ComponentAmalgamation`].
///
pub type UserIDAmalgamation<'a> = ComponentAmalgamation<'a, UserID>;

/// A User Attribute and its associated data.
///
/// A specialized version of [`ComponentAmalgamation`].
///
pub type UserAttributeAmalgamation<'a>
    = ComponentAmalgamation<'a, UserAttribute>;

/// An Unknown component and its associated data.
///
/// A specialized version of [`ComponentAmalgamation`].
///
pub type UnknownComponentAmalgamation<'a>
    = ComponentAmalgamation<'a, Unknown>;

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert,
            bundle: self.bundle,
        }
    }
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Creates a new amalgamation.
    pub(crate) fn new(cert: &'a Cert, bundle: &'a ComponentBundle<C>) -> Self
    {
        Self {
            cert,
            bundle,
        }
    }

    /// Returns the amalgamations's associated certificate.
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for u in cert.userids() {
    ///     // It's not only an identical `Cert`, it's the same one.
    ///     assert!(std::ptr::eq(u.cert(), &cert));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn cert(&self) -> &'a Cert {
        self.cert
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
    ///     eprintln!("{:?}", ua.binding_signature(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
                                -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(crate::now);
        self.bundle().binding_signature(policy, time)
    }

    /// Returns this amalgamation's bundle.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// cert.userids()
    ///     .map(|ua| ua.bundle())
    ///     .collect::<Vec<&ComponentBundle<_>>>();
    /// # Ok(()) }
    /// ```
    pub fn bundle(&self) -> &'a ComponentBundle<C> {
        self.bundle
    }

    /// Returns this amalgamation's component.
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
    ///     eprintln!(" - {:?}", u.component());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn component(&self) -> &'a C {
        self.bundle().component()
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
    ///               ka.self_signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_signatures(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.bundle().self_signatures()
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
    ///               ua.certifications().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn certifications(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.bundle().certifications()
    }

    /// Returns third-party certifications that appear to issued by
    /// any of the specified keys.
    ///
    /// A certification is returned if one of the provided key handles
    /// matches an [Issuer subpacket] or [Issuer Fingerprint
    /// subpacket] in the certification.
    ///
    ///   [Issuer subpacket]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.12
    ///   [Issuer Fingerprint subpacket]: https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr
    ///
    /// This function does not check that a certification is valid.
    /// It can't.  To check that a certification was actually issued
    /// by a specific key, we also need a policy and the public key,
    /// which we don't have.  To only get valid certifications, use
    /// [`UserIDAmalgamation::valid_certifications_by_key`] or
    /// [`UserIDAmalgamation::active_certifications_by_key`] instead
    /// of this function.
    pub fn certifications_by_key<'b>(&'b self, issuers: &'b [ KeyHandle ])
        -> impl Iterator<Item=&'a Signature> + Send + Sync + 'b
    {
        self.certifications().filter(|certification| {
            certification.get_issuers().into_iter().any(|certification_issuer| {
                issuers.iter().any(|issuer| {
                    certification_issuer.aliases(issuer)
                })
            })
        })
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
    ///               u.self_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.bundle().self_revocations()
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
    ///               u.other_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn other_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync {
        self.bundle().other_revocations()
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
    /// Currently, only userid and user attribute certifications can
    /// be approved of.  See [Approved Certifications subpacket] for
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
    ///               uid.approvals().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn approvals(&self)
                     -> impl Iterator<Item=&'a Signature> + Send + Sync + 'a
    {
        self.bundle().approvals()
    }

    /// Returns all the component's signatures.
    ///
    /// Only the self-signatures are validated.  The signatures are
    /// sorted first by type, then by creation time.  The self
    /// revocations come first, then the self signatures,
    /// then any certification approval key  signatures,
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
    ///               ka.signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn signatures(&self)
                      -> impl Iterator<Item = &'a Signature> + Send + Sync {
        self.bundle().signatures()
    }

    // Used to implement
    // [`UserIDAmalgamation::valid_certifications_by_key`],
    // [`KeyAmalgamation::valid_certifications_by_key`],
    // [`UserIDAmalgamation::active_certifications_by_key`], and
    // [`KeyAmalgamation::active_certifications_by_key`].
    fn valid_certifications_by_key_<'b, F>(
        &self,
        policy: &'a dyn Policy,
        reference_time: Option<time::SystemTime>,
        issuer: &'a packet::Key<packet::key::PublicParts,
                                packet::key::UnspecifiedRole>,
        only_active: bool,
        certifications: impl Iterator<Item=&'b Signature> + Send + Sync,
        verify_certification: F)
        -> impl Iterator<Item=&'b Signature> + Send + Sync
    where
        F: Fn(&Signature) -> Result<()>
    {
        let reference_time = reference_time.unwrap_or_else(crate::now);
        let issuer_handle = issuer.key_handle();
        let issuer_handle = &issuer_handle;

        let mut certifications: Vec<(&Signature, _)> = certifications
            .filter_map(|certification| {
                // Extract the signature's creation time.  Ignore
                // certifications without a creation time: those are
                // malformed.
                certification
                    .signature_creation_time()
                    .map(|ct| (certification, ct))
            })
            .filter(|(certification, _ct)| {
                // Filter out certifications that definitely aren't
                // from `issuer`.
                certification.get_issuers().into_iter().any(|sig_issuer| {
                    sig_issuer.aliases(issuer_handle)
                })
            })
            .map(|(certification, ct)| {
                let hard = if matches!(certification.typ(),
                                       SignatureType::KeyRevocation
                                       | SignatureType::SubkeyRevocation
                                       | SignatureType::CertificationRevocation)
                {
                    certification.reason_for_revocation()
                        .map(|(reason, _text)| {
                            reason.revocation_type() == RevocationType::Hard
                        })
                        // Interpret an unspecified reason as a hard
                        // revocation.
                        .unwrap_or(true)
                } else {
                    false
                };

                (certification, ct, hard)
            })
            .filter(|(_certification, ct, hard)| {
                // Skip certifications created after the reference
                // time, unless they are hard revocations.
                *ct <= reference_time || *hard
            })
            .filter(|(certification, ct, hard)| {
                // Check that the certification is not expired as of
                // the reference time.
                if *hard {
                    // Hard revocations don't expire.
                    true
                } else if let Some(validity)
                    = certification.signature_validity_period()
                {
                    if validity == Duration::new(0, 0) {
                        // "If this is not present or has a value of
                        // zero, it never expires."
                        //
                        // https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time
                        true
                    } else {
                        // "the number of seconds after the signature
                        // creation time that the signature expires"
                        //
                        // Assume validity = 1 second, then:
                        //
                        //  expiry time   reference time    status
                        //  -----------   --------------    ------
                        //              >     ct            live
                        //  ct + 1      =     ct + 1        expired
                        //              <     ct + 2        expired
                        *ct + validity > reference_time
                    }
                } else {
                    true
                }
            })
            .filter(|(_certification, ct, hard)| {
                // Make sure the certification was created after the
                // certificate, unless they are hard revocations.
                self.cert.primary_key().key().creation_time() <= *ct || *hard
            })
            .filter(|(certification, _ct, _hard)| {
                // Make sure the certification conforms to the policy.
                policy
                    .signature(certification,
                               HashAlgoSecurity::CollisionResistance)
                    .is_ok()
            })
            .map(|(certification, ct, _hard)| (certification, ct))
            .collect();

        // Sort the certifications by creation time so that the newest
        // certifications come first.
        certifications.sort_unstable_by(|(_, a), (_, b)| {
            a.cmp(b).reverse()
        });

        // Check that the issuer actually made the signatures, and
        // collect the most recent certifications.
        let mut valid = Vec::new();
        for (certification, ct) in certifications.into_iter() {
            if only_active {
                if let Some((_active, active_ct)) = valid.get(0) {
                    if *active_ct != ct {
                        // This certification is further in the past.
                        // We're done.
                        break;
                    }
                }
            }

            if let Ok(()) = verify_certification(certification) {
                valid.push((certification, ct));
            }
        }

        valid.into_iter()
            .map(|(certification, _creation_time)| certification)
            .collect::<Vec<&Signature>>()
            .into_iter()
    }
}

macro_rules! impl_with_policy {
    ($func:ident, $value:ident $(, $arg:ident: $type:ty )*) => {
        fn $func<T>(&self, policy: &'a dyn Policy, time: T, $($arg: $type, )*)
            -> Result<Self::V>
            where T: Into<Option<time::SystemTime>>,
                  Self: Sized
        {
            let time = time.into().unwrap_or_else(crate::now);

            if $value {
                self.cert.with_policy(policy, time)?;
            }

            let binding_signature = self.binding_signature(policy, time)?;
            let cert = self.cert;
            // We can't do `Cert::with_policy` as that would
            // result in infinite recursion.  But at this point,
            // we know the certificate is valid (unless the caller
            // doesn't care).
            Ok(ValidComponentAmalgamation {
                ca: self.clone(),
                cert: ValidCert {
                    cert,
                    policy,
                    time,
                },
                binding_signature,
            })
        }
    }
}

impl<'a, C> seal::Sealed for ComponentAmalgamation<'a, C> {}
impl<'a, C> ValidateAmalgamation<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy, true);
}

impl<'a, C> ValidateAmalgamationRelaxed<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy_relaxed, valid_cert, valid_cert: bool);
}

impl<'a> UserIDAmalgamation<'a> {
    /// Returns a reference to the User ID.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentAmalgamation::component`].
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
    ///     eprintln!(" - {:?}", ua.userid());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn userid(&self) -> &'a UserID {
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
    ///               ua.revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
                                -> RevocationStatus
    where
        T: Into<Option<time::SystemTime>>,
    {
        let t = t.into();
        self.bundle().revocation_status(policy, t)
    }

    /// Returns the third-party certifications issued by the specified
    /// key, and valid at the specified time.
    ///
    /// This function returns the certifications issued by the
    /// specified key.  Specifically, it returns a certification if:
    ///
    ///   - it is well-formed,
    ///   - it is live with respect to the reference time,
    ///   - it conforms to the policy, and
    ///   - the signature is cryptographically valid.
    ///
    /// This method is implemented on a [`UserIDAmalgamation`] and not
    /// a [`ValidUserIDAmalgamation`], because a third-party
    /// certification does not require the user ID to be self-signed.
    ///
    /// # Examples
    ///
    /// Alice has certified that a certificate belongs to Bob on two
    /// occasions.  Whereas
    /// [`UserIDAmalgamation::valid_certifications_by_key`] returns
    /// both certifications,
    /// [`UserIDAmalgamation::active_certifications_by_key`] only
    /// returns the most recent certification.
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::packet::UserID;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::types::SignatureType;
    ///
    /// const P: &StandardPolicy = &StandardPolicy::new();
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// # let epoch = std::time::SystemTime::now()
    /// #     - std::time::Duration::new(100, 0);
    /// # let t0 = epoch;
    /// #
    /// # let (alice, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid("<alice@example.org>")
    /// #     .generate()
    /// #     .unwrap();
    /// let alice: Cert = // ...
    /// # alice;
    /// #
    /// # let bob_userid = "<bob@example.org>";
    /// # let (bob, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid(bob_userid)
    /// #     .generate()
    /// #     .unwrap();
    /// let bob: Cert = // ...
    /// # bob;
    ///
    /// # // Alice has not certified Bob's User ID.
    /// # let ua = bob.userids().next().expect("have a user id");
    /// # assert_eq!(
    /// #     ua.active_certifications_by_key(
    /// #         P, t0, alice.primary_key().key()).count(),
    /// #     0);
    /// #
    /// # // Have Alice certify Bob's certificate.
    /// # let mut alice_signer = alice
    /// #     .keys()
    /// #     .with_policy(P, None)
    /// #     .for_certification()
    /// #     .next().expect("have a certification-capable key")
    /// #     .key()
    /// #     .clone()
    /// #     .parts_into_secret().expect("have unencrypted key material")
    /// #     .into_keypair().expect("have unencrypted key material");
    /// #
    /// # let mut bob = bob;
    /// # for i in 1..=2usize {
    /// #     let ti = t0 + std::time::Duration::new(i as u64, 0);
    /// #
    /// #     let certification = SignatureBuilder::new(SignatureType::GenericCertification)
    /// #         .set_signature_creation_time(ti)?
    /// #         .sign_userid_binding(
    /// #             &mut alice_signer,
    /// #             bob.primary_key().key(),
    /// #             &UserID::from(bob_userid))?;
    /// #     bob = bob.insert_packets(certification)?.0;
    /// #
    /// #     let ua = bob.userids().next().expect("have a user id");
    /// #     assert_eq!(
    /// #         ua.valid_certifications_by_key(
    /// #             P, ti, alice.primary_key().key()).count(),
    /// #         i);
    /// #
    /// #     assert_eq!(
    /// #         ua.active_certifications_by_key(
    /// #             P, ti, alice.primary_key().key()).count(),
    /// #         1);
    /// # }
    /// let ua = bob.userids().next().expect("have user id");
    ///
    /// let valid_certifications = ua.valid_certifications_by_key(
    ///     P, None, alice.primary_key().key());
    /// // Alice certified Bob's certificate twice.
    /// assert_eq!(valid_certifications.count(), 2);
    ///
    /// let active_certifications = ua.active_certifications_by_key(
    ///     P, None, alice.primary_key().key());
    /// // But only the most recent one is active.
    /// assert_eq!(active_certifications.count(), 1);
    /// # Ok(()) }
    /// ```
    pub fn valid_certifications_by_key<T, PK>(&self,
                                              policy: &'a dyn Policy,
                                              reference_time: T,
                                              issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a packet::Key<packet::key::PublicParts,
                                 packet::key::UnspecifiedRole>>,
    {
        let reference_time = reference_time.into();
        let issuer = issuer.into();

        self.valid_certifications_by_key_(
            policy, reference_time, issuer, false,
            self.certifications(),
            |sig| {
                sig.clone().verify_userid_binding(
                    issuer,
                    self.cert.primary_key().key(),
                    self.userid())
            })
    }

    /// Returns any active third-party certifications issued by the
    /// specified key.
    ///
    /// This function is like
    /// [`UserIDAmalgamation::valid_certifications_by_key`], but it
    /// only returns active certifications.  Active certifications are
    /// the most recent valid certifications with respect to the
    /// reference time.
    ///
    /// Although there is normally only a single active certification,
    /// there can be multiple certifications with the same timestamp.
    /// In this case, all of them are returned.
    ///
    /// Unlike self-signatures, multiple third-party certifications
    /// issued by the same key at the same time can be sensible.  For
    /// instance, Alice may fully trust a CA for user IDs in a
    /// particular domain, and partially trust it for everything else.
    /// This can only be expressed using multiple certifications.
    ///
    /// This method is implemented on a [`UserIDAmalgamation`] and not
    /// a [`ValidUserIDAmalgamation`], because a third-party
    /// certification does not require the user ID to be self-signed.
    ///
    /// # Examples
    ///
    /// See the examples for
    /// [`UserIDAmalgamation::valid_certifications_by_key`].
    pub fn active_certifications_by_key<T, PK>(&self,
                                               policy: &'a dyn Policy,
                                               reference_time: T,
                                               issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a packet::Key<packet::key::PublicParts,
                                 packet::key::UnspecifiedRole>>,
    {
        let reference_time = reference_time.into();
        let issuer = issuer.into();

        self.valid_certifications_by_key_(
            policy, reference_time, issuer, true,
            self.certifications(),
            |sig| {
                sig.clone().verify_userid_binding(
                    issuer,
                    self.cert.primary_key().key(),
                    self.userid())
            })
    }

    /// Returns the third-party revocations issued by the specified
    /// key, and valid at the specified time.
    ///
    /// This function returns the revocations issued by the specified
    /// key.  Specifically, it returns a revocation if:
    ///
    ///   - it is well-formed,
    ///   - it is live with respect to the reference time,
    ///   - it conforms to the policy, and
    ///   - the signature is cryptographically valid.
    ///
    /// This method is implemented on a [`UserIDAmalgamation`] and not
    /// a [`ValidUserIDAmalgamation`], because a third-party
    /// revocation does not require the user ID to be self-signed.
    ///
    /// # Examples
    ///
    /// Alice revokes a user ID on Bob's certificate.
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// # use openpgp::Packet;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::packet::UserID;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::types::ReasonForRevocation;
    /// # use openpgp::types::SignatureType;
    ///
    /// const P: &StandardPolicy = &StandardPolicy::new();
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// # let epoch = std::time::SystemTime::now()
    /// #     - std::time::Duration::new(100, 0);
    /// # let t0 = epoch;
    /// # let t1 = epoch + std::time::Duration::new(1, 0);
    /// #
    /// # let (alice, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid("<alice@example.org>")
    /// #     .generate()
    /// #     .unwrap();
    /// let alice: Cert = // ...
    /// # alice;
    /// #
    /// # let bob_userid = "<bob@example.org>";
    /// # let (bob, _) = CertBuilder::new()
    /// #     .set_creation_time(t0)
    /// #     .add_userid(bob_userid)
    /// #     .generate()
    /// #     .unwrap();
    /// let bob: Cert = // ...
    /// # bob;
    ///
    /// # // Alice has not certified Bob's User ID.
    /// # let ua = bob.userids().next().expect("have a user id");
    /// # assert_eq!(
    /// #     ua.active_certifications_by_key(
    /// #         P, t0, alice.primary_key().key()).count(),
    /// #     0);
    /// #
    /// # // Have Alice certify Bob's certificate.
    /// # let mut alice_signer = alice
    /// #     .keys()
    /// #     .with_policy(P, None)
    /// #     .for_certification()
    /// #     .next().expect("have a certification-capable key")
    /// #     .key()
    /// #     .clone()
    /// #     .parts_into_secret().expect("have unencrypted key material")
    /// #     .into_keypair().expect("have unencrypted key material");
    /// #
    /// # let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
    /// #     .set_signature_creation_time(t1)?
    /// #     .set_reason_for_revocation(
    /// #         ReasonForRevocation::UIDRetired, b"")?
    /// #     .sign_userid_binding(
    /// #         &mut alice_signer,
    /// #         bob.primary_key().key(),
    /// #         &UserID::from(bob_userid))?;
    /// # let bob = bob.insert_packets([
    /// #     Packet::from(UserID::from(bob_userid)),
    /// #     Packet::from(certification),
    /// # ])?.0;
    /// let ua = bob.userids().next().expect("have user id");
    ///
    /// let revs = ua.valid_third_party_revocations_by_key(
    ///     P, None, alice.primary_key().key());
    /// // Alice revoked the User ID.
    /// assert_eq!(revs.count(), 1);
    /// # Ok(()) }
    /// ```
    pub fn valid_third_party_revocations_by_key<T, PK>(&self,
                                                       policy: &'a dyn Policy,
                                                       reference_time: T,
                                                       issuer: PK)
        -> impl Iterator<Item=&Signature> + Send + Sync
    where
        T: Into<Option<time::SystemTime>>,
        PK: Into<&'a packet::Key<packet::key::PublicParts,
                                 packet::key::UnspecifiedRole>>,
    {
        let reference_time = reference_time.into();
        let issuer = issuer.into();

        self.valid_certifications_by_key_(
            policy, reference_time, issuer, false,
            self.other_revocations(),
            |sig| {
                sig.clone().verify_userid_revocation(
                    issuer,
                    self.cert.primary_key().key(),
                    self.userid())
            })
    }

    /// Approves of third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certifications subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    ///
    /// A policy is needed, because the expiration is updated by
    /// updating the current binding signatures.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # fn main() -> openpgp::Result<()> {
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::types::*;
    /// # let policy = &openpgp::policy::StandardPolicy::new();
    /// let (alice, _) = CertBuilder::new()
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut alice_signer =
    ///     alice.primary_key().key().clone().parts_into_secret()?
    ///     .into_keypair()?;
    ///
    /// let (bob, _) = CertBuilder::new()
    ///     .add_userid("bob@example.org")
    ///     .generate()?;
    /// let mut bob_signer =
    ///     bob.primary_key().key().clone().parts_into_secret()?
    ///     .into_keypair()?;
    /// let bob_pristine = bob.clone();
    ///
    /// // Have Alice certify the binding between "bob@example.org" and
    /// // Bob's key.
    /// let alice_certifies_bob
    ///     = bob.userids().next().unwrap().userid().bind(
    ///         &mut alice_signer, &bob,
    ///         SignatureBuilder::new(SignatureType::GenericCertification))?;
    /// let bob = bob.insert_packets(vec![alice_certifies_bob.clone()])?.0;
    ///
    /// // Have Bob approve of that certification.
    /// let bobs_uid = bob.userids().next().unwrap();
    /// let approvals =
    ///     bobs_uid.approve_of_certifications(
    ///         policy,
    ///         None,
    ///         &mut bob_signer,
    ///         bobs_uid.certifications())?;
    /// let bob = bob.insert_packets(approvals)?.0;
    ///
    /// assert_eq!(bob.bad_signatures().count(), 0);
    /// assert_eq!(bob.userids().next().unwrap().certifications().next(),
    ///            Some(&alice_certifies_bob));
    /// # Ok(()) }
    /// ```
    pub fn approve_of_certifications<T, C, S>(&self,
                                              policy: &dyn Policy,
                                              time: T,
                                              primary_signer: &mut dyn Signer,
                                              certifications: C)
        -> Result<Vec<Signature>>
    where T: Into<Option<time::SystemTime>>,
          C: IntoIterator<Item = S>,
          S: Borrow<Signature>,
    {
        let time = time.into();
        let certifications = certifications.into_iter()
            .collect::<Vec<_>>();

        // Check if there is a previous attestation.  If so, we need
        // that to robustly override it.
        let old = self.clone()
            .with_policy(policy, time)
            .ok()
            .and_then(
                |v| v.certification_approval_key_signatures().next().cloned());

        approve_of_certifications_common(self.cert().primary_key().key(),
                                         self.userid(),
                                         old, time, primary_signer,
                                         &certifications)
    }
}

impl<'a> UserAttributeAmalgamation<'a> {
    /// Returns a reference to the User Attribute.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentAmalgamation::component`].
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
    ///     eprintln!(" - {:?}", ua.user_attribute());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn user_attribute(&self) -> &'a UserAttribute {
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
    ///               i, ua.revocation_status(p, None));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn revocation_status<T>(&self, policy: &dyn Policy, t: T)
                                -> RevocationStatus
    where
        T: Into<Option<time::SystemTime>>,
    {
        let t = t.into();
        self.bundle().revocation_status(policy, t)
    }

    /// Approves of third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certifications subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    /// A policy is needed, because the expiration is updated by
    /// updating the current binding signatures.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    ///
    /// # Examples
    ///
    /// See [`UserIDAmalgamation::approve_of_certifications#examples`].
    ///
    ///   [`UserIDAmalgamation::approve_of_certifications#examples`]: UserIDAmalgamation#examples
    // The explicit link works around a bug in rustdoc.
    pub fn approve_of_certifications<T, C, S>(&self,
                                              policy: &dyn Policy,
                                              time: T,
                                              primary_signer: &mut dyn Signer,
                                              certifications: C)
        -> Result<Vec<Signature>>
    where T: Into<Option<time::SystemTime>>,
          C: IntoIterator<Item = S>,
          S: Borrow<Signature>,
    {
        let time = time.into();
        let certifications = certifications.into_iter()
            .collect::<Vec<_>>();

        // Check if there is a previous attestation.  If so, we need
        // that to robustly override it.
        let old = self.clone()
            .with_policy(policy, time)
            .ok()
            .and_then(
                |v| v.certification_approval_key_signatures().next().cloned());

        approve_of_certifications_common(self.cert().primary_key().key(),
                                         self.user_attribute(),
                                         old, time, primary_signer,
                                         &certifications)
    }
}

/// Approves of third-party certifications.
fn approve_of_certifications_common<S>(key: &Key<PublicParts, PrimaryRole>,
                                          component: &dyn Hash,
                                          old_attestation: Option<Signature>,
                                          time: Option<SystemTime>,
                                          primary_signer: &mut dyn Signer,
                                          certifications: &[S])
                                          -> Result<Vec<Signature>>
where
    S: Borrow<Signature>,
{
    use crate::{
        packet::signature::{SignatureBuilder, subpacket::SubpacketArea},
        serialize::MarshalInto,
    };

    // Fix the time.
    let now = time.unwrap_or_else(crate::now);

    // Fix the algorithm.
    let hash_algo = HashAlgorithm::default();
    let digest_size = hash_algo.digest_size()?;

    let mut attestations = Vec::new();
    for certification in certifications {
        let mut h = hash_algo.context()?
            .for_signature(primary_signer.public().version());
        certification.borrow().hash_for_confirmation(&mut h)?;
        attestations.push(h.into_digest()?);
    }

    // Hashes SHOULD be sorted.
    attestations.sort();

    // All attestation signatures we generate for this component
    // should have the same creation time.  Fix it now.  We also like
    // our signatures to be newer than any existing signatures.  Do so
    // by using the old attestation as template.
    let template = if let Some(old) = old_attestation {
        let mut s = SignatureBuilder::from(old)
            .set_reference_time(now)?;
        s.hashed_area_mut().clear();
        s.unhashed_area_mut().clear();
        s
    } else {
        // Backdate the signature a little so that we can immediately
        // override it.
        use crate::packet::signature::SIG_BACKDATE_BY;

        let mut creation_time =
            now - time::Duration::new(SIG_BACKDATE_BY, 0);

        // ... but don't backdate it further than the key's creation
        // time, which would make it invalid.
        let key_creation_time = primary_signer.public().creation_time();
        if creation_time < key_creation_time {
            // ... unless that would make it is later than now.
            creation_time = key_creation_time.min(now);
        }

        let template = SignatureBuilder::new(SignatureType::CertificationApproval)
            .set_signature_creation_time(creation_time)?;
        template

    };

    let template = template
        .set_hash_algo(hash_algo);

    // Compute the available space in the hashed area.  For this,
    // it is important that template.pre_sign has been called.
    let available_space = {
        // But, we do it on a clone, so that `template` is still not
        // initialized.
        let t = template.clone().pre_sign(primary_signer)?;

        SubpacketArea::MAX_SIZE - t.hashed_area().serialized_len()
    };

    // Reserve space for the subpacket header, length and tag.
    const SUBPACKET_HEADER_MAX_LEN: usize = 5 + 1;

    // Compute the chunk size for each signature.
    let digests_per_sig =
        (available_space - SUBPACKET_HEADER_MAX_LEN) / digest_size;

    // Now create the signatures.
    let mut sigs = Vec::new();
    for digests in attestations.chunks(digests_per_sig) {
        // Hash the components.  First, initialize the salt.
        let t = template.clone().pre_sign(primary_signer)?;

        let mut hash = hash_algo.context()?
            .for_signature(primary_signer.public().version());

        if let Some(salt) = t.sb_version.salt() {
            hash.update(salt);
        }
        key.hash(&mut hash)?;
        component.hash(&mut hash)?;

        sigs.push(t
                  .set_approved_certifications(digests)?
                  .sign_hash(primary_signer, hash)?);
    }

    if attestations.is_empty() {
        // The certificate owner can withdraw attestations by issuing
        // an empty attestation key signature.
        assert!(sigs.is_empty());

        // Hash the components.  First, initialize the salt.
        let t = template.clone().pre_sign(primary_signer)?;

        let mut hash = hash_algo.context()?
            .for_signature(primary_signer.public().version());

        if let Some(salt) = t.sb_version.salt() {
            hash.update(salt);
        }
        key.hash(&mut hash)?;
        component.hash(&mut hash)?;

        sigs.push(t
                  .set_approved_certifications(Option::<&[u8]>::None)?
                  .sign_hash(primary_signer, hash.clone())?);
    }

    Ok(sigs)
}

impl<'a> UnknownComponentAmalgamation<'a> {
    /// Returns a reference to the Unknown packet.
    ///
    /// This is just a type-specific alias for
    /// [`ComponentAmalgamation::component`].
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
    /// // Display some information about the Unknown components.
    /// for u in cert.unknowns() {
    ///     eprintln!(" - {:?}", u.unknown());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn unknown(&self) -> &'a Unknown {
        self.component()
    }
}

/// A `ComponentAmalgamation` plus a `Policy` and a reference time.
///
/// A `ValidComponentAmalgamation` combines a
/// [`ComponentAmalgamation`] with a [`Policy`] and a reference time.
/// This allows it to implement the [`ValidAmalgamation`] trait, which
/// provides methods that require a [`Policy`] and a reference time.
/// Although `ComponentAmalgamation` could implement these methods by
/// requiring that the caller explicitly pass them in, embedding them
/// in the `ValidComponentAmalgamation` helps ensure that multipart
/// operations, even those that span multiple functions, use the same
/// `Policy` and reference time.
///
/// A `ValidComponentAmalgamation` is typically obtained by
/// transforming a `ComponentAmalgamation` using
/// [`ValidateAmalgamation::with_policy`].  A
/// [`ComponentAmalgamationIter`] can also be changed to yield
/// `ValidComponentAmalgamation`s.
///
/// A `ValidComponentAmalgamation` is guaranteed to come from a valid
/// certificate, and have a valid and live binding signature at the
/// specified reference time.  Note: this only means that the binding
/// signatures are live; it says nothing about whether the
/// *certificate* is live.  If you care about that, then you need to
/// check it separately.
///
/// # Examples
///
/// Print out information about all non-revoked User IDs.
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::RevocationStatus;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
/// # let (cert, _) = CertBuilder::new()
/// #     .add_userid("Alice")
/// #     .add_signing_subkey()
/// #     .add_transport_encryption_subkey()
/// #     .generate()?;
/// for u in cert.userids() {
///     // Create a `ValidComponentAmalgamation`.  This may fail if
///     // there are no binding signatures that are accepted by the
///     // policy and that are live right now.
///     let u = u.with_policy(p, None)?;
///
///     // Before using the User ID, we still need to check that it is
///     // not revoked; `ComponentAmalgamation::with_policy` ensures
///     // that there is a valid *binding signature*, not that the
///     // `ComponentAmalgamation` is valid.
///     //
///     // Note: `ValidComponentAmalgamation::revocation_status` and
///     // `Preferences::preferred_symmetric_algorithms` use the
///     // embedded policy and timestamp.  Even though we used `None` for
///     // the timestamp (i.e., now), they are guaranteed to use the same
///     // timestamp, because `with_policy` eagerly transforms it into
///     // the current time.
///     //
///     // Note: we only check whether the User ID is not revoked.  If
///     // we were using a key, we'd also want to check that it is alive.
///     // (Keys can expire, but User IDs cannot.)
///     if let RevocationStatus::Revoked(_revs) = u.revocation_status() {
///         // Revoked by the key owner.  (If we care about
///         // designated revokers, then we need to check those
///         // ourselves.)
///     } else {
///         // Print information about the User ID.
///         eprintln!("{}: preferred symmetric algorithms: {:?}",
///                   String::from_utf8_lossy(u.userid().value()),
///                   u.preferred_symmetric_algorithms());
///     }
/// }
/// # Ok(()) }
/// ```
///
/// [`Policy`]: crate::policy::Policy
#[derive(Debug)]
pub struct ValidComponentAmalgamation<'a, C> {
    ca: ComponentAmalgamation<'a, C>,
    cert: ValidCert<'a>,
    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}
assert_send_and_sync!(ValidComponentAmalgamation<'_, C> where C);

impl<'a, C> ValidComponentAmalgamation<'a, C> {
    /// Returns the valid amalgamation's associated certificate.
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// for u in cert.userids() {
    ///     // It's not only an identical `Cert`, it's the same one.
    ///     assert!(std::ptr::eq(u.cert(), &cert));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn cert(&self) -> &'a Cert {
        self.ca.cert()
    }

    /// Returns the valid amalgamation's active binding signature.
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
    /// for ua in cert.with_policy(p, None)?.userids() {
    ///     eprintln!("{:?}", ua.binding_signature());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    /// Returns the valid amalgamation's amalgamation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// // Get a user ID amalgamation.
    /// let ua = cert.userids().next().expect("added one");
    ///
    /// // Validate it, yielding a valid component amalgamation.
    /// let vua = ua.with_policy(p, None)?;
    ///
    /// // And here we get the amalgamation back.
    /// let ua2 = vua.amalgamation();
    /// assert_eq!(&ua, ua2);
    /// # Ok(()) }
    /// ```
    pub fn amalgamation(&self) -> &ComponentAmalgamation<'a, C> {
        &self.ca
    }

    /// Returns this valid amalgamation's bundle.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    /// let p = &openpgp::policy::StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate()?;
    /// cert.with_policy(p, None)?.userids()
    ///     .map(|ua| ua.bundle())
    ///     .collect::<Vec<&ComponentBundle<_>>>();
    /// # Ok(()) }
    /// ```
    pub fn bundle(&self) -> &'a ComponentBundle<C> {
        self.ca.bundle()
    }

    /// Returns this valid amalgamation's component.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(Some("alice@example.org"))
    /// #     .generate()?;
    /// let p = &openpgp::policy::StandardPolicy::new();
    ///
    /// // Display some information about any userid components.
    /// for u in cert.with_policy(p, None)?.userids() {
    ///     eprintln!(" - {:?}", u.component());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn component(&self) -> &'a C {
        self.bundle().component()
    }
}

impl<'a, C> ValidComponentAmalgamation<'a, C>
where
    C: Send + Sync,
{
    /// Returns the valid amalgamation's self-signatures.
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.  This method only returns
    /// signatures that are valid under the current policy.
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
    /// for (i, ka) in cert.with_policy(p, None)?.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} self signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.self_signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_signatures(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync + 'a {
        let policy = self.cert.policy();
        let has = self.ca.bundle().hash_algo_security;

        self.ca.self_signatures()
          .filter(move |sig| policy.signature(sig, has).is_ok())
    }

    /// Returns the component's third-party certifications.
    ///
    /// The signatures are *not* validated.  They are sorted by their
    /// creation time, most recent first.  This method only returns
    /// signatures that are valid under the current policy.
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
    /// for ua in cert.with_policy(p, None)?.userids() {
    ///     eprintln!("User ID {} has {:?} unverified, third-party certifications",
    ///               String::from_utf8_lossy(ua.userid().value()),
    ///               ua.certifications().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn certifications(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync + 'a {
        let policy = self.cert.policy();

        self.ca.certifications()
          .filter(move |sig| policy.signature(sig,
            HashAlgoSecurity::CollisionResistance).is_ok())
    }

    /// Returns the valid amalgamation's revocations that were issued
    /// by the certificate holder.
    ///
    /// The revocations are validated, and they are sorted by their
    /// creation time, most recent first.  This method only returns
    /// signatures that are valid under the current policy.
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
    /// for u in cert.with_policy(p, None)?.userids() {
    ///     eprintln!("User ID {} has {:?} revocation certificates.",
    ///               String::from_utf8_lossy(u.userid().value()),
    ///               u.self_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn self_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync + 'a  {
        let policy = self.cert.policy();
        let has = self.ca.bundle().hash_algo_security;

        self.ca.self_revocations()
          .filter(move |sig| policy.signature(sig, has).is_ok())
    }

    /// Returns the valid amalgamation's revocations that were issued
    /// by other certificates.
    ///
    /// The revocations are *not* validated.  They are sorted by their
    /// creation time, most recent first.  This method only returns
    /// signatures that are valid under the current policy.
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
    /// for u in cert.with_policy(p, None)?.userids() {
    ///     eprintln!("User ID {} has {:?} unverified, third-party revocation certificates.",
    ///               String::from_utf8_lossy(u.userid().value()),
    ///               u.other_revocations().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn other_revocations(&self) -> impl Iterator<Item=&'a Signature> + Send + Sync + 'a {
        let policy = self.cert.policy();

        self.ca.other_revocations()
          .filter(move |sig| policy.signature(sig,
            HashAlgoSecurity::CollisionResistance).is_ok())
    }

    /// Returns all of the valid amalgamation's Certification Approval
    /// Key Signatures.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// The signatures are validated, and they are sorted by their
    /// creation time, most recent first.
    ///
    /// A certificate owner can use Certification Approval Key
    /// Signatures to approve of third party certifications.
    /// Currently, only userid and user attribute certifications can
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
    /// for (i, uid) in cert.with_policy(p, None)?.userids().enumerate() {
    ///     eprintln!("UserID #{} ({:?}) has {:?} certification approval key signatures",
    ///               i, uid.userid().email(),
    ///               uid.approvals().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn approvals(&self)
                     -> impl Iterator<Item = &'a Signature> + Send + Sync + 'a
    {
        let policy = self.cert.policy();
        let has = self.ca.bundle().hash_algo_security;

        self.ca.approvals()
          .filter(move |sig| policy.signature(sig, has).is_ok())
    }

    /// Returns all of the valid amalgamations's signatures.
    ///
    /// Only the self-signatures are validated.  The signatures are
    /// sorted first by type, then by creation time.  The self
    /// revocations come first, then the self signatures,
    /// then any certification approval key signatures,
    /// certifications, and third-party revocations coming last.  This
    /// function may return additional types of signatures that could
    /// be associated to this component.
    ///
    /// This method only returns signatures that are valid under the
    /// current policy.
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
    /// for (i, ka) in cert.with_policy(p, None)?.keys().enumerate() {
    ///     eprintln!("Key #{} ({}) has {:?} signatures",
    ///               i, ka.key().fingerprint(),
    ///               ka.signatures().count());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn signatures(&self)
                      -> impl Iterator<Item = &'a Signature> + Send + Sync + 'a {
        let policy = self.cert.policy();

        self.ca.signatures()
          .filter(move |sig| policy.signature(sig,
            HashAlgoSecurity::CollisionResistance).is_ok())
    }
}

/// A Valid User ID and its associated data.
///
/// A specialized version of [`ValidComponentAmalgamation`].
///
pub type ValidUserIDAmalgamation<'a> = ValidComponentAmalgamation<'a, UserID>;

impl<'a> ValidUserIDAmalgamation<'a> {
    /// Returns a reference to the User ID.
    ///
    /// This is just a type-specific alias for
    /// [`ValidComponentAmalgamation::component`].
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
    ///     eprintln!(" - {:?}", ua.userid());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn userid(&self) -> &'a UserID {
        self.component()
    }

    /// Returns the user ID's approved third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certification subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    /// This method only returns signatures that are valid under the
    /// current policy and are approved by the certificate holder.
    ///
    ///   [Approved Certification subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    pub fn approved_certifications(&self)
        -> impl Iterator<Item=&Signature> + Send + Sync
    {
        let mut hash_algo = None;
        let digests: std::collections::HashSet<_> =
            self.certification_approval_key_signatures()
            .filter_map(|sig| {
                sig.approved_certifications().ok()
                    .map(|digest_iter| (sig, digest_iter))
            })
            .flat_map(|(sig, digest_iter)| {
                hash_algo = Some(sig.hash_algo());
                digest_iter
            })
            .collect();

        self.certifications()
            .filter_map(move |sig| {
                let mut hash = hash_algo.and_then(|a| a.context().ok())?
                    .for_signature(sig.version());
                sig.hash_for_confirmation(&mut hash).ok()?;
                let digest = hash.into_digest().ok()?;
                if digests.contains(&digest[..]) {
                    Some(sig)
                } else {
                    None
                }
            })
    }

    /// Returns set of active certification approval key signatures.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Returns the set of signatures with the newest valid signature
    /// creation time.  Older signatures are not returned.  The sum of
    /// all digests in these signatures are the set of approved
    /// third-party certifications.
    ///
    /// This interface is useful for pruning old certification
    /// approval key signatures when filtering a certificate.
    ///
    /// Note: This is a low-level interface.  Consider using
    /// [`ValidUserIDAmalgamation::approved_certifications`] to
    /// iterate over all approved certifications.
    ///
    ///   [`ValidUserIDAmalgamation::approved_certifications`]: ValidUserIDAmalgamation#method.approved_certifications
    // The explicit link works around a bug in rustdoc.
    pub fn certification_approval_key_signatures(&'a self)
        -> impl Iterator<Item=&'a Signature> + Send + Sync
    {
        let mut first = None;

        // The newest valid signature will be returned first.
        self.ca.approvals()
        // First, filter out any invalid (e.g. too new) signatures.
            .filter(move |sig| self.cert.policy().signature(
                sig,
                HashAlgoSecurity::CollisionResistance).is_ok())
            .take_while(move |sig| {
                let time_hash = (
                    if let Some(t) = sig.signature_creation_time() {
                        (t, sig.hash_algo())
                    } else {
                        // Something is off.  Just stop.
                        return false;
                    },
                    sig.hash_algo());

                if let Some(reference) = first {
                    // Stop looking once we see an older signature or one
                    // with a different hash algo.
                    reference == time_hash
                } else {
                    first = Some(time_hash);
                    true
                }
            })
    }

    /// Approves of third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certifications subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # fn main() -> openpgp::Result<()> {
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::packet::signature::SignatureBuilder;
    /// # use openpgp::types::*;
    /// # let policy = &openpgp::policy::StandardPolicy::new();
    /// let (alice, _) = CertBuilder::new()
    ///     .add_userid("alice@example.org")
    ///     .generate()?;
    /// let mut alice_signer =
    ///     alice.primary_key().key().clone().parts_into_secret()?
    ///     .into_keypair()?;
    ///
    /// let (bob, _) = CertBuilder::new()
    ///     .add_userid("bob@example.org")
    ///     .generate()?;
    /// let mut bob_signer =
    ///     bob.primary_key().key().clone().parts_into_secret()?
    ///     .into_keypair()?;
    /// let bob_pristine = bob.clone();
    ///
    /// // Have Alice certify the binding between "bob@example.org" and
    /// // Bob's key.
    /// let alice_certifies_bob
    ///     = bob.userids().next().unwrap().userid().bind(
    ///         &mut alice_signer, &bob,
    ///         SignatureBuilder::new(SignatureType::GenericCertification))?;
    /// let bob = bob.insert_packets(vec![alice_certifies_bob.clone()])?.0;
    ///
    /// // Have Bob approve of that certification.
    /// let bobs_uid = bob.with_policy(policy, None)?.userids().next().unwrap();
    /// let approvals =
    ///     bobs_uid.approve_of_certifications(
    ///         &mut bob_signer,
    ///         bobs_uid.certifications())?;
    /// let bob = bob.insert_packets(approvals)?.0;
    ///
    /// assert_eq!(bob.bad_signatures().count(), 0);
    /// assert_eq!(bob.userids().next().unwrap().certifications().next(),
    ///            Some(&alice_certifies_bob));
    /// # Ok(()) }
    /// ```
    pub fn approve_of_certifications<C, S>(&self,
                                           primary_signer: &mut dyn Signer,
                                           certifications: C)
                                           -> Result<Vec<Signature>>
    where C: IntoIterator<Item = S>,
          S: Borrow<Signature>,
    {
        self.ca
            .approve_of_certifications(self.policy(),
                                       self.time(),
                                       primary_signer,
                                       certifications)
    }
}

/// A Valid User Attribute and its associated data.
///
/// A specialized version of [`ValidComponentAmalgamation`].
///
pub type ValidUserAttributeAmalgamation<'a>
    = ValidComponentAmalgamation<'a, UserAttribute>;

impl<'a> ValidUserAttributeAmalgamation<'a> {
    /// Returns a reference to the User Attribute.
    ///
    /// This is just a type-specific alias for
    /// [`ValidComponentAmalgamation::component`].
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
    /// for ua in cert.user_attributes() {
    ///     eprintln!(" - {:?}", ua.user_attribute());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn user_attribute(&self) -> &'a UserAttribute {
        self.component()
    }

    /// Returns the user attributes' approved third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certifications subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    /// This method only returns signatures that are valid under the
    /// current policy and are approved by the certificate holder.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    pub fn approved_certifications(&self)
        -> impl Iterator<Item=&Signature> + Send + Sync
    {
        let mut hash_algo = None;
        let digests: std::collections::HashSet<_> =
            self.certification_approval_key_signatures()
            .filter_map(|sig| {
                sig.approved_certifications().ok()
                    .map(|digest_iter| (sig, digest_iter))
            })
            .flat_map(|(sig, digest_iter)| {
                hash_algo = Some(sig.hash_algo());
                digest_iter
            })
            .collect();

        self.certifications()
            .filter_map(move |sig| {
                let mut hash = hash_algo.and_then(|a| a.context().ok())?
                    .for_signature(sig.version());
                sig.hash_for_confirmation(&mut hash).ok()?;
                let digest = hash.into_digest().ok()?;
                if digests.contains(&digest[..]) {
                    Some(sig)
                } else {
                    None
                }
            })
    }

    /// Returns set of active certification approval key signatures.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Returns the set of signatures with the newest valid signature
    /// creation time.  Older signatures are not returned.  The sum of
    /// all digests in these signatures are the set of approved
    /// third-party certifications.
    ///
    /// This interface is useful for pruning old certification
    /// approval key signatures when filtering a certificate.
    ///
    /// Note: This is a low-level interface.  Consider using
    /// [`ValidUserAttributeAmalgamation::approved_certifications`] to
    /// iterate over all approved certifications.
    ///
    ///   [`ValidUserAttributeAmalgamation::approved_certifications`]: ValidUserAttributeAmalgamation#method.approved_certifications
    // The explicit link works around a bug in rustdoc.
    pub fn certification_approval_key_signatures(&'a self)
        -> impl Iterator<Item=&'a Signature> + Send + Sync
    {
        let mut first = None;

        // The newest valid signature will be returned first.
        self.ca.approvals()
        // First, filter out any invalid (e.g. too new) signatures.
            .filter(move |sig| self.cert.policy().signature(
                sig,
                HashAlgoSecurity::CollisionResistance).is_ok())
            .take_while(move |sig| {
                let time_hash = (
                    if let Some(t) = sig.signature_creation_time() {
                        (t, sig.hash_algo())
                    } else {
                        // Something is off.  Just stop.
                        return false;
                    },
                    sig.hash_algo());

                if let Some(reference) = first {
                    // Stop looking once we see an older signature or one
                    // with a different hash algo.
                    reference == time_hash
                } else {
                    first = Some(time_hash);
                    true
                }
            })
    }

    /// Approves of third-party certifications.
    ///
    /// This feature is [experimental](crate#experimental-features).
    ///
    /// Allows the certificate owner to approve of third party
    /// certifications. See [Approved Certifications subpacket] for
    /// details.  This can be used to address certificate flooding
    /// concerns.
    ///
    ///   [Approved Certifications subpacket]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#approved-certifications-subpacket
    ///
    /// # Examples
    ///
    /// See [`ValidUserIDAmalgamation::approve_of_certifications#examples`].
    ///
    ///   [`ValidUserIDAmalgamation::approve_of_certifications#examples`]: ValidUserIDAmalgamation#examples
    // The explicit link works around a bug in rustdoc.
    pub fn approve_of_certifications<C, S>(&self,
                                           primary_signer: &mut dyn Signer,
                                           certifications: C)
                                           -> Result<Vec<Signature>>
    where C: IntoIterator<Item = S>,
          S: Borrow<Signature>,
    {
        self.ca
            .approve_of_certifications(self.policy(),
                                       self.time(),
                                       primary_signer,
                                       certifications)
    }
}

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ValidComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            binding_signature: self.binding_signature,
        }
    }
}

impl<'a, C: 'a> From<ValidComponentAmalgamation<'a, C>>
    for ComponentAmalgamation<'a, C>
{
    fn from(vca: ValidComponentAmalgamation<'a, C>) -> Self {
        assert!(std::ptr::eq(vca.ca.cert(), vca.cert.cert()));
        vca.ca
    }
}

impl<'a, C> ValidComponentAmalgamation<'a, C>
    where C: Ord + Send + Sync
{
    /// Returns the amalgamated primary component at time `time`
    ///
    /// If `time` is None, then the current time is used.
    /// `ValidComponentAmalgamationIter` for the definition of a valid component.
    ///
    /// The primary component is determined by taking the components that
    /// are alive at time `t`, and sorting them as follows:
    ///
    ///   - non-revoked first
    ///   - primary first
    ///   - signature creation first
    ///
    /// If there is more than one, then one is selected in a
    /// deterministic, but undefined manner.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only exposed to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    pub(super) fn primary(cert: &'a Cert,
                          iter: std::slice::Iter<'a, ComponentBundle<C>>,
                          policy: &'a dyn Policy, t: SystemTime,
                          valid_cert: bool)
        -> Result<ValidComponentAmalgamation<'a, C>>
    {
        use std::cmp::Ordering;

        let mut error = None;

        // Filter out components that are not alive at time `t`.
        //
        // While we have the binding signature, extract a few
        // properties to avoid recomputing the same thing multiple
        // times.
        iter.filter_map(|c| {
            // No binding signature at time `t` => not alive.
            let sig = match c.binding_signature(policy, t) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    error = Some(e);
                    None
                },
            }?;

            let revoked = c.revocation_status_intern(
                policy, Some(t), false, Some(sig));
            let primary = sig.primary_userid().unwrap_or(false);
            let signature_creation_time = match sig.signature_creation_time() {
                Some(time) => Some(time),
                None => {
                    error = Some(Error::MalformedPacket(
                        "Signature has no creation time".into()).into());
                    None
                },
            }?;

            Some(((c, sig, revoked), primary, signature_creation_time))
        })
            .max_by(|(a, a_primary, a_signature_creation_time),
                    (b, b_primary, b_signature_creation_time)| {
                match (matches!(&a.2, RevocationStatus::Revoked(_)),
                       matches!(&b.2, RevocationStatus::Revoked(_))) {
                    (true, false) => return Ordering::Less,
                    (false, true) => return Ordering::Greater,
                    _ => (),
                }
                match (a_primary, b_primary) {
                    (true, false) => return Ordering::Greater,
                    (false, true) => return Ordering::Less,
                    _ => (),
                }
                match a_signature_creation_time.cmp(b_signature_creation_time)
                {
                    Ordering::Less => return Ordering::Less,
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Equal => (),
                }

                // Fallback to a lexographical comparison.  Prefer
                // the "smaller" one.
                match a.0.component().cmp(b.0.component()) {
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less,
                    Ordering::Equal =>
                        panic!("non-canonicalized Cert (duplicate components)"),
                }
            })
            .ok_or_else(|| {
                error.map(|e| e.context(format!(
                    "No binding signature at time {}", crate::fmt::time(&t))))
                    .unwrap_or_else(|| Error::NoBindingSignature(t).into())
            })
            .and_then(|c| ComponentAmalgamation::new(cert, (c.0).0)
                      .with_policy_relaxed(policy, t, valid_cert))
    }
}

impl<'a, C> seal::Sealed for ValidComponentAmalgamation<'a, C> {}
impl<'a, C> ValidateAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C> {
    type V = Self;

    fn with_policy<T>(&self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized,
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));

        let time = time.into().unwrap_or_else(crate::now);
        self.ca.with_policy(policy, time)
    }
}

impl<'a, C> ValidAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C>
where
    C: Send + Sync,
{
    fn valid_cert(&self) -> &ValidCert<'a> {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        &self.cert
    }

    fn time(&self) -> SystemTime {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.time
    }

    fn policy(&self) -> &'a dyn Policy
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.policy
    }

    fn binding_signature(&self) -> &'a Signature {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.binding_signature
    }

    fn revocation_status(&self) -> RevocationStatus<'a> {
        self.bundle().revocation_status_intern(
            self.policy(), Some(self.cert.time), false,
            Some(self.binding_signature))
    }

    fn revocation_keys(&self)
                       -> Box<dyn Iterator<Item = &'a RevocationKey> + 'a>
    {
        let mut keys = std::collections::HashSet::new();

        let policy = self.policy();
        let pk_sec = self.cert().primary_key().key().hash_algo_security();

        // All valid self-signatures.
        let sec = self.bundle().hash_algo_security;
        self.self_signatures()
            .filter(move |sig| {
                policy.signature(sig, sec).is_ok()
            })
        // All direct-key signatures.
            .chain(self.cert().primary_key()
                   .self_signatures()
                   .filter(|sig| {
                       policy.signature(sig, pk_sec).is_ok()
                   }))
            .flat_map(|sig| sig.revocation_keys())
            .for_each(|rk| { keys.insert(rk); });

        Box::new(keys.into_iter())
    }
}

impl<'a, C> ValidBindingSignature<'a, C> for ValidComponentAmalgamation<'a, C>
where
    C: Send + Sync,
{}

impl<'a, C> crate::cert::Preferences<'a>
    for ValidComponentAmalgamation<'a, C>
where
    C: Send + Sync,
{
    fn preferred_symmetric_algorithms(&self)
                                      -> Option<&'a [SymmetricAlgorithm]> {
        self.map(|s| s.preferred_symmetric_algorithms())
    }

    fn preferred_hash_algorithms(&self) -> Option<&'a [HashAlgorithm]> {
        self.map(|s| s.preferred_hash_algorithms())
    }

    fn preferred_compression_algorithms(&self)
                                        -> Option<&'a [CompressionAlgorithm]> {
        self.map(|s| s.preferred_compression_algorithms())
    }

    fn preferred_aead_ciphersuites(
        &self)
        -> Option<&'a [(SymmetricAlgorithm, AEADAlgorithm)]>
    {
        self.map(|s| s.preferred_aead_ciphersuites())
    }

    fn key_server_preferences(&self) -> Option<KeyServerPreferences> {
        self.map(|s| s.key_server_preferences())
    }

    fn preferred_key_server(&self) -> Option<&'a [u8]> {
        self.map(|s| s.preferred_key_server())
    }

    fn policy_uri(&self) -> Option<&'a [u8]> {
        self.map(|s| s.policy_uri())
    }

    fn features(&self) -> Option<Features> {
        self.map(|s| s.features())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::time::UNIX_EPOCH;

    use crate::policy::StandardPolicy as P;
    use crate::Packet;
    use crate::packet::signature::SignatureBuilder;
    use crate::packet::UserID;
    use crate::types::SignatureType;
    use crate::types::ReasonForRevocation;

    // derive(Clone) doesn't work with generic parameters that don't
    // implement clone.  Make sure that our custom implementations
    // work.
    //
    // See: https://github.com/rust-lang/rust/issues/26925
    #[test]
    fn clone() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let userid : UserIDAmalgamation = cert.userids().next().unwrap();
        assert_eq!(userid.userid(), userid.clone().userid());

        let userid : ValidUserIDAmalgamation
            = userid.with_policy(p, None).unwrap();
        let c = userid.clone();
        assert_eq!(userid.userid(), c.userid());
        assert_eq!(userid.time(), c.time());
    }

    #[test]
    fn map() {
        // The reference returned by `ComponentAmalgamation::userid`
        // and `ComponentAmalgamation::user_attribute` is bound by the
        // reference to the `Component` in the
        // `ComponentAmalgamation`, not the `ComponentAmalgamation`
        // itself.
        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let _ = cert.userids().map(|ua| ua.userid())
            .collect::<Vec<_>>();

        let _ = cert.user_attributes().map(|ua| ua.user_attribute())
            .collect::<Vec<_>>();
    }

    #[test]
    fn component_amalgamation_certifications_by_key() -> Result<()> {
        // Alice and Bob certify Carol's certificate.  We then check
        // that certifications_by_key returns them.
        let (alice, _) = CertBuilder::new()
            .add_userid("<alice@example.example>")
            .generate()
            .unwrap();

        let (bob, _) = CertBuilder::new()
            .add_userid("<bob@example.example>")
            .generate()
            .unwrap();

        let carol_userid = "<carol@example.example>";
        let (carol, _) = CertBuilder::new()
            .add_userid(carol_userid)
            .generate()
            .unwrap();

        let ua = alice.userids().next().expect("have a user id");
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 0);

        // Alice has not certified Bob's User ID.
        let ua = bob.userids().next().expect("have a user id");
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 0);

        // Alice has not certified Carol's User ID.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 0);


        // Have Alice certify Carol's certificate.
        let mut alice_signer = alice.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification)?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 1);
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 1);
        assert_eq!(ua.certifications_by_key(&[ bob.key_handle() ]).count(), 0);


        // Have Bob certify Carol's certificate.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification)?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 2);
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 1);
        assert_eq!(ua.certifications_by_key(&[ bob.key_handle() ]).count(), 1);

        // Again.
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification)?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 3);
        assert_eq!(ua.certifications_by_key(&[ alice.key_handle() ]).count(), 1);
        assert_eq!(ua.certifications_by_key(&[ bob.key_handle() ]).count(), 2);

        Ok(())
    }

    #[test]
    fn user_id_amalgamation_certifications_by_key() -> Result<()> {
        // Alice and Bob certify Carol's certificate.  We then check
        // that valid_certifications_by_key and
        // active_certifications_by_key return them.
        let p = &crate::policy::StandardPolicy::new();

        // $ date -u -d '2024-01-02 13:00' +%s
        let t0 = UNIX_EPOCH + Duration::new(1704200400, 0);
        // $ date -u -d '2024-01-02 14:00' +%s
        let t1 = UNIX_EPOCH + Duration::new(1704204000, 0);
        // $ date -u -d '2024-01-02 15:00' +%s
        let t2 = UNIX_EPOCH + Duration::new(1704207600, 0);

        let (alice, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<alice@example.example>")
            .generate()
            .unwrap();
        let alice_primary = alice.primary_key().key();

        let (bob, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<bob@example.example>")
            .generate()
            .unwrap();
        let bob_primary = bob.primary_key().key();

        let carol_userid = "<carol@example.example>";
        let (carol, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid(carol_userid)
            .generate()
            .unwrap();

        let ua = alice.userids().next().expect("have a user id");
        assert_eq!(ua.valid_certifications_by_key(p, None, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, None, alice_primary).count(), 0);

        // Alice has not certified Bob's User ID.
        let ua = bob.userids().next().expect("have a user id");
        assert_eq!(ua.valid_certifications_by_key(p, None, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, None, alice_primary).count(), 0);

        // Alice has not certified Carol's User ID.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.valid_certifications_by_key(p, None, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, None, alice_primary).count(), 0);


        // Have Alice certify Carol's certificate at t1.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t1)?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 1);

        assert_eq!(ua.valid_certifications_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, alice_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, alice_primary).count(), 1);
        assert_eq!(ua.active_certifications_by_key(p, t1, alice_primary).count(), 1);

        assert_eq!(ua.valid_certifications_by_key(p, t1, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t1, bob_primary).count(), 0);


        // Have Alice certify Carol's certificate at t1 (again).
        // Since both certifications were created at t1, they should
        // both be returned.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t1)?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 2);
        assert_eq!(ua.valid_certifications_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, alice_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t1, alice_primary).count(), 2);

        assert_eq!(ua.valid_certifications_by_key(p, t2, alice_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t2, alice_primary).count(), 2);

        assert_eq!(ua.valid_certifications_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, bob_primary).count(), 0);


        // Have Alice certify Carol's certificate at t2.  Now we only
        // have one active certification.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t2)?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 3);
        assert_eq!(ua.valid_certifications_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, alice_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t1, alice_primary).count(), 2);

        assert_eq!(ua.valid_certifications_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.active_certifications_by_key(p, t2, alice_primary).count(), 1);

        assert_eq!(ua.valid_certifications_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, bob_primary).count(), 0);


        // Have Bob certify Carol's certificate at t1 and have it expire at t2.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t1)?
            .set_signature_validity_period(t2.duration_since(t1)?)?
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 4);

        assert_eq!(ua.valid_certifications_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, alice_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t1, alice_primary).count(), 2);

        assert_eq!(ua.valid_certifications_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.active_certifications_by_key(p, t2, alice_primary).count(), 1);

        assert_eq!(ua.valid_certifications_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, bob_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, bob_primary).count(), 1);
        assert_eq!(ua.active_certifications_by_key(p, t1, bob_primary).count(), 1);

        // It expired.
        assert_eq!(ua.valid_certifications_by_key(p, t2, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t2, bob_primary).count(), 0);


        // Have Bob certify Carol's certificate at t1 again.  This
        // time don't have it expire.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t1)?
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &UserID::from(carol_userid))?;
        let carol = carol.insert_packets(certification.clone())?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.certifications().count(), 5);
        assert_eq!(ua.valid_certifications_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, alice_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t1, alice_primary).count(), 2);

        assert_eq!(ua.valid_certifications_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.active_certifications_by_key(p, t2, alice_primary).count(), 1);

        assert_eq!(ua.valid_certifications_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.active_certifications_by_key(p, t0, bob_primary).count(), 0);

        assert_eq!(ua.valid_certifications_by_key(p, t1, bob_primary).count(), 2);
        assert_eq!(ua.active_certifications_by_key(p, t1, bob_primary).count(), 2);

        // One of the certifications expired.
        assert_eq!(ua.valid_certifications_by_key(p, t2, bob_primary).count(), 1);
        assert_eq!(ua.active_certifications_by_key(p, t2, bob_primary).count(), 1);

        Ok(())
    }

    #[test]
    fn user_id_amalgamation_third_party_revocations_by_key() -> Result<()> {
        // Alice and Bob revoke Carol's User ID.  We then check
        // that valid_third_party_revocations_by_key returns them.
        let p = &crate::policy::StandardPolicy::new();

        // $ date -u -d '2024-01-02 13:00' +%s
        let t0 = UNIX_EPOCH + Duration::new(1704200400, 0);
        // $ date -u -d '2024-01-02 14:00' +%s
        let t1 = UNIX_EPOCH + Duration::new(1704204000, 0);
        // $ date -u -d '2024-01-02 15:00' +%s
        let t2 = UNIX_EPOCH + Duration::new(1704207600, 0);

        let (alice, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<alice@example.example>")
            .generate()
            .unwrap();
        let alice_primary = alice.primary_key().key();

        let (bob, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid("<bob@example.example>")
            .generate()
            .unwrap();
        let bob_primary = bob.primary_key().key();

        let carol_userid = "<carol@example.example>";
        let (carol, _) = CertBuilder::new()
            .set_creation_time(t0)
            .add_userid(carol_userid)
            .generate()
            .unwrap();
        let carol_userid = UserID::from(carol_userid);

        let ua = alice.userids().next().expect("have a user id");
        assert_eq!(ua.valid_third_party_revocations_by_key(p, None, alice_primary).count(), 0);

        // Alice has not certified Bob's User ID.
        let ua = bob.userids().next().expect("have a user id");
        assert_eq!(ua.valid_third_party_revocations_by_key(p, None, alice_primary).count(), 0);

        // Alice has not certified Carol's User ID.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.valid_third_party_revocations_by_key(p, None, alice_primary).count(), 0);


        // Have Alice revoke Carol's certificate at t1.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(
                ReasonForRevocation::UIDRetired, b"")?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &carol_userid)?;
        let carol = carol.insert_packets([
            Packet::from(carol_userid.clone()),
            Packet::from(certification.clone()),
        ])?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.other_revocations().count(), 1);

        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, alice_primary).count(), 1);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, bob_primary).count(), 0);


        // Have Alice certify Carol's certificate at t1 (again).
        // Since both certifications were created at t1, they should
        // both be returned.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &carol_userid)?;
        let carol = carol.insert_packets([
            Packet::from(carol_userid.clone()),
            Packet::from(certification.clone()),
        ])?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.other_revocations().count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, alice_primary).count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, bob_primary).count(), 0);


        // Have Alice certify Carol's certificate at t2.  Now we only
        // have one active certification.
        let mut alice_signer = alice_primary
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(t2)?
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")?
            .sign_userid_binding(
                &mut alice_signer,
                carol.primary_key().key(),
                &carol_userid)?;
        let carol = carol.insert_packets([
            Packet::from(carol_userid.clone()),
            Packet::from(certification.clone()),
        ])?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.other_revocations().count(), 3);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, bob_primary).count(), 0);


        // Have Bob certify Carol's certificate at t1 and have it expire at t2.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(t1)?
            .set_signature_validity_period(t2.duration_since(t1)?)?
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")?
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &carol_userid)?;
        let carol = carol.insert_packets([
            Packet::from(carol_userid.clone()),
            Packet::from(certification.clone()),
        ])?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.other_revocations().count(), 4);

        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, bob_primary).count(), 1);
        // It expired.
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, bob_primary).count(), 0);


        // Have Bob certify Carol's certificate at t1 again.  This
        // time don't have it expire.
        let mut bob_signer = bob.primary_key()
            .key()
            .clone()
            .parts_into_secret().expect("have unencrypted key material")
            .into_keypair().expect("have unencrypted key material");
        let certification = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(t1)?
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")?
            .sign_userid_binding(
                &mut bob_signer,
                carol.primary_key().key(),
                &carol_userid)?;
        let carol = carol.insert_packets([
            Packet::from(carol_userid.clone()),
            Packet::from(certification.clone()),
        ])?.0;

        // Check that it is returned.
        let ua = carol.userids().next().expect("have a user id");
        assert_eq!(ua.other_revocations().count(), 5);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, alice_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, alice_primary).count(), 2);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, alice_primary).count(), 3);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t0, bob_primary).count(), 0);
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t1, bob_primary).count(), 2);
        // One of the certifications expired.
        assert_eq!(ua.valid_third_party_revocations_by_key(p, t2, bob_primary).count(), 1);

        Ok(())
    }
}
