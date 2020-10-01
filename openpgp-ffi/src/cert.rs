//! OpenPGP Certificates.
//!
//! Wraps [`sequoia-openpgp::Cert`] and [related functionality].
//!
//! [`sequoia-openpgp::Cert`]: ../../../sequoia_openpgp/cert/struct.Cert.html
//! [related functionality]: ../../../sequoia_openpgp/cert/index.html

use std::convert::TryFrom;
use std::ptr;
use std::slice;
use libc::{c_char, c_int, size_t, time_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    crypto,
    crypto::Password,
    types::ReasonForRevocation,
    parse::{
        PacketParserResult,
        Parse,
    },
    cert::prelude::*,
};

use crate::error::Status;
use super::fingerprint::Fingerprint;
use super::packet::key::Key;
use super::packet::Packet;
use super::packet::signature::Signature;
use super::packet_pile::PacketPile;
use super::tsk::TSK;
use super::revocation_status::RevocationStatus;
use super::policy::Policy;
use super::amalgamation::{UserIDAmalgamation, ValidUserIDAmalgamation};
use super::key_amalgamation::{KeyAmalgamation, ValidKeyAmalgamation};

use crate::Maybe;
use crate::RefRaw;
use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::maybe_time;

/// An OpenPGP Certificate.
///
/// A Certificate (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// Certs are always canonicalized in the sense that only elements
/// (user id, user attribute, subkey) with at least one valid
/// self-signature are preserved.  Also, invalid self-signatures are
/// dropped.  The self-signatures are sorted so that the newest
/// self-signature comes first.  User IDs are sorted so that the first
/// `UserID` is the primary User ID.  Third-party certifications are
/// *not* validated, as the keys are not available; they are simply
/// passed through as is.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
#[crate::ffi_wrapper_type(
    prefix = "pgp_", name = "cert",
    derive = "Clone, Debug, Display, PartialEq, Parse, Serialize")]
pub struct Cert(openpgp::Cert);

/// Returns the first Cert found in `m`.
///
/// Consumes `m`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_from_packet_pile(errp: Option<&mut *mut crate::error::Error>,
                            m: *mut PacketPile)
                            -> Maybe<Cert> {
    openpgp::Cert::try_from(m.move_from_raw()).move_into_raw(errp)
}

/// Returns the first Cert found in the packet parser.
///
/// Consumes the packet parser result.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_from_packet_parser(errp: Option<&mut *mut crate::error::Error>,
                              ppr: *mut PacketParserResult)
                              -> Maybe<Cert>
{
    let ppr = ffi_param_move!(ppr);

    openpgp::Cert::try_from(*ppr).move_into_raw(errp)
}

/// Merges `other` into `cert`.
///
/// If `other` is a different key, then nothing is merged into
/// `cert`, but `cert` is still canonicalized.
///
/// Consumes `cert` and `other`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_merge(errp: Option<&mut *mut crate::error::Error>,
                 cert: *mut Cert,
                 other: *mut Cert)
                 -> Maybe<Cert> {
    let cert = cert.move_from_raw();
    let other = other.move_from_raw();
    cert.merge(other).move_into_raw(errp)
}

/// Adds packets to the Cert.
///
/// This recanonicalizes the Cert.  If the packets are invalid, they
/// are dropped.
///
/// Consumes `cert` and the packets in `packets`.  The buffer, however,
/// must be managed by the caller.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_insert_packets(errp: Option<&mut *mut crate::error::Error>,
                         cert: *mut Cert,
                         packets: *mut *mut Packet,
                         packets_len: size_t)
                         -> Maybe<Cert> {
    let cert = cert.move_from_raw();
    let packets = unsafe {
        slice::from_raw_parts_mut(packets, packets_len)
    };
    let packets =
        packets.iter_mut().map(|&mut p| p.move_from_raw());
    cert.insert_packets(packets).move_into_raw(errp)
}

/// Returns the fingerprint.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_fingerprint(cert: *const Cert)
                       -> *mut Fingerprint {
    let cert = cert.ref_raw();
    cert.fingerprint().move_into_raw()
}

/// Derives a [`TSK`] object from this key.
///
/// This object writes out secret keys during serialization.
///
/// [`TSK`]: ../tsk/struct.TSK.html
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_as_tsk(cert: *const Cert) -> *mut TSK<'static> {
    cert.ref_raw().as_tsk().move_into_raw()
}

/// Returns a reference to the Cert's primary key.
///
/// The cert still owns the key.  The caller must not modify the key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_primary_key(cert: *const Cert) -> *const Key {
    let key = cert.ref_raw().primary_key().key()
        .parts_as_unspecified().role_as_unspecified();
    key.move_into_raw()
}

/// Returns the Cert's revocation status as of a given time.
///
/// Note: this only returns whether the Cert has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
///
/// If `when` is 0, then returns the Cert's revocation status as of the
/// time of the call.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_revocation_status(cert: *const Cert, policy: *const Policy, when: time_t)
    -> *mut RevocationStatus<'static>
{
    let policy = &**policy.ref_raw();
    cert.ref_raw()
        .revocation_status(policy, maybe_time(when))
        .move_into_raw()
}

fn int_to_reason_for_revocation(code: c_int) -> ReasonForRevocation {
    match code {
        0 => ReasonForRevocation::KeyCompromised,
        1 => ReasonForRevocation::Unspecified,
        2 => ReasonForRevocation::KeySuperseded,
        3 => ReasonForRevocation::KeyCompromised,
        4 => ReasonForRevocation::KeyRetired,
        5 => ReasonForRevocation::UIDRetired,
        _ => panic!("Bad reason for revocation: {}", code),
    }
}


/// Returns a new revocation certificate for the Cert.
///
/// This function does *not* consume `cert`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_cert_builder_t builder;
/// pgp_cert_t cert;
/// pgp_signature_t revocation;
/// pgp_key_t primary_key;
/// pgp_key_pair_t primary_keypair;
/// pgp_signer_t primary_signer;
/// pgp_policy_t policy = pgp_standard_policy ();
///
/// builder = pgp_cert_builder_new ();
/// pgp_cert_builder_set_cipher_suite (&builder, PGP_CERT_CIPHER_SUITE_CV25519);
/// pgp_cert_builder_generate (NULL, builder, &cert, &revocation);
/// assert (cert);
/// assert (revocation);
/// pgp_signature_free (revocation);    /* Free the generated one.  */
///
/// primary_key = pgp_cert_primary_key (cert);
/// primary_keypair = pgp_key_into_key_pair (NULL, pgp_key_clone (primary_key));
/// pgp_key_free (primary_key);
/// assert (primary_keypair);
/// primary_signer = pgp_key_pair_as_signer (primary_keypair);
/// revocation = pgp_cert_revoke (NULL, cert, primary_signer,
///                              PGP_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                              "It was the maid :/");
/// assert (revocation);
/// pgp_signer_free (primary_signer);
/// pgp_key_pair_free (primary_keypair);
///
/// pgp_packet_t packet = pgp_signature_into_packet (revocation);
/// cert = pgp_cert_insert_packets (NULL, cert, &packet, 1);
/// assert (cert);
///
/// pgp_revocation_status_t rs = pgp_cert_revocation_status (cert, policy, 0);
/// assert (pgp_revocation_status_variant (rs) == PGP_REVOCATION_STATUS_REVOKED);
/// pgp_revocation_status_free (rs);
///
/// pgp_cert_free (cert);
/// pgp_policy_free (policy);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_revoke(errp: Option<&mut *mut crate::error::Error>,
                  cert: *const Cert,
                  primary_signer: *mut Box<dyn crypto::Signer>,
                  code: c_int,
                  reason: Option<&c_char>)
                  -> Maybe<Signature>
{
    ffi_make_fry_from_errp!(errp);
    let cert = cert.ref_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        ffi_param_cstr!(reason as *const c_char).to_bytes()
    } else {
        b""
    };

    let builder = CertRevocationBuilder::new();
    let builder = ffi_try_or!(builder.set_reason_for_revocation(code, reason), None);
    let sig = builder.build(signer.as_mut(), cert, None);
    sig.move_into_raw(errp)
}

/// Returns a new revocation certificate for the Cert.
///
/// This function consumes `cert` and returns a new `Cert`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_revoke_in_place(errp: Option<&mut *mut crate::error::Error>,
                            cert: *mut Cert,
                            primary_signer: *mut Box<dyn crypto::Signer>,
                            code: c_int,
                            reason: Option<&c_char>)
                  -> Maybe<Cert>
{
    ffi_make_fry_from_errp!(errp);
    let cert = cert.move_from_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        ffi_param_cstr!(reason as *const c_char).to_bytes()
    } else {
        b""
    };

    let builder = CertRevocationBuilder::new();
    let builder = ffi_try_or!(builder.set_reason_for_revocation(code, reason), None);
    let sig = builder.build(signer.as_mut(), &cert, None);
    cert.insert_packets(sig).move_into_raw(errp)
}

/// Returns whether the Cert is alive at the specified time.
///
/// If `when` is 0, then the current time is used.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_alive(errp: Option<&mut *mut crate::error::Error>,
                  cert: *const Cert, policy: *const Policy, when: time_t)
    -> Status
{
    let policy = &**policy.ref_raw();
    ffi_make_fry_from_errp!(errp);
    let valid_cert = ffi_try_or_status!(
        cert.ref_raw().with_policy(policy, maybe_time(when)));
    ffi_try_status!(valid_cert.alive())
}

/// Sets the key to expire at the given time.
///
/// This function consumes `cert` and returns a new `Cert`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_set_expiration_time(errp: Option<&mut *mut crate::error::Error>,
                       cert: *mut Cert,
                       policy: *const Policy,
                       primary_signer: *mut Box<dyn crypto::Signer>,
                       expiry: time_t)
    -> Maybe<Cert>
{
    ffi_make_fry_from_errp!(errp);
    let policy = &**policy.ref_raw();
    let cert = cert.move_from_raw();
    let signer = ffi_param_ref_mut!(primary_signer);

    let sigs = ffi_try_or!(cert.set_expiration_time(policy, None, signer.as_mut(),
                                                    maybe_time(expiry)), None);
    cert.insert_packets(sigs).move_into_raw(errp)
}

/// Returns whether the Cert includes any secret key material.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_is_tsk(cert: *const Cert)
                  -> c_int {
    let cert = cert.ref_raw();
    cert.is_tsk() as c_int
}

/// Returns an iterator over the Cert's user id bindings.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_primary_user_id(cert: *const Cert, policy: *const Policy,
                            when: time_t)
                           -> *mut c_char
{
    let cert = cert.ref_raw();
    let policy = &**policy.ref_raw();
    if let Ok(binding) = cert.with_policy(policy, maybe_time(when))
        .and_then(|valid_cert| valid_cert.primary_userid())
    {
        ffi_return_string!(binding.userid().value())
    } else {
        ptr::null_mut()
    }
}

/* UserIDIter */

/// Wraps a UserIDIter for export via the FFI.
pub struct UserIDIterWrapper<'a> {
    pub(crate) // For serialize.rs.
    iter: Option<ComponentAmalgamationIter<'a, openpgp::packet::UserID>>,
    // Whether next has been called.
    next_called: bool,
}

/// Returns an iterator over the Cert's user ids.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_user_id_iter(cert: *const Cert)
    -> *mut UserIDIterWrapper<'static>
{
    let cert = cert.ref_raw();
    box_raw!(UserIDIterWrapper {
        iter: Some(cert.userids()),
        next_called: false,
    })
}

/// Changes the iterator to only return keys that are valid at time
/// `t`.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_user_id_iter_policy<'a>(
    iter_wrapper: *mut UserIDIterWrapper<'a>,
    policy: *const Policy,
    when: time_t)
    -> *mut ValidUserIDIterWrapper<'static>
{
    let policy = policy.ref_raw();
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change UserIDIter filter after iterating.");
    }

    use std::mem::transmute;
    box_raw!(ValidUserIDIterWrapper {
        iter: Some(unsafe {
            transmute(iter_wrapper.iter.take().unwrap()
                      .with_policy(&**policy, maybe_time(when)))
        }),
        next_called: false,
    })
}


/// Frees a pgp_user_id_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_user_id_iter_free(
    iter: Option<&mut UserIDIterWrapper>)
{
    ffi_free!(iter)
}

/// Returns the next `UserIDAmalgamation`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_user_id_iter_next<'a>(
    iter_wrapper: *mut UserIDIterWrapper<'a>)
    -> Maybe<UserIDAmalgamation<'a>>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.next_called = true;

    if let Some(ua) = iter_wrapper.iter.as_mut().unwrap().next() {
        Some(ua).move_into_raw()
    } else {
        None
    }
}

/// Wraps a ValidKeyAmalgamationIter for export via the FFI.
pub struct ValidUserIDIterWrapper<'a> {
    pub(crate) // For serialize.rs.
    iter: Option<ValidComponentAmalgamationIter<'a, openpgp::packet::UserID>>,
    // Whether next has been called.
    next_called: bool,
}

/// Returns an iterator over the Cert's user id bundles.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_user_id_iter(cert: *const Cert,
                                          policy: *const Policy, when: time_t)
    -> *mut ValidUserIDIterWrapper<'static>
{
    let cert = cert.ref_raw();
    let iter = box_raw!(UserIDIterWrapper {
        iter: Some(cert.userids()),
        next_called: false,
    });

    pgp_cert_user_id_iter_policy(iter, policy, when)
}

/// Frees a pgp_user_id_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_user_id_iter_free(
    iter: Option<&mut ValidUserIDIterWrapper>)
{
    ffi_free!(iter)
}

/// Returns the next `UserIDAmalgamation`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_user_id_iter_next<'a>(
    iter_wrapper: *mut ValidUserIDIterWrapper<'a>)
    -> Maybe<ValidUserIDAmalgamation<'a>>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.next_called = true;

    if let Some(ua) = iter_wrapper.iter.as_mut().unwrap().next() {
        Some(ua).move_into_raw()
    } else {
        None
    }
}


/* cert::KeyAmalgamationIter. */

/// Wraps a KeyAmalgamationIter for export via the FFI.
pub struct KeyAmalgamationIterWrapper<'a> {
    pub(crate) // For serialize.rs.
    iter: Option<KeyAmalgamationIter<'a, openpgp::packet::key::PublicParts,
                         openpgp::packet::key::UnspecifiedRole>>,
    // Whether next has been called.
    next_called: bool,
}

/// Returns an iterator over all `Key`s in a Cert.
///
/// That is, this returns an iterator over the primary key and any
/// subkeys.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter(cert: *const Cert)
    -> *mut KeyAmalgamationIterWrapper<'static>
{
    let cert = cert.ref_raw();
    box_raw!(KeyAmalgamationIterWrapper {
        iter: Some(cert.keys()),
        next_called: false,
    })
}

/// Frees a pgp_cert_key_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_free(
    iter: Option<&mut KeyAmalgamationIterWrapper>)
{
    ffi_free!(iter)
}

/// Changes the iterator to only return keys that have secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_secret<'a>(
    iter_wrapper: *mut KeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    use std::mem::transmute;
    iter_wrapper.iter = Some(unsafe {
        transmute(iter_wrapper.iter.take().unwrap().secret())
    });
}

/// Changes the iterator to only return keys that have unencrypted
/// secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_unencrypted_secret<'a>(
    iter_wrapper: *mut KeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    use std::mem::transmute;
    iter_wrapper.iter = Some(unsafe {
        transmute(iter_wrapper.iter.take().unwrap().unencrypted_secret())
    });
}

/// Changes the iterator to only return keys that are valid at time
/// `t`.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_policy<'a>(
    iter_wrapper: *mut KeyAmalgamationIterWrapper<'a>,
    policy: *const Policy,
    when: time_t)
    -> *mut ValidKeyAmalgamationIterWrapper<'static>
{
    let policy = policy.ref_raw();
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    use std::mem::transmute;
    box_raw!(ValidKeyAmalgamationIterWrapper {
        iter: Some(unsafe {
            transmute(iter_wrapper.iter.take().unwrap()
                      .with_policy(&**policy, maybe_time(when)))
        }),
        next_called: false,
    })
}

/// Returns the next key.  Returns NULL if there are no more elements.
///
/// If sigo is not NULL, stores the current self-signature (if any) in
/// *sigo.  (Note: subkeys always have signatures, but a primary key
/// may not have a direct signature, and there might not be any user
/// ids.)
///
/// If rso is not NULL, this stores the key's revocation status in
/// *rso.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_next<'a>(
    iter_wrapper: *mut KeyAmalgamationIterWrapper<'a>)
    -> Maybe<KeyAmalgamation<'a>>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.next_called = true;

    if let Some(ka) = iter_wrapper.iter.as_mut().unwrap().next() {
        Some(ka.parts_into_unspecified()).move_into_raw()
    } else {
        None
    }
}

/// Wraps a ValidKeyAmalgamationIter for export via the FFI.
pub struct ValidKeyAmalgamationIterWrapper<'a> {
    pub(crate) // For serialize.rs.
    iter: Option<ValidKeyAmalgamationIter<'a, openpgp::packet::key::PublicParts,
                              openpgp::packet::key::UnspecifiedRole>>,
    // Whether next has been called.
    next_called: bool,
}

/// Returns an iterator over all valid `Key`s in a Cert.
///
/// That is, this returns an iterator over the primary key and any
/// subkeys that are valid (i.e., have a self-signature at time
/// `when`).
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter(cert: *const Cert,
                                          policy: *const Policy, when: time_t)
    -> *mut ValidKeyAmalgamationIterWrapper<'static>
{
    let cert = cert.ref_raw();
    let iter = box_raw!(KeyAmalgamationIterWrapper {
        iter: Some(cert.keys()),
        next_called: false,
    });

    pgp_cert_key_iter_policy(iter, policy, when)
}

/// Frees a pgp_cert_key_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_free(
    iter: Option<&mut ValidKeyAmalgamationIterWrapper>)
{
    ffi_free!(iter)
}

/// Changes the iterator to only return keys that have secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_secret<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change ValidKeyAmalgamationIter filter after iterating.");
    }

    use std::mem::transmute;
    iter_wrapper.iter = Some(unsafe {
        transmute(iter_wrapper.iter.take().unwrap().secret())
    });
}

/// Changes the iterator to only return keys that have unencrypted
/// secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_unencrypted_secret<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change ValidKeyAmalgamationIter filter after iterating.");
    }

    use std::mem::transmute;
    iter_wrapper.iter = Some(unsafe {
        transmute(iter_wrapper.iter.take().unwrap().unencrypted_secret())
    });
}

/// Changes the iterator to only return keys that are certification
/// capable.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_for_certification<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter =
        Some(iter_wrapper.iter.take().unwrap().for_certification());
}

/// Changes the iterator to only return keys that are certification
/// capable.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_for_signing<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter =
        Some(iter_wrapper.iter.take().unwrap().for_signing());
}

/// Changes the iterator to only return keys that are capable of
/// encrypting data at rest.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_for_storage_encryption<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter =
        Some(iter_wrapper.iter.take().unwrap().for_storage_encryption());
}

/// Changes the iterator to only return keys that are capable of
/// encrypting data for transport.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_for_transport_encryption<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter =
        Some(iter_wrapper.iter.take().unwrap().for_transport_encryption());
}

/// Changes the iterator to only return keys that are alive.
///
/// If you call this function (or `pgp_cert_valid_key_iter_alive_at`), only
/// the last value is used.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_alive<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter = Some(iter_wrapper.iter.take().unwrap().alive());
}

/// Changes the iterator to only return keys whose revocation status
/// matches `revoked`.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_revoked<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>,
    revoked: bool)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyAmalgamationIter filter after iterating.");
    }

    iter_wrapper.iter =
        Some(iter_wrapper.iter.take().unwrap().revoked(revoked));
}

/// Returns the next valid key.  Returns NULL if there are no more
/// elements.
///
/// If sigo is not NULL, stores the current self-signature.
///
/// If rso is not NULL, this stores the key's revocation status in
/// *rso.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_valid_key_iter_next<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>,
    sigo: Option<&mut *mut Signature>,
    rso: Option<&mut *mut RevocationStatus<'a>>)
    -> Maybe<ValidKeyAmalgamation<'a>>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.next_called = true;

    if let Some(ka) = iter_wrapper.iter.as_mut().unwrap().next() {
        let sig = ka.binding_signature();
        let rs = ka.revocation_status();

        if let Some(ptr) = sigo {
            *ptr = sig.move_into_raw();
        }

        if let Some(ptr) = rso {
            *ptr = rs.move_into_raw();
        }

        Some(ka.parts_into_unspecified()).move_into_raw()
    } else {
        None
    }
}

/// Wraps a CertParser for export via the FFI.
pub struct CertParserWrapper<'a> {
    parser: CertParser<'a>,
}

/// Returns a CertParser.
///
/// A `CertParser` parses a keyring, which is simply zero or more Certs
/// concatenated together.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_parser_from_bytes(errp: Option<&mut *mut crate::error::Error>,
                             buf: *const u8, len: size_t)
    -> *mut CertParserWrapper<'static>
{
    ffi_make_fry_from_errp!(errp);

    let buf : &[u8] = unsafe { std::slice::from_raw_parts(buf, len) };
    box_raw!(CertParserWrapper { parser: ffi_try!(CertParser::from_bytes(buf)) })
}

/// Returns a CertParser.
///
/// A `CertParser` parses a keyring, which is simply zero or more Certs
/// concatenated together.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_parser_from_packet_parser(ppr: *mut PacketParserResult<'static>)
    -> *mut CertParserWrapper<'static>
{
    let ppr = ffi_param_move!(ppr);
    let parser = CertParser::from(*ppr);
    box_raw!(CertParserWrapper { parser: parser })
}


/// Returns the next Cert, if any.
///
/// If there is an error parsing the Cert, it is returned in *errp.
///
/// If this function returns NULL and does not set *errp, then the end
/// of the file was reached.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_parser_next(errp: Option<&mut *mut crate::error::Error>,
                       parser: *mut CertParserWrapper)
    -> *mut Cert
{
    ffi_make_fry_from_errp!(errp);
    let wrapper : &mut CertParserWrapper = ffi_param_ref_mut!(parser);
    match wrapper.parser.next() {
        Some(certr) => ffi_try!(certr).move_into_raw(),
        None => ::std::ptr::null_mut(),
    }
}

/// Frees a pgp_cert_parser_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_parser_free(parser: Option<&mut CertParserWrapper>)
{
    ffi_free!(parser)
}

/* CertBuilder */

/// Creates a default `pgp_cert_builder_t`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_cert_builder_t builder;
/// pgp_cert_t cert;
/// pgp_signature_t revocation;
///
/// builder = pgp_cert_builder_new ();
/// pgp_cert_builder_set_cipher_suite (&builder, PGP_CERT_CIPHER_SUITE_CV25519);
/// pgp_cert_builder_add_userid (&builder, "some@example.org");
/// pgp_cert_builder_add_signing_subkey (&builder);
/// pgp_cert_builder_add_transport_encryption_subkey (&builder);
/// pgp_cert_builder_generate (NULL, builder, &cert, &revocation);
/// assert (cert);
/// assert (revocation);
///
/// /* Use the Cert.  */
///
/// pgp_signature_free (revocation);
/// pgp_cert_free (cert);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_new() -> *mut CertBuilder {
    box_raw!(CertBuilder::new())
}

/// Generates a general-purpose key.
///
/// The key's primary key is certification- and signature-capable.
/// The key has one subkey, an encryption-capable subkey.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_general_purpose(cs: c_int,
                                                       uid: *const c_char)
    -> *mut CertBuilder
{
    let uid = if uid.is_null() {
        None
    } else {
        Some(ffi_param_cstr!(uid).to_string_lossy())
    };
    box_raw!(CertBuilder::general_purpose(
        Some(int_to_cipher_suite(cs)), uid))
}

/// Frees an `pgp_cert_builder_t`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_free(certb: Option<&mut CertBuilder>)
{
    ffi_free!(certb)
}

fn int_to_cipher_suite(cs: c_int) -> CipherSuite {
    use self::CipherSuite::*;

    match cs {
        0 => Cv25519,
        1 => RSA3k,
        2 => P256,
        3 => P384,
        4 => P521,
        5 => RSA2k,
        6 => RSA4k,
        n => panic!("Bad ciphersuite: {}", n),
     }
}

/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_set_cipher_suite
    (certb: *mut *mut CertBuilder, cs: c_int)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let cs = int_to_cipher_suite(cs);
    let certb_ = certb_.set_cipher_suite(cs);
    *certb = box_raw!(certb_);
}

/// Sets the password for primary and all subkeys.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_set_password
    (certb: *mut *mut CertBuilder, password: *const u8, password_len: size_t)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let password: Password = password.into();
    let certb_ = certb_.set_password(Some(password));
    *certb = box_raw!(certb_);
}

/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
///
/// `uid` must contain valid UTF-8.  If it does not contain valid
/// UTF-8, then the invalid code points are silently replaced with
/// `U+FFFD REPLACEMENT CHARACTER`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_add_userid
    (certb: *mut *mut CertBuilder, uid: *const c_char)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let uid = ffi_param_cstr!(uid).to_string_lossy();
    let certb_ = certb_.add_userid(uid);
    *certb = box_raw!(certb_);
}

/// Adds a signing capable subkey.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_add_signing_subkey
    (certb: *mut *mut CertBuilder)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let certb_ = certb_.add_signing_subkey();
    *certb = box_raw!(certb_);
}

/// Adds an encryption capable subkey.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_add_transport_encryption_subkey
    (certb: *mut *mut CertBuilder)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let certb_ = certb_.add_transport_encryption_subkey();
    *certb = box_raw!(certb_);
}

/// Adds an certification capable subkey.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_add_certification_subkey
    (certb: *mut *mut CertBuilder)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let certb_ = certb_.add_certification_subkey();
    *certb = box_raw!(certb_);
}

/// Sets the creation time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_set_creation_time
    (certb: *mut *mut CertBuilder, when: time_t)
{
    let certb = ffi_param_ref_mut!(certb);
    let certb_ = ffi_param_move!(*certb);
    let certb_ = certb_.set_creation_time(maybe_time(when));
    *certb = box_raw!(certb_);
}

/// Generates the actual Cert.
///
/// Consumes `certb`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_generate
    (errp: Option<&mut *mut crate::error::Error>, certb: *mut CertBuilder,
     cert_out: *mut Maybe<Cert>,
     revocation_out: *mut *mut Signature)
    -> Status
{
    let cert_out = ffi_param_ref_mut!(cert_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let certb = ffi_param_move!(certb);
    match certb.generate() {
        Ok((cert, revocation)) => {
            *cert_out = Some(cert).move_into_raw();
            *revocation_out = revocation.move_into_raw();
            Status::Success
        },
        Err(e) => {
            *cert_out = None;
            Err::<(), anyhow::Error>(e).move_into_raw(errp)
        },
    }
}
