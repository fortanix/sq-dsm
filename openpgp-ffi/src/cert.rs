//! OpenPGP Certificates.
//!
//! Wraps [`sequoia-openpgp::Cert`] and [related functionality].
//!
//! [`sequoia-openpgp::Cert`]: ../../sequoia_openpgp/struct.Cert.html
//! [related functionality]: ../../sequoia_openpgp/cert/index.html

use std::ptr;
use std::slice;
use libc::{c_char, c_int, size_t, time_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    autocrypt::Autocrypt,
    crypto,
    types::ReasonForRevocation,
    parse::{
        PacketParserResult,
        Parse,
    },
    cert::{
        CipherSuite,
        KeyIter,
        CertBuilder,
        CertParser,
        CertRevocationBuilder,
        UserIDBinding,
        UserIDBindingIter,
    },
};

use crate::error::Status;
use super::fingerprint::Fingerprint;
use super::packet::key::Key;
use super::packet::Packet;
use super::packet::signature::Signature;
use super::packet_pile::PacketPile;
use super::tsk::TSK;
use super::revocation_status::RevocationStatus;

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
    openpgp::Cert::from_packet_pile(m.move_from_raw()).move_into_raw(errp)
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

    openpgp::Cert::from_packet_parser(*ppr).move_into_raw(errp)
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
fn pgp_cert_merge_packets(errp: Option<&mut *mut crate::error::Error>,
                         cert: *mut Cert,
                         packets: *mut *mut Packet,
                         packets_len: size_t)
                         -> Maybe<Cert> {
    let cert = cert.move_from_raw();
    let packets = unsafe {
        slice::from_raw_parts_mut(packets, packets_len)
    };
    let packets =
        packets.iter_mut().map(|&mut p| p.move_from_raw()).collect();
    cert.merge_packets(packets).move_into_raw(errp)
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
/// [`TSK`]: cert/struct.TSK.html
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_as_tsk(cert: *const Cert) -> *mut TSK<'static> {
    cert.ref_raw().as_tsk().move_into_raw()
}

/// Returns a reference to the Cert's primary key.
///
/// The cert still owns the key.  The caller must not modify the key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_primary_key(cert: *const Cert) -> *const Key {
    let key = cert.ref_raw().primary()
        .mark_parts_unspecified_ref().mark_role_unspecified_ref();
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
fn pgp_cert_revoked(cert: *const Cert, when: time_t)
    -> *mut RevocationStatus<'static>
{
    cert.ref_raw().revoked(maybe_time(when)).move_into_raw()
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
/// cert = pgp_cert_merge_packets (NULL, cert, &packet, 1);
/// assert (cert);
///
/// pgp_revocation_status_t rs = pgp_cert_revoked (cert, 0);
/// assert (pgp_revocation_status_variant (rs) == PGP_REVOCATION_STATUS_REVOKED);
/// pgp_revocation_status_free (rs);
///
/// pgp_cert_free (cert);
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

/// Adds a revocation certificate to the cert.
///
/// This function consumes the cert.
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
/// cert = pgp_cert_revoke_in_place (NULL, cert, primary_signer,
///                               PGP_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                               "It was the maid :/");
/// assert (cert);
/// pgp_signer_free (primary_signer);
/// pgp_key_pair_free (primary_keypair);
///
/// pgp_revocation_status_t rs = pgp_cert_revoked (cert, 0);
/// assert (pgp_revocation_status_variant (rs) == PGP_REVOCATION_STATUS_REVOKED);
/// pgp_revocation_status_free (rs);
///
/// pgp_cert_free (cert);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_revoke_in_place(errp: Option<&mut *mut crate::error::Error>,
                           cert: *mut Cert,
                           primary_signer: *mut Box<dyn crypto::Signer>,
                           code: c_int,
                           reason: Option<&c_char>)
                           -> Maybe<Cert>
{
    let cert = cert.move_from_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        ffi_param_cstr!(reason as *const c_char).to_bytes()
    } else {
        b""
    };

    cert.revoke_in_place(signer.as_mut(), code, reason).move_into_raw(errp)
}

/// Returns whether the Cert is alive at the specified time.
///
/// If `when` is 0, then the current time is used.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_alive(errp: Option<&mut *mut crate::error::Error>,
                  cert: *const Cert, when: time_t) -> Status {
    ffi_make_fry_from_errp!(errp);
    ffi_try_status!(cert.ref_raw().alive(maybe_time(when)))
}

/// Changes the Cert's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `cert` and returns a new `Cert`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_set_expiry(errp: Option<&mut *mut crate::error::Error>,
                       cert: *mut Cert,
                       primary_signer: *mut Box<dyn crypto::Signer>,
                       expiry: u32)
                       -> Maybe<Cert> {
    let cert = cert.move_from_raw();
    let signer = ffi_param_ref_mut!(primary_signer);

    cert.set_expiry(signer.as_mut(),
                   Some(std::time::Duration::new(expiry as u64, 0)))
        .move_into_raw(errp)
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
fn pgp_cert_primary_user_id(cert: *const Cert)
                           -> *mut c_char
{
    let cert = cert.ref_raw();
    if let Some(binding) = cert.userids().nth(0) {
        ffi_return_string!(binding.userid().value())
    } else {
        ptr::null_mut()
    }
}

/* UserIDBinding */

/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_id_binding_user_id(
    binding: *const UserIDBinding)
    -> *mut c_char
{
    let binding = ffi_param_ref!(binding);

    ffi_return_maybe_string!(binding.userid().value())
}

/// Returns a reference to the self-signature, if any.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_id_binding_selfsig(
    binding: *const UserIDBinding)
    -> Maybe<Signature>
{
    let binding = ffi_param_ref!(binding);
    binding.binding_signature(None).move_into_raw()
}


/* UserIDBindingIter */

/// Returns an iterator over the Cert's user id bindings.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_user_id_binding_iter(cert: *const Cert)
    -> *mut UserIDBindingIter<'static>
{
    let cert = cert.ref_raw();
    box_raw!(cert.userids())
}

/// Frees a pgp_user_id_binding_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_id_binding_iter_free(
    iter: Option<&mut UserIDBindingIter>)
{
    ffi_free!(iter)
}

/// Returns the next `UserIDBinding`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_id_binding_iter_next<'a>(
    iter: *mut UserIDBindingIter<'a>)
    -> Option<&'a UserIDBinding>
{
    let iter = ffi_param_ref_mut!(iter);
    iter.next()
}

/* cert::KeyIter. */

/// Wraps a KeyIter for export via the FFI.
pub struct KeyIterWrapper<'a> {
    pub(crate) // For serialize.rs.
    iter: KeyIter<'a, openpgp::packet::key::PublicParts,
                  openpgp::packet::key::UnspecifiedRole>,
    // Whether next has been called.
    next_called: bool,
}

/// Returns an iterator over the Cert's live, non-revoked keys.
///
/// That is, this returns an iterator over the primary key and any
/// subkeys, along with the corresponding signatures.
///
/// Note: since a primary key is different from a subkey, the iterator
/// is over `Key`s and not `SubkeyBindings`.  Since the primary key
/// has no binding signature, the signature carrying the primary key's
/// key flags is returned (either a direct key signature, or the
/// self-signature on the primary User ID).  There are corner cases
/// where no such signature exists (e.g. partial Certs), therefore this
/// iterator may return `None` for the primary key's signature.
///
/// A valid `Key` has at least one good self-signature.
///
/// To return all keys, use `pgp_cert_key_iter_all()`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_valid(cert: *const Cert)
    -> *mut KeyIterWrapper<'static>
{
    let cert = cert.ref_raw();
    box_raw!(KeyIterWrapper {
        iter: cert.keys_valid(),
        next_called: false,
    })
}

/// Returns an iterator over all `Key`s in a Cert.
///
/// Compare with `pgp_cert_key_iter_valid`, which filters out expired
/// and revoked keys by default.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_all(cert: *const Cert)
    -> *mut KeyIterWrapper<'static>
{
    let cert = cert.ref_raw();
    box_raw!(KeyIterWrapper {
        iter: cert.keys_all(),
        next_called: false,
    })
}

/// Frees a pgp_cert_key_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_free(
    iter: Option<&mut KeyIterWrapper>)
{
    ffi_free!(iter)
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
pub extern "C" fn pgp_cert_key_iter_for_certification<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.for_certification();
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
pub extern "C" fn pgp_cert_key_iter_for_signing<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.for_signing();
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
pub extern "C" fn pgp_cert_key_iter_for_storage_encryption<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.for_storage_encryption();
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
pub extern "C" fn pgp_cert_key_iter_for_transport_encryption<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.for_transport_encryption();
}

/// Changes the iterator to only return keys that are alive.
///
/// If you call this function (or `pgp_cert_key_iter_alive_at`), only
/// the last value is used.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_alive<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.alive();
}

/// Changes the iterator to only return keys that are alive at the
/// specified time.
///
/// If you call this function (or `pgp_cert_key_iter_alive`), only the
/// last value is used.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_alive_at<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>,
    when: time_t)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter =
        tmp.alive_at(maybe_time(when).unwrap_or(std::time::UNIX_EPOCH));
}

/// Changes the iterator to only return keys whose revocation status
/// matches `revoked`.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_revoked<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>,
    revoked: bool)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = tmp.revoked(Some(revoked));
}

/// Changes the iterator to only return keys that have secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_secret<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter = unsafe { std::mem::transmute(tmp.secret()) };
}

/// Changes the iterator to only return keys that have unencrypted
/// secret keys.
///
/// Note: you may not call this function after starting to iterate.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_key_iter_unencrypted_secret<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>)
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    if iter_wrapper.next_called {
        panic!("Can't change KeyIter filter after iterating.");
    }

    use std::mem;
    let tmp = mem::replace(&mut iter_wrapper.iter, unsafe { mem::zeroed() });
    iter_wrapper.iter =
        unsafe { std::mem::transmute(tmp.unencrypted_secret()) };
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
    iter_wrapper: *mut KeyIterWrapper<'a>,
    sigo: Option<&mut Maybe<Signature>>,
    rso: Option<&mut *mut RevocationStatus<'a>>)
    -> Maybe<Key>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.next_called = true;

    if let Some(ka) = iter_wrapper.iter.next() {
        // XXX: Shouldn't assume the current time.
        let sig = ka.binding_signature(None);
        let rs = ka.revoked(None);
        let key = ka.key();

        if let Some(ptr) = sigo {
            *ptr = sig.move_into_raw();
        }

        if let Some(ptr) = rso {
            *ptr = rs.move_into_raw();
        }

        let key
            = key.mark_parts_unspecified_ref().mark_role_unspecified_ref();

        Some(key).move_into_raw()
    } else {
        None
    }
}

/// Wraps a CertParser for export via the FFI.
pub struct CertParserWrapper<'a> {
    parser: CertParser<'a, std::vec::IntoIter<self::openpgp::Packet>>,
}

/// Returns a CertParser.
///
/// A `CertParser` parses a keyring, which is simply zero or more Certs
/// concatenated together.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_cert_parser_from_bytes(errp: Option<&mut *mut crate::error::Error>,
                             buf: *mut u8, len: size_t)
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
    let parser = CertParser::from_packet_parser(*ppr);
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

/// Generates a key compliant to [Autocrypt Level 1].
///
/// Autocrypt requires a user id, however, if `uid` is NULL, a Cert is
/// created without any user ids.  It is then the caller's
/// responsibility to ensure that a user id is added later.
///
/// `uid` must contain valid UTF-8.  If it does not contain valid
/// UTF-8, then the invalid code points are silently replaced with
/// `U+FFFD REPLACEMENT CHARACTER`.
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_cert_builder_autocrypt(uid: *const c_char)
    -> *mut CertBuilder
{
    let uid = if uid.is_null() {
        None
    } else {
        Some(ffi_param_cstr!(uid).to_string_lossy())
    };
    box_raw!(CertBuilder::autocrypt(Autocrypt::V1, uid))
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
            Err::<(), failure::Error>(e).move_into_raw(errp)
        },
    }
}
