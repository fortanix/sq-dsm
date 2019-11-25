//! Signature packets.
//!
//! Signature packets are used both for certification purposes as well
//! as for document signing purposes.
//!
//! See [Section 5.2 of RFC 4880] for details.
//!
//!   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2

use libc::time_t;
use libc::c_uint;

extern crate sequoia_openpgp as openpgp;
use super::Packet;
use super::super::fingerprint::Fingerprint;
use super::super::keyid::KeyID;
use super::key::Key;

use crate::error::Status;
use crate::Maybe;
use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::RefRaw;

/// Holds a signature packet.
///
/// Signature packets are used both for certification purposes as well
/// as for document signing purposes.
///
/// See [Section 5.2 of RFC 4880] for details.
///
///   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2
///
/// Wraps [`sequoia-openpgp::packet::signature::Signature`].
///
/// [`sequoia-openpgp::packet::signature::Signature`]: ../../sequoia_openpgp/packet/signature/struct.Signature.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq, Parse, Serialize")]
pub struct Signature(openpgp::packet::Signature);

/// Converts the signature to a packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_into_packet(s: *mut Signature) -> *mut Packet {
    let p : openpgp::Packet = s.move_from_raw().into();
    p.move_into_raw()
}

/// Returns the value of the `Signature` packet's Issuer subpacket.
///
/// If there is no Issuer subpacket, this returns NULL.  Note: if
/// there is no Issuer subpacket, but there is an IssuerFingerprint
/// subpacket, this still returns NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_issuer(sig: *const Signature) -> Maybe<KeyID> {
    sig.ref_raw().issuer().move_into_raw()
}

/// Returns the value of the `Signature` packet's IssuerFingerprint subpacket.
///
/// If there is no IssuerFingerprint subpacket, this returns NULL.
/// Note: if there is no IssuerFingerprint subpacket, but there is an
/// Issuer subpacket, this still returns NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_issuer_fingerprint(sig: *const Signature)
                                    -> Maybe<Fingerprint> {
    sig.ref_raw().issuer_fingerprint().move_into_raw()
}


/// Returns whether the KeyFlags indicates that the key can be used to
/// make certifications.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_for_certification(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().for_certification()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_for_signing(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().for_signing()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_for_transport_encryption(sig: *const Signature)
                                           -> bool {
    sig.ref_raw().key_flags().for_transport_encryption()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_for_storage_encryption(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().for_storage_encryption()
}

/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_for_authentication(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().for_authentication()
}

/// Returns whether the KeyFlags indicates that the key is a split
/// key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_is_split_key(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().is_split_key()
}

/// Returns whether the KeyFlags indicates that the key is a group
/// key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_is_group_key(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().is_group_key()
}


/// Returns whether the signature is alive at the specified time.
///
/// A signature is considered to be alive if `creation time -
/// tolerance <= time` and `time <= expiration time`.
///
/// If `time` is 0, uses the current time.
///
/// This function uses the default tolerance.  If you want to specify
/// a different tolerance (or no tolerance), then use
/// `pgp_signature_alive_with_tolerance`.
///
/// Some tolerance for clock skew is sometimes necessary, because
/// although most computers synchronize their clock with a time
/// server, up to a few seconds of clock skew are not unusual in
/// practice.  And, even worse, several minutes of clock skew appear
/// to be not uncommon on virtual machines.
///
/// Not accounting for clock skew can result in signatures being
/// unexpectedly considered invalid.  Consider: computer A sends a
/// message to computer B at 9:00, but computer B, whose clock says
/// the current time is 8:59, rejects it, because the signature
/// appears to have been made in the future.  This is particularly
/// problematic for low-latency protocols built on top of OpenPGP,
/// e.g., state synchronization between two MUAs via a shared IMAP
/// folder.
///
/// Being tolerant to potential clock skew is not always appropriate.
/// For instance, when determining a User ID's current self signature
/// at time `t`, we don't ever want to consider a self-signature made
/// after `t` to be valid, even if it was made just a few moments
/// after `t`.  This goes doubly so for soft revocation certificates:
/// the user might send a message that she is retiring, and then
/// immediately create a soft revocation.  The soft revocation should
/// not invalidate the message.
///
/// Unfortunately, in many cases, whether we should account for clock
/// skew or not depends on application-specific context.  As a rule of
/// thumb, if the time and the timestamp come from different sources,
/// you probably want to account for clock skew.
///
/// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A Signature
/// Creation Time subpacket]] MUST be present in the hashed area."
/// Consequently, if such a packet does not exist, but a "Signature
/// Expiration Time" subpacket exists, we conservatively treat the
/// signature as expired, because there is no way to evaluate the
/// expiration time.
///
///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_alive(errp: Option<&mut *mut crate::error::Error>,
                       sig: *const Signature, time: time_t)
                       -> Status
{
    ffi_make_fry_from_errp!(errp);
    let time = if time == 0 {
        None
    } else {
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(time as u64, 0))
    };
    ffi_try_status!(sig.ref_raw().signature_alive(time, None))
}

/// Returns whether the signature is alive at the specified time.
///
/// A signature is considered to be alive if `creation time -
/// tolerance <= time` and `time <= expiration time`.
///
/// If `time` is 0, uses the current time.
///
/// If `tolerance` is 0, uses no tolerance.  To ensure consistency
/// across callers, you should use the default tolerance (i.e., use
/// `pgp_signature_alive`).
///
/// Some tolerance for clock skew is sometimes necessary, because
/// although most computers synchronize their clock with a time
/// server, up to a few seconds of clock skew are not unusual in
/// practice.  And, even worse, several minutes of clock skew appear
/// to be not uncommon on virtual machines.
///
/// Not accounting for clock skew can result in signatures being
/// unexpectedly considered invalid.  Consider: computer A sends a
/// message to computer B at 9:00, but computer B, whose clock says
/// the current time is 8:59, rejects it, because the signature
/// appears to have been made in the future.  This is particularly
/// problematic for low-latency protocols built on top of OpenPGP,
/// e.g., state synchronization between two MUAs via a shared IMAP
/// folder.
///
/// Being tolerant to potential clock skew is not always appropriate.
/// For instance, when determining a User ID's current self signature
/// at time `t`, we don't ever want to consider a self-signature made
/// after `t` to be valid, even if it was made just a few moments
/// after `t`.  This goes doubly so for soft revocation certificates:
/// the user might send a message that she is retiring, and then
/// immediately create a soft revocation.  The soft revocation should
/// not invalidate the message.
///
/// Unfortunately, in many cases, whether we should account for clock
/// skew or not depends on application-specific context.  As a rule of
/// thumb, if the time and the timestamp come from different sources,
/// you probably want to account for clock skew.
///
/// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A Signature
/// Creation Time subpacket]] MUST be present in the hashed area."
/// Consequently, if such a packet does not exist, but a "Signature
/// Expiration Time" subpacket exists, we conservatively treat the
/// signature as expired, because there is no way to evaluate the
/// expiration time.
///
///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_alive_with_tolerance(errp: Option<&mut *mut crate::error::Error>,
                                      sig: *const Signature,
                                      time: time_t, tolerance: c_uint)
                                      -> Status
{
    ffi_make_fry_from_errp!(errp);
    let time = if time == 0 {
        None
    } else {
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(time as u64, 0))
    };
    let tolerance = std::time::Duration::new(tolerance as u64, 0);
    ffi_try_status!(sig.ref_raw().signature_alive(time, Some(tolerance)))
}

/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
///
/// If `when` is 0, then the current time is used.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_key_alive(errp: Option<&mut *mut crate::error::Error>,
                           sig: *const Signature, key: *const Key,
                           when: time_t)
                           -> Status
{
    ffi_make_fry_from_errp!(errp);
    let t = if when == 0 {
        None
    } else {
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(when as u64, 0))
    };
    ffi_try_status!(sig.ref_raw().key_alive(key.ref_raw(), t))
}
