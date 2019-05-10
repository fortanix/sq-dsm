//! Signature packets.
//!
//! Signature packets are used both for certification purposes as well
//! as for document signing purposes.
//!
//! See [Section 5.2 of RFC 4880] for details.
//!
//!   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2

use libc::time_t;

extern crate sequoia_openpgp as openpgp;
use super::Packet;
use super::super::fingerprint::Fingerprint;
use super::super::keyid::KeyID;
use super::key::Key;

use Maybe;
use MoveFromRaw;
use MoveIntoRaw;
use RefRaw;

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
#[::ffi_wrapper_type(prefix = "pgp_",
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
fn pgp_signature_can_certify(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().can_certify()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_can_sign(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().can_sign()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_can_encrypt_for_transport(sig: *const Signature)
                                           -> bool {
    sig.ref_raw().key_flags().can_encrypt_for_transport()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_can_encrypt_at_rest(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().can_encrypt_at_rest()
}

/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_can_authenticate(sig: *const Signature) -> bool {
    sig.ref_raw().key_flags().can_authenticate()
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


/// Returns whether the signature is alive.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_alive(sig: *const Signature) -> bool {
    sig.ref_raw().signature_alive()
}

/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_alive_at(sig: *const Signature, when: time_t) -> bool {
    sig.ref_raw()
        .signature_alive_at(time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns whether the signature is expired.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_expired(sig: *const Signature) -> bool {
    sig.ref_raw().signature_expired()
}

/// Returns whether the signature is expired at the specified time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_expired_at(sig: *const Signature, when: time_t) -> bool {
    sig.ref_raw()
        .signature_expired_at(time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns whether the signature is alive.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_key_alive(sig: *const Signature, key: *const Key)
                           -> bool {
    sig.ref_raw().key_alive(key.ref_raw())
}

/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_key_alive_at(sig: *const Signature, key: *const Key,
                              when: time_t) -> bool {
    sig.ref_raw()
        .key_alive_at(key.ref_raw(),
                      time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns whether the signature is expired.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_key_expired(sig: *const Signature, key: *const Key)
                             -> bool {
    sig.ref_raw().key_expired(key.ref_raw())
}

/// Returns whether the signature is expired at the specified time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_signature_key_expired_at(sig: *const Signature, key: *const Key,
                                when: time_t) -> bool {
    sig.ref_raw()
        .key_expired_at(key.ref_raw(),
                        time::at(time::Timespec::new(when as i64, 0)))
}
