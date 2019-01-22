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
use self::openpgp::{
    KeyID,
    packet,
    Packet,
    Fingerprint,
};
use self::openpgp::packet::{
    Signature,
};

/// Frees the Signature.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_free(s: Option<&mut Signature>) {
    ffi_free!(s)
}

/// Converts the signature to a packet.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_to_packet(s: *mut Signature)
                                              -> *mut Packet
{
    let s = ffi_param_move!(s);
    box_raw!(s.to_packet())
}

/// Returns the value of the `Signature` packet's Issuer subpacket.
///
/// If there is no Issuer subpacket, this returns NULL.  Note: if
/// there is no Issuer subpacket, but there is an IssuerFingerprint
/// subpacket, this still returns NULL.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_issuer(sig: *const packet::Signature)
                                           -> *mut KeyID {
    let sig = ffi_param_ref!(sig);
    maybe_box_raw!(sig.issuer())
}

/// Returns the value of the `Signature` packet's IssuerFingerprint subpacket.
///
/// If there is no IssuerFingerprint subpacket, this returns NULL.
/// Note: if there is no IssuerFingerprint subpacket, but there is an
/// Issuer subpacket, this still returns NULL.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_issuer_fingerprint(
    sig: *const packet::Signature)
    -> *mut Fingerprint
{
    let sig = ffi_param_ref!(sig);
    maybe_box_raw!(sig.issuer_fingerprint())
}


/// Returns whether the KeyFlags indicates that the key can be used to
/// make certifications.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_can_certify(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().can_certify()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_can_sign(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().can_sign()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_can_encrypt_for_transport(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().can_encrypt_for_transport()
}

/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_can_encrypt_at_rest(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().can_encrypt_at_rest()
}

/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_can_authenticate(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().can_authenticate()
}

/// Returns whether the KeyFlags indicates that the key is a split
/// key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_is_split_key(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().is_split_key()
}

/// Returns whether the KeyFlags indicates that the key is a group
/// key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_is_group_key(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.key_flags().is_group_key()
}


/// Returns whether the signature is alive.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_alive(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.signature_alive()
}

/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_alive_at(sig: *const packet::Signature,
                                             when: time_t)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.signature_alive_at(time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns whether the signature is expired.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_expired(sig: *const packet::Signature)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.signature_expired()
}

/// Returns whether the signature is expired at the specified time.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signature_expired_at(sig: *const packet::Signature,
                                               when: time_t)
    -> bool
{
    let sig = ffi_param_ref!(sig);
    sig.signature_expired_at(time::at(time::Timespec::new(when as i64, 0)))
}
