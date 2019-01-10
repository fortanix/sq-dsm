//! Handles TPKs.
//!
//! Wraps [`sequoia-openpgp::TPK`] and [related functionality].
//!
//! [`sequoia-openpgp::TPK`]: ../../../sequoia_openpgp/struct.TPK.html
//! [related functionality]: ../../../sequoia_openpgp/tpk/index.html

use std::ffi::{CString, CStr};
use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, c_char, c_int, size_t, time_t};

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    Fingerprint,
    Packet,
    PacketPile,
    RevocationStatus,
    TPK,
    TSK,
    autocrypt::Autocrypt,
    constants::ReasonForRevocation,
    packet::{self, Signature},
    parse::PacketParserResult,
    parse::Parse,
    serialize::Serialize,
    tpk::{
        CipherSuite,
        KeyIter,
        TPKBuilder,
        UserIDBinding,
        UserIDBindingIter,
    },
};

use ::core::Context;
use ::error::Status;

/// Returns the first TPK encountered in the reader.
#[no_mangle]
pub extern "system" fn sq_tpk_from_reader(ctx: *mut Context,
                                          reader: *mut Box<Read>)
                                          -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let reader = ffi_param_ref_mut!(reader);
    fry_box!(ctx, TPK::from_reader(reader))
}

/// Returns the first TPK encountered in the file.
#[no_mangle]
pub extern "system" fn sq_tpk_from_file(ctx: *mut Context,
                                        filename: *const c_char)
                                        -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, TPK::from_file(&filename))
}

/// Returns the first TPK found in `m`.
///
/// Consumes `m`.
#[no_mangle]
pub extern "system" fn sq_tpk_from_packet_pile(ctx: *mut Context,
                                               m: *mut PacketPile)
                                               -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let m = ffi_param_move!(m);
    fry_box!(ctx, TPK::from_packet_pile(*m))
}

/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP-encoded TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_from_bytes(ctx: *mut Context,
                                         b: *const uint8_t, len: size_t)
                                         -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, TPK::from_bytes(buf))
}

/// Returns the first TPK found in the packet parser.
///
/// Consumes the packet parser result.
#[no_mangle]
pub extern "system" fn sq_tpk_from_packet_parser(ctx: *mut Context,
                                                 ppr: *mut PacketParserResult)
    -> *mut TPK
{
    let ctx = ffi_param_ref_mut!(ctx);
    let ppr = ffi_param_move!(ppr);

    fry_box!(ctx, TPK::from_packet_parser(*ppr))
}

/// Frees the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_free(tpk: Option<&mut TPK>) {
    ffi_free!(tpk)
}

/// Clones the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_clone(tpk: *const TPK)
                                    -> *mut TPK {
    let tpk = ffi_param_ref!(tpk);
    box_raw!(tpk.clone())
}

/// Compares TPKs.
#[no_mangle]
pub extern "system" fn sq_tpk_equal(a: *const TPK,
                                    b: *const TPK)
                                    -> bool {
    let a = ffi_param_ref!(a);
    let b = ffi_param_ref!(b);
    a == b
}

/// Serializes the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_serialize(ctx: *mut Context,
                                        tpk: *const TPK,
                                        writer: *mut Box<Write>)
                                        -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_ref!(tpk);
    let writer = ffi_param_ref_mut!(writer);
    fry_status!(ctx, tpk.serialize(writer))
}

/// Merges `other` into `tpk`.
///
/// If `other` is a different key, then nothing is merged into
/// `tpk`, but `tpk` is still canonicalized.
///
/// Consumes `tpk` and `other`.
#[no_mangle]
pub extern "system" fn sq_tpk_merge(ctx: *mut Context,
                                    tpk: *mut TPK,
                                    other: *mut TPK)
                                    -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_move!(tpk);
    let other = ffi_param_move!(other);
    fry_box!(ctx, tpk.merge(*other))
}

/// Adds packets to the TPK.
///
/// This recanonicalizes the TPK.  If the packets are invalid, they
/// are dropped.
///
/// Consumes `tpk` and the packets in `packets`.  The buffer, however,
/// must be managed by the caller.
#[no_mangle]
pub extern "system" fn sq_tpk_merge_packets(ctx: *mut Context,
                                            tpk: *mut TPK,
                                            packets: *mut *mut Packet,
                                            packets_len: size_t)
                                            -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_move!(tpk);
    let packets = unsafe {
        slice::from_raw_parts_mut(packets, packets_len)
    };
    let packets =
        packets.iter_mut().map(|p| *unsafe { Box::from_raw(*p) } ).collect();
    fry_box!(ctx, tpk.merge_packets(packets))
}

/// Dumps the TPK.
///
/// XXX Remove this.
#[no_mangle]
pub extern "system" fn sq_tpk_dump(tpk: *const TPK) {
    let tpk = ffi_param_ref!(tpk);
    println!("{:?}", *tpk);
}

/// Returns the fingerprint.
#[no_mangle]
pub extern "system" fn sq_tpk_fingerprint(tpk: *const TPK)
                                          -> *mut Fingerprint {
    let tpk = ffi_param_ref!(tpk);
    box_raw!(tpk.fingerprint())
}

/// Cast the public key into a secret key that allows using the secret
/// parts of the containing keys.
#[no_mangle]
pub extern "system" fn sq_tpk_into_tsk(tpk: *mut TPK)
                                       -> *mut TSK {
    let tpk = ffi_param_move!(tpk);
    box_raw!(tpk.into_tsk())
}

/// Returns a reference to the TPK's primary key.
///
/// The tpk still owns the key.  The caller should neither modify nor
/// free the key.
#[no_mangle]
pub extern "system" fn sq_tpk_primary(tpk: *const TPK)
    -> *const packet::Key {
    let tpk = ffi_param_ref!(tpk);
    tpk.primary()
}

/// Returns the TPK's revocation status.
///
/// Note: this only returns whether the TPK has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
#[no_mangle]
pub extern "system" fn sq_tpk_revocation_status(tpk: *const TPK)
                                                -> *mut RevocationStatus<'static> {
    let tpk = ffi_param_ref!(tpk);
    box_raw!(tpk.revoked())
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


/// Returns a new revocation certificate for the TPK.
///
/// This function does *not* consume `tpk`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia.h>
///
/// sq_context_t ctx;
/// sq_tpk_builder_t builder;
/// sq_tpk_t tpk;
/// sq_signature_t revocation;
///
/// ctx = sq_context_new ("org.sequoia-pgp.tests", NULL);
///
/// builder = sq_tpk_builder_default ();
/// sq_tpk_builder_set_cipher_suite (&builder, SQ_TPK_CIPHER_SUITE_CV25519);
/// sq_tpk_builder_generate (ctx, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
/// sq_signature_free (revocation);    /* Free the generated one.  */
///
/// revocation = sq_tpk_revoke (ctx, tpk,
///                             SQ_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                             "It was the maid :/");
/// assert (revocation);
///
/// sq_packet_t packet = sq_signature_to_packet (revocation);
/// tpk = sq_tpk_merge_packets (ctx, tpk, &packet, 1);
/// assert (tpk);
///
/// sq_revocation_status_t rs = sq_tpk_revocation_status (tpk);
/// assert (sq_revocation_status_variant (rs) == SQ_REVOCATION_STATUS_REVOKED);
/// sq_revocation_status_free (rs);
///
/// sq_tpk_free (tpk);
/// sq_context_free (ctx);
/// ```
#[no_mangle]
pub extern "system" fn sq_tpk_revoke(ctx: *mut Context,
                                     tpk: *mut TPK,
                                     code: c_int,
                                     reason: Option<*const c_char>)
    -> *mut packet::Signature
{
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_ref!(tpk);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        unsafe {
            CStr::from_ptr(reason).to_bytes()
        }
    } else {
        b""
    };

    fry_box!(ctx, tpk.revoke(code, reason))
}

/// Adds a revocation certificate to the tpk.
///
/// This function consumes the tpk.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia.h>
///
/// sq_context_t ctx;
/// sq_tpk_builder_t builder;
/// sq_tpk_t tpk;
/// sq_signature_t revocation;
///
/// ctx = sq_context_new ("org.sequoia-pgp.tests", NULL);
///
/// builder = sq_tpk_builder_default ();
/// sq_tpk_builder_set_cipher_suite (&builder, SQ_TPK_CIPHER_SUITE_CV25519);
/// sq_tpk_builder_generate (ctx, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
/// sq_signature_free (revocation);    /* Free the generated one.  */
///
/// tpk = sq_tpk_revoke_in_place (ctx, tpk,
///                               SQ_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                               "It was the maid :/");
///
/// sq_revocation_status_t rs = sq_tpk_revocation_status (tpk);
/// assert (sq_revocation_status_variant (rs) == SQ_REVOCATION_STATUS_REVOKED);
/// sq_revocation_status_free (rs);
///
/// sq_tpk_free (tpk);
/// sq_context_free (ctx);
/// ```
#[no_mangle]
pub extern "system" fn sq_tpk_revoke_in_place(ctx: *mut Context,
                                              tpk: *mut TPK,
                                              code: c_int,
                                              reason: Option<*const c_char>)
    -> *mut TPK
{
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_move!(tpk);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        unsafe {
            CStr::from_ptr(reason).to_bytes()
        }
    } else {
        b""
    };

    fry_box!(ctx, tpk.revoke_in_place(code, reason))
}

/// Returns whether the TPK has expired.
#[no_mangle]
pub extern "system" fn sq_tpk_expired(tpk: *const TPK)
                                      -> c_int {
    let tpk = ffi_param_ref!(tpk);

    tpk.expired() as c_int
}

/// Returns whether the TPK has expired.
#[no_mangle]
pub extern "system" fn sq_tpk_expired_at(tpk: *const TPK, when: time_t)
                                      -> c_int {
    let tpk = ffi_param_ref!(tpk);
    tpk.expired_at(time::at(time::Timespec::new(when as i64, 0))) as c_int
}

/// Returns whether the TPK is alive.
#[no_mangle]
pub extern "system" fn sq_tpk_alive(tpk: *const TPK)
                                      -> c_int {
    let tpk = ffi_param_ref!(tpk);

    tpk.alive() as c_int
}

/// Returns whether the TPK is alive at the specified time.
#[no_mangle]
pub extern "system" fn sq_tpk_alive_at(tpk: *const TPK, when: time_t)
                                      -> c_int {
    let tpk = ffi_param_ref!(tpk);
    tpk.alive_at(time::at(time::Timespec::new(when as i64, 0))) as c_int
}

/// Changes the TPK's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `tpk` and returns a new `TPK`.
#[no_mangle]
pub extern "system" fn sq_tpk_set_expiry(ctx: *mut Context,
                                         tpk: *mut TPK, expiry: u32)
                                         -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk = ffi_param_move!(tpk);

    fry_box!(ctx, tpk.set_expiry_in_seconds(expiry))
}

/// Returns whether the TPK includes any secret key material.
#[no_mangle]
pub extern "system" fn sq_tpk_is_tsk(tpk: *const TPK)
                                     -> c_int {
    let tpk = ffi_param_ref!(tpk);
    tpk.is_tsk() as c_int
}

/// Returns an iterator over the TPK's user id bindings.
#[no_mangle]
pub extern "system" fn sq_tpk_primary_user_id(tpk: *const TPK)
    -> *mut c_char
{
    let tpk = ffi_param_ref!(tpk);
    if let Some(binding) = tpk.userids().nth(0) {
        CString::new(binding.userid().userid())
            .unwrap() // Errors only on internal nul bytes.
            .into_raw()
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
#[no_mangle]
pub extern "system" fn sq_user_id_binding_user_id(
    binding: *const UserIDBinding)
    -> *mut c_char
{
    let binding = ffi_param_ref!(binding);

    if let Ok(c_str) = CString::new(binding.userid().userid()) {
        c_str.into_raw()
    } else {
        ptr::null_mut()
    }
}

/// Returns a reference to the self-signature, if any.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_selfsig(
    binding: *const UserIDBinding)
    -> Option<&'static Signature>
{
    let binding = ffi_param_ref!(binding);
    binding.binding_signature()
}


/* UserIDBindingIter */

/// Returns an iterator over the TPK's user id bindings.
#[no_mangle]
pub extern "system" fn sq_tpk_user_id_binding_iter(tpk: *const TPK)
    -> *mut UserIDBindingIter<'static>
{
    let tpk = ffi_param_ref!(tpk);
    box_raw!(tpk.userids())
}

/// Frees a sq_user_id_binding_iter_t.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_iter_free(
    iter: Option<&mut UserIDBindingIter>)
{
    ffi_free!(iter)
}

/// Returns the next `UserIDBinding`.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_iter_next<'a>(
    iter: *mut UserIDBindingIter<'a>)
    -> Option<&'a UserIDBinding>
{
    let iter = ffi_param_ref_mut!(iter);
    iter.next()
}

/* tpk::KeyIter. */

/// Wrapers a KeyIter for export via the FFI.
pub struct KeyIterWrapper<'a> {
    iter: KeyIter<'a>,
    rso: Option<RevocationStatus<'a>>,
}

/// Returns an iterator over the TPK's keys.
///
/// This iterates over both the primary key and any subkeys.
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter(tpk: *const TPK)
    -> *mut KeyIterWrapper<'static>
{
    let tpk = ffi_param_ref!(tpk);
    box_raw!(KeyIterWrapper {
        iter: tpk.keys(),
        rso: None,
    })
}

/// Frees a sq_tpk_key_iter_t.
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter_free(
    iter: Option<&mut KeyIterWrapper>)
{
    ffi_free!(iter)
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
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter_next<'a>(
    iter_wrapper: *mut KeyIterWrapper<'a>,
    sigo: Option<&mut Option<&'a packet::Signature>>,
    rso: Option<&mut &'a RevocationStatus<'a>>)
    -> Option<&'a packet::Key>
{
    let iter_wrapper = ffi_param_ref_mut!(iter_wrapper);
    iter_wrapper.rso = None;

    if let Some((sig, rs, key)) = iter_wrapper.iter.next() {
        if let Some(ptr) = sigo {
            *ptr = sig;
        }

        if let Some(ptr) = rso {
            iter_wrapper.rso = Some(rs);
            *ptr = iter_wrapper.rso.as_ref().unwrap();
        }

        Some(key)
    } else {
        None
    }
}

/* TPKBuilder */

/// Creates a default `sq_tpk_builder_t`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia.h>
///
/// sq_context_t ctx;
/// sq_tpk_builder_t builder;
/// sq_tpk_t tpk;
/// sq_signature_t revocation;
///
/// ctx = sq_context_new ("org.sequoia-pgp.tests", NULL);
///
/// builder = sq_tpk_builder_default ();
/// sq_tpk_builder_set_cipher_suite (&builder, SQ_TPK_CIPHER_SUITE_CV25519);
/// sq_tpk_builder_add_userid (&builder, "some@example.org");
/// sq_tpk_builder_add_signing_subkey (&builder);
/// sq_tpk_builder_add_encryption_subkey (&builder);
/// sq_tpk_builder_generate (ctx, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
///
/// /* Use the TPK.  */
///
/// sq_signature_free (revocation);
/// sq_tpk_free (tpk);
/// sq_context_free (ctx);
/// ```
#[no_mangle]
pub extern "system" fn sq_tpk_builder_default() -> *mut TPKBuilder {
    box_raw!(TPKBuilder::default())
}

/// Generates a key compliant to [Autocrypt Level 1].
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
#[no_mangle]
pub extern "system" fn sq_tpk_builder_autocrypt() -> *mut TPKBuilder {
    box_raw!(TPKBuilder::autocrypt(Autocrypt::V1))
}

/// Frees an `sq_tpk_builder_t`.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_free(tpkb: Option<&mut TPKBuilder>)
{
    ffi_free!(tpkb)
}

/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_set_cipher_suite
    (tpkb: *mut *mut TPKBuilder, cs: c_int)
{
    use self::CipherSuite::*;
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let cs = match cs {
        0 => Cv25519,
        1 => RSA3k,
        n => panic!("Bad ciphersuite: {}", n),
    };
    let tpkb_ = tpkb_.set_cipher_suite(cs);
    *tpkb = box_raw!(tpkb_);
}

/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_userid
    (tpkb: *mut *mut TPKBuilder, uid: *const c_char)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let uid = unsafe { CStr::from_ptr(uid).to_string_lossy().to_string() };
    let tpkb_ = tpkb_.add_userid(uid.as_ref());
    *tpkb = box_raw!(tpkb_);
}

/// Adds a signing capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_signing_subkey
    (tpkb: *mut *mut TPKBuilder)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let tpkb_ = tpkb_.add_signing_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an encryption capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_encryption_subkey
    (tpkb: *mut *mut TPKBuilder)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let tpkb_ = tpkb_.add_encryption_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an certification capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_certification_subkey
    (tpkb: *mut *mut TPKBuilder)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let tpkb_ = tpkb_.add_certification_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Generates the actual TPK.
///
/// Consumes `tpkb`.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_generate
    (ctx: *mut Context, tpkb: *mut TPKBuilder,
     tpk_out: *mut *mut TPK,
     revocation_out: *mut *mut Signature)
    -> Status
{
    let ctx = ffi_param_ref_mut!(ctx);
    let tpk_out = ffi_param_ref_mut!(tpk_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let tpkb = ffi_param_move!(tpkb);
    match tpkb.generate() {
        Ok((tpk, revocation)) => {
            *tpk_out = box_raw!(tpk);
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}
