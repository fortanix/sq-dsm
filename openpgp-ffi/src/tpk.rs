//! Transferable public keys.
//!
//! Wraps [`sequoia-openpgp::TPK`] and [related functionality].
//!
//! [`sequoia-openpgp::TPK`]: ../../sequoia_openpgp/struct.TPK.html
//! [related functionality]: ../../sequoia_openpgp/tpk/index.html

use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, c_char, c_int, size_t, time_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    Packet,
    PacketPile,
    RevocationStatus,
    autocrypt::Autocrypt,
    crypto,
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

use ::error::Status;
use super::fingerprint::Fingerprint;
use super::tsk::TSK;
use Maybe;

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
#[::ffi_wrapper_type(prefix = "pgp_", name = "tpk",
                     derive = "Clone, Debug, Display, PartialEq")]
pub struct TPK(openpgp::TPK);

/// Returns the first TPK encountered in the reader.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_from_reader(errp: Option<&mut *mut failure::Error>,
                       reader: *mut Box<Read>)
                       -> Maybe<TPK> {
    let reader = ffi_param_ref_mut!(reader);
    openpgp::TPK::from_reader(reader).move_into_raw(errp)
}

/// Returns the first TPK encountered in the file.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_from_file(errp: Option<&mut *mut failure::Error>,
                     filename: *const c_char)
                     -> Maybe<TPK> {
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    openpgp::TPK::from_file(&filename).move_into_raw(errp)
}

/// Returns the first TPK found in `m`.
///
/// Consumes `m`.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_from_packet_pile(errp: Option<&mut *mut failure::Error>,
                            m: *mut PacketPile)
                            -> Maybe<TPK> {
    let m = ffi_param_move!(m);
    openpgp::TPK::from_packet_pile(*m).move_into_raw(errp)
}

/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP-encoded TPK.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_from_bytes(errp: Option<&mut *mut failure::Error>,
                      b: *const uint8_t, len: size_t)
                      -> Maybe<TPK> {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    openpgp::TPK::from_bytes(buf).move_into_raw(errp)
}

/// Returns the first TPK found in the packet parser.
///
/// Consumes the packet parser result.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_from_packet_parser(errp: Option<&mut *mut failure::Error>,
                              ppr: *mut PacketParserResult)
                              -> Maybe<TPK>
{
    let ppr = ffi_param_move!(ppr);

    openpgp::TPK::from_packet_parser(*ppr).move_into_raw(errp)
}

/// Serializes the TPK.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_serialize(errp: Option<&mut *mut failure::Error>,
                     tpk: *const TPK,
                     writer: *mut Box<Write>)
                     -> Status {
    ffi_make_fry_from_errp!(errp);
    let tpk = tpk.ref_raw();
    let writer = ffi_param_ref_mut!(writer);
    ffi_try_status!(tpk.serialize(writer))
}

/// Merges `other` into `tpk`.
///
/// If `other` is a different key, then nothing is merged into
/// `tpk`, but `tpk` is still canonicalized.
///
/// Consumes `tpk` and `other`.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_merge(errp: Option<&mut *mut failure::Error>,
                 tpk: *mut TPK,
                 other: *mut TPK)
                 -> Maybe<TPK> {
    let tpk = tpk.move_from_raw();
    let other = other.move_from_raw();
    tpk.merge(other).move_into_raw(errp)
}

/// Adds packets to the TPK.
///
/// This recanonicalizes the TPK.  If the packets are invalid, they
/// are dropped.
///
/// Consumes `tpk` and the packets in `packets`.  The buffer, however,
/// must be managed by the caller.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_merge_packets(errp: Option<&mut *mut failure::Error>,
                         tpk: *mut TPK,
                         packets: *mut *mut Packet,
                         packets_len: size_t)
                         -> Maybe<TPK> {
    let tpk = tpk.move_from_raw();
    let packets = unsafe {
        slice::from_raw_parts_mut(packets, packets_len)
    };
    let packets =
        packets.iter_mut().map(|p| *unsafe { Box::from_raw(*p) } ).collect();
    tpk.merge_packets(packets).move_into_raw(errp)
}

/// Returns the fingerprint.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_fingerprint(tpk: *const TPK)
                       -> *mut Fingerprint {
    let tpk = tpk.ref_raw();
    tpk.fingerprint().move_into_raw()
}

/// Cast the public key into a secret key that allows using the secret
/// parts of the containing keys.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_into_tsk(tpk: *mut TPK)
                    -> *mut TSK {
    tpk.move_from_raw().into_tsk().move_into_raw()
}

/// Returns a reference to the TPK's primary key.
///
/// The tpk still owns the key.  The caller should neither modify nor
/// free the key.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_primary(tpk: *const TPK)
                   -> *const packet::Key {
    let tpk = tpk.ref_raw();
    tpk.primary()
}

/// Returns the TPK's revocation status.
///
/// Note: this only returns whether the TPK has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_revocation_status(tpk: *const TPK)
                             -> *mut RevocationStatus<'static> {
    let tpk = tpk.ref_raw();
    box_raw!(tpk.revoked(None))
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
/// #include <sequoia/openpgp.h>
///
/// pgp_tpk_builder_t builder;
/// pgp_tpk_t tpk;
/// pgp_signature_t revocation;
/// pgp_key_t primary_key;
/// pgp_key_pair_t primary_keypair;
/// pgp_signer_t primary_signer;
///
/// builder = pgp_tpk_builder_default ();
/// pgp_tpk_builder_set_cipher_suite (&builder, PGP_TPK_CIPHER_SUITE_CV25519);
/// pgp_tpk_builder_generate (NULL, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
/// pgp_signature_free (revocation);    /* Free the generated one.  */
///
/// primary_key = pgp_key_clone (pgp_tpk_primary (tpk));
/// assert (primary_key);
/// primary_keypair = pgp_key_into_key_pair (NULL, primary_key);
/// assert (primary_keypair);
/// primary_signer = pgp_key_pair_as_signer (primary_keypair);
/// revocation = pgp_tpk_revoke (NULL, tpk, primary_signer,
///                             PGP_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                             "It was the maid :/");
/// assert (revocation);
/// pgp_signer_free (primary_signer);
/// pgp_key_pair_free (primary_keypair);
///
/// pgp_packet_t packet = pgp_signature_to_packet (revocation);
/// tpk = pgp_tpk_merge_packets (NULL, tpk, &packet, 1);
/// assert (tpk);
///
/// pgp_revocation_status_t rs = pgp_tpk_revocation_status (tpk);
/// assert (pgp_revocation_status_variant (rs) == PGP_REVOCATION_STATUS_REVOKED);
/// pgp_revocation_status_free (rs);
///
/// pgp_tpk_free (tpk);
/// ```
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_revoke(errp: Option<&mut *mut failure::Error>,
                  tpk: *const TPK,
                  primary_signer: *mut Box<crypto::Signer>,
                  code: c_int,
                  reason: Option<&c_char>)
                  -> *mut packet::Signature
{
    ffi_make_fry_from_errp!(errp);
    let tpk = tpk.ref_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        ffi_param_cstr!(reason as *const c_char).to_bytes()
    } else {
        b""
    };

    ffi_try_box!(tpk.revoke(signer.as_mut(), code, reason))
}

/// Adds a revocation certificate to the tpk.
///
/// This function consumes the tpk.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_tpk_builder_t builder;
/// pgp_tpk_t tpk;
/// pgp_signature_t revocation;
/// pgp_key_t primary_key;
/// pgp_key_pair_t primary_keypair;
/// pgp_signer_t primary_signer;
///
/// builder = pgp_tpk_builder_default ();
/// pgp_tpk_builder_set_cipher_suite (&builder, PGP_TPK_CIPHER_SUITE_CV25519);
/// pgp_tpk_builder_generate (NULL, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
/// pgp_signature_free (revocation);    /* Free the generated one.  */
///
/// primary_key = pgp_key_clone (pgp_tpk_primary (tpk));
/// assert (primary_key);
/// primary_keypair = pgp_key_into_key_pair (NULL, primary_key);
/// assert (primary_keypair);
/// primary_signer = pgp_key_pair_as_signer (primary_keypair);
/// tpk = pgp_tpk_revoke_in_place (NULL, tpk, primary_signer,
///                               PGP_REASON_FOR_REVOCATION_KEY_COMPROMISED,
///                               "It was the maid :/");
/// assert (tpk);
/// pgp_signer_free (primary_signer);
/// pgp_key_pair_free (primary_keypair);
///
/// pgp_revocation_status_t rs = pgp_tpk_revocation_status (tpk);
/// assert (pgp_revocation_status_variant (rs) == PGP_REVOCATION_STATUS_REVOKED);
/// pgp_revocation_status_free (rs);
///
/// pgp_tpk_free (tpk);
/// ```
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_revoke_in_place(errp: Option<&mut *mut failure::Error>,
                           tpk: *mut TPK,
                           primary_signer: *mut Box<crypto::Signer>,
                           code: c_int,
                           reason: Option<&c_char>)
                           -> Maybe<TPK>
{
    let tpk = tpk.move_from_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        ffi_param_cstr!(reason as *const c_char).to_bytes()
    } else {
        b""
    };

    tpk.revoke_in_place(signer.as_mut(), code, reason).move_into_raw(errp)
}

/// Returns whether the TPK has expired.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_expired(tpk: *const TPK)
                   -> c_int {
    let tpk = tpk.ref_raw();

    tpk.expired() as c_int
}

/// Returns whether the TPK has expired.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_expired_at(tpk: *const TPK, when: time_t)
                      -> c_int {
    let tpk = tpk.ref_raw();
    tpk.expired_at(time::at(time::Timespec::new(when as i64, 0))) as c_int
}

/// Returns whether the TPK is alive.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_alive(tpk: *const TPK)
                 -> c_int {
    let tpk = tpk.ref_raw();

    tpk.alive() as c_int
}

/// Returns whether the TPK is alive at the specified time.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_alive_at(tpk: *const TPK, when: time_t)
                    -> c_int {
    let tpk = tpk.ref_raw();
    tpk.alive_at(time::at(time::Timespec::new(when as i64, 0))) as c_int
}

/// Changes the TPK's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `tpk` and returns a new `TPK`.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_set_expiry(errp: Option<&mut *mut failure::Error>,
                      tpk: *mut TPK, expiry: u32)
                      -> Maybe<TPK> {
    let tpk = tpk.move_from_raw();

    tpk.set_expiry_in_seconds(expiry).move_into_raw(errp)
}

/// Returns whether the TPK includes any secret key material.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_is_tsk(tpk: *const TPK)
                  -> c_int {
    let tpk = tpk.ref_raw();
    tpk.is_tsk() as c_int
}

/// Returns an iterator over the TPK's user id bindings.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tpk_primary_user_id(tpk: *const TPK)
                           -> *mut c_char
{
    let tpk = tpk.ref_raw();
    if let Some(binding) = tpk.userids().nth(0) {
        ffi_return_string!(binding.userid().userid())
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_id_binding_user_id(
    binding: *const UserIDBinding)
    -> *mut c_char
{
    let binding = ffi_param_ref!(binding);

    ffi_return_maybe_string!(binding.userid().userid())
}

/// Returns a reference to the self-signature, if any.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_id_binding_selfsig(
    binding: *const UserIDBinding)
    -> Option<&'static Signature>
{
    let binding = ffi_param_ref!(binding);
    binding.binding_signature()
}


/* UserIDBindingIter */

/// Returns an iterator over the TPK's user id bindings.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_user_id_binding_iter(tpk: *const TPK)
    -> *mut UserIDBindingIter<'static>
{
    let tpk = tpk.ref_raw();
    box_raw!(tpk.userids())
}

/// Frees a pgp_user_id_binding_iter_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_id_binding_iter_free(
    iter: Option<&mut UserIDBindingIter>)
{
    ffi_free!(iter)
}

/// Returns the next `UserIDBinding`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_id_binding_iter_next<'a>(
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_key_iter(tpk: *const TPK)
    -> *mut KeyIterWrapper<'static>
{
    let tpk = tpk.ref_raw();
    box_raw!(KeyIterWrapper {
        iter: tpk.keys(),
        rso: None,
    })
}

/// Frees a pgp_tpk_key_iter_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_key_iter_free(
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_key_iter_next<'a>(
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

/// Creates a default `pgp_tpk_builder_t`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_tpk_builder_t builder;
/// pgp_tpk_t tpk;
/// pgp_signature_t revocation;
///
/// builder = pgp_tpk_builder_default ();
/// pgp_tpk_builder_set_cipher_suite (&builder, PGP_TPK_CIPHER_SUITE_CV25519);
/// pgp_tpk_builder_add_userid (&builder, "some@example.org");
/// pgp_tpk_builder_add_signing_subkey (&builder);
/// pgp_tpk_builder_add_encryption_subkey (&builder);
/// pgp_tpk_builder_generate (NULL, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
///
/// /* Use the TPK.  */
///
/// pgp_signature_free (revocation);
/// pgp_tpk_free (tpk);
/// ```
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_default() -> *mut TPKBuilder {
    box_raw!(TPKBuilder::default())
}

/// Generates a key compliant to [Autocrypt Level 1].
///
/// Autocrypt requires a user id, however, if `uid` is NULL, a TPK is
/// created without any user ids.  It is then the caller's
/// responsibility to ensure that a user id is added later.
///
/// `uid` must contain valid UTF-8.  If it does not contain valid
/// UTF-8, then the invalid code points are silently replaced with
/// `U+FFFD REPLACEMENT CHARACTER`.
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_autocrypt(uid: *const c_char)
    -> *mut TPKBuilder
{
    let uid = if uid.is_null() {
        None
    } else {
        Some(ffi_param_cstr!(uid).to_string_lossy())
    };
    box_raw!(TPKBuilder::autocrypt(Autocrypt::V1, uid))
}

/// Frees an `pgp_tpk_builder_t`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_free(tpkb: Option<&mut TPKBuilder>)
{
    ffi_free!(tpkb)
}

/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_set_cipher_suite
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
///
/// `uid` must contain valid UTF-8.  If it does not contain valid
/// UTF-8, then the invalid code points are silently replaced with
/// `U+FFFD REPLACEMENT CHARACTER`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_add_userid
    (tpkb: *mut *mut TPKBuilder, uid: *const c_char)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let uid = ffi_param_cstr!(uid).to_string_lossy();
    let tpkb_ = tpkb_.add_userid(uid);
    *tpkb = box_raw!(tpkb_);
}

/// Adds a signing capable subkey.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_add_signing_subkey
    (tpkb: *mut *mut TPKBuilder)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let tpkb_ = tpkb_.add_signing_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an encryption capable subkey.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_add_encryption_subkey
    (tpkb: *mut *mut TPKBuilder)
{
    let tpkb = ffi_param_ref_mut!(tpkb);
    let tpkb_ = ffi_param_move!(*tpkb);
    let tpkb_ = tpkb_.add_encryption_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an certification capable subkey.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_add_certification_subkey
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tpk_builder_generate
    (errp: Option<&mut *mut failure::Error>, tpkb: *mut TPKBuilder,
     tpk_out: *mut Maybe<TPK>,
     revocation_out: *mut *mut Signature)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let tpk_out = ffi_param_ref_mut!(tpk_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let tpkb = ffi_param_move!(tpkb);
    match tpkb.generate() {
        Ok((tpk, revocation)) => {
            *tpk_out = Some(tpk).move_into_raw();
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => {
            *tpk_out = None;
            ffi_try_status!(Err::<(), failure::Error>(e))
        },
    }
}
