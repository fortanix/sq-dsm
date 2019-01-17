// Common code for sequoia-openpgp-ffi and sequoia-ffi.

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;

/* Canonical free().  */

/// Transfers ownership from C to Rust, then frees the object.
///
/// NOP if called with NULL.
macro_rules! ffi_free {
    ($name:ident) => {{
        if let Some(ptr) = $name {
            unsafe {
                drop(Box::from_raw(ptr))
            }
        }
    }};
}

/* Parameter handling.  */

/// Transfers ownership from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_move {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            Box::from_raw($name)
        }
    }};
}

/// Transfers a reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &*$name
        }
    }};
}

/// Transfers a mutable reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref_mut {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &mut *$name
        }
    }};
}

/// Transfers a reference to a string from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_cstr {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            ::std::ffi::CStr::from_ptr($name)
        }
    }};
}

/* Return value handling.  */

/// Duplicates a string similar to strndup(3).
#[allow(dead_code)]
pub(crate) fn strndup(src: &[u8]) -> Option<*mut libc::c_char> {
    if src.contains(&0) {
        return None;
    }

    let l = src.len() + 1;
    let s = unsafe {
        ::std::slice::from_raw_parts_mut(libc::malloc(l) as *mut u8, l)
    };
    &mut s[..l - 1].copy_from_slice(src);
    s[l - 1] = 0;

    Some(s.as_mut_ptr() as *mut libc::c_char)
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Panics if the given string contains a 0.
macro_rules! ffi_return_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).expect(
            &format!("Returned string {} contains a 0 byte.", stringify!($name))
        )
    }};
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Does *NOT* panic if the given string contains a 0, but returns
/// `NULL`.
macro_rules! ffi_return_maybe_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).unwrap_or(::std::ptr::null_mut())
    }};
}

/* Error handling with implicit error return argument.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_errp {
    ($errp:expr) => {
        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  On success, evaluate to
        /// `Status.Success`.  On failure, stashes the error in the
        /// context and evaluates to the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_status {
            ($expr:expr) => {
                match $expr {
                    Ok(_) => Status::Success,
                    Err(e) => {
                        let status = Status::from(&e);
                        if let Some(errp) = $errp {
                            *errp = box_raw!(e);
                        }
                        status
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns $or.
        #[allow(unused_macros)]
        macro_rules! ffi_try_or {
            ($expr:expr, $or:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        if let Some(errp) = $errp {
                            *errp = box_raw!(e);
                        }
                        return $or;
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try {
            ($expr:expr) => {
                ffi_try_or!($expr, ::std::ptr::null_mut())
            };
        }

        /// Like try! for ffi glue, then box into raw pointer.
        ///
        /// This is used to transfer ownership from Rust to C.
        ///
        /// Unwraps the given expression.  On success, it boxes the
        /// value and turns it into a raw pointer.  On failure,
        /// stashes the error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try_box {
            ($expr:expr) => {
                Box::into_raw(Box::new(ffi_try!($expr)))
            }
        }
    }
}

/// Box, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! box_raw {
    ($expr:expr) => {
        Box::into_raw(Box::new($expr))
    }
}

/// Box an Option<T>, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! maybe_box_raw {
    ($expr:expr) => {
        $expr.map(|x| box_raw!(x)).unwrap_or(ptr::null_mut())
    }
}

/// Builds hashers for computing hashes.
///
/// This is used to derive Hasher instances for computing hashes of
/// objects so that they can be used in hash tables by foreign code.
pub(crate) fn build_hasher() -> DefaultHasher {
    lazy_static! {
        static ref RANDOM_STATE: RandomState = RandomState::new();
    }
    RANDOM_STATE.build_hasher()
}

pub mod armor;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod io;
pub mod keyid;
pub mod packet_pile;
pub mod tpk;
pub mod tsk;

use std::mem::forget;
use std::ptr;
use std::slice;
use std::io as std_io;
use std::io::{Read, Write};
use libc::{uint8_t, c_char, c_int, size_t, ssize_t, c_void, time_t};
use failure::ResultExt;

extern crate sequoia_openpgp as openpgp;
extern crate time;

use self::openpgp::{
    Fingerprint,
    KeyID,
    RevocationStatus,
    TPK,
    Packet,
    packet::{
        Signature,
        Tag,
        PKESK,
        SKESK,
        key::SecretKey,
    },
    crypto::Password,
};
use self::openpgp::packet;
use self::openpgp::parse::{
    Parse,
    PacketParserResult,
    PacketParser,
    PacketParserEOF,
};
use self::openpgp::parse::stream::{
    DecryptionHelper,
    Decryptor,
    Secret,
    VerificationHelper,
    VerificationResult,
    Verifier,
    DetachedVerifier,
};
use self::openpgp::constants::{
    DataFormat,
};

use error::Status;


/* openpgp::packet::Tag.  */

/// Returns a human-readable tag name.
///
/// ```c
/// #include <assert.h>
/// #include <string.h>
/// #include <sequoia/openpgp.h>
///
/// assert (strcmp (pgp_tag_to_string (2), "SIGNATURE") == 0);
/// ```
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tag_to_string(tag: u8) -> *const c_char {
    match Tag::from(tag) {
        Tag::PKESK => "PKESK\x00",
        Tag::Signature => "SIGNATURE\x00",
        Tag::SKESK => "SKESK\x00",
        Tag::OnePassSig => "ONE PASS SIG\x00",
        Tag::SecretKey => "SECRET KEY\x00",
        Tag::PublicKey => "PUBLIC KEY\x00",
        Tag::SecretSubkey => "SECRET SUBKEY\x00",
        Tag::CompressedData => "COMPRESSED DATA\x00",
        Tag::SED => "SED\x00",
        Tag::Marker => "MARKER\x00",
        Tag::Literal => "LITERAL\x00",
        Tag::Trust => "TRUST\x00",
        Tag::UserID => "USER ID\x00",
        Tag::PublicSubkey => "PUBLIC SUBKEY\x00",
        Tag::UserAttribute => "USER ATTRIBUTE\x00",
        Tag::SEIP => "SEIP\x00",
        Tag::MDC => "MDC\x00",
        _ => "OTHER\x00",
    }.as_bytes().as_ptr() as *const c_char
}

fn revocation_status_to_int(rs: &RevocationStatus) -> c_int {
    match rs {
        RevocationStatus::Revoked(_) => 0,
        RevocationStatus::CouldBe(_) => 1,
        RevocationStatus::NotAsFarAsWeKnow => 2,
    }
}

/// Returns the TPK's revocation status variant.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_revocation_status_variant(
    rs: *mut RevocationStatus)
    -> c_int
{
    let rs = ffi_param_move!(rs);
    let variant = revocation_status_to_int(rs.as_ref());
    Box::into_raw(rs);
    variant
}

/// Frees a pgp_revocation_status_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_revocation_status_free(
    rs: Option<&mut RevocationStatus>)
{
    ffi_free!(rs)
}

/* openpgp::Packet.  */

/// Frees the Packet.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_free(p: Option<&mut Packet>) {
    ffi_free!(p)
}

/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_tag(p: *const Packet)
                                     -> uint8_t {
    let p = ffi_param_ref!(p);
    let tag: u8 = p.tag().into();
    tag as uint8_t
}

/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `PGP_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_kind(p: *const Packet)
                                      -> uint8_t {
    let p = ffi_param_ref!(p);
    if let Some(kind) = p.kind() {
        kind.into()
    } else {
        0
    }
}

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


/// Clones the key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_clone(key: *const packet::Key)
                                      -> *mut packet::Key {
    let key = ffi_param_ref!(key);
    box_raw!(key.clone())
}

/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_fingerprint(key: *const packet::Key)
                                            -> *mut Fingerprint {
    let key = ffi_param_ref!(key);
    box_raw!(key.fingerprint())
}

/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_keyid(key: *const packet::Key)
                                      -> *mut KeyID {
    let key = ffi_param_ref!(key);
    box_raw!(key.keyid())
}

/// Returns whether the key is expired according to the provided
/// self-signature.
///
/// Note: this is with respect to the provided signature, which is not
/// checked for validity.  That is, we do not check whether the
/// signature is a valid self-signature for the given key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_expired(key: *const packet::Key,
                                      sig: *const packet::Signature)
    -> bool
{
    let key = ffi_param_ref!(key);
    let sig = ffi_param_ref!(sig);

    sig.key_expired(key)
}

/// Like pgp_p_key_expired, but at a specific time.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_expired_at(key: *const packet::Key,
                                         sig: *const packet::Signature,
                                         when: time_t)
    -> bool
{
    let key = ffi_param_ref!(key);
    let sig = ffi_param_ref!(sig);

    sig.key_expired_at(key, time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns whether the key is alive according to the provided
/// self-signature.
///
/// A key is alive if the creation date is in the past, and the key
/// has not expired.
///
/// Note: this is with respect to the provided signature, which is not
/// checked for validity.  That is, we do not check whether the
/// signature is a valid self-signature for the given key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_alive(key: *const packet::Key,
                                      sig: *const packet::Signature)
    -> bool
{
    let key = ffi_param_ref!(key);
    let sig = ffi_param_ref!(sig);

    sig.key_alive(key)
}

/// Like pgp_p_key_alive, but at a specific time.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_alive_at(key: *const packet::Key,
                                         sig: *const packet::Signature,
                                         when: time_t)
    -> bool
{
    let key = ffi_param_ref!(key);
    let sig = ffi_param_ref!(sig);

    sig.key_alive_at(key, time::at(time::Timespec::new(when as i64, 0)))
}

/// Returns the key's creation time.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_creation_time(key: *const packet::Key)
    -> u32
{
    let key = ffi_param_ref!(key);
    let ct = key.creation_time();

    ct.to_timespec().sec as u32
}

/// Returns the key's public key algorithm.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_public_key_algo(key: *const packet::Key)
    -> c_int
{
    let key = ffi_param_ref!(key);
    let pk_algo : u8 = key.pk_algo().into();
    pk_algo as c_int
}

/// Returns the public key's size in bits.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_public_key_bits(key: *const packet::Key)
    -> c_int
{
    use self::openpgp::crypto::mpis::PublicKey::*;

    let key = ffi_param_ref!(key);
    match key.mpis() {
        RSA { e: _, n } => n.bits as c_int,
        DSA { p: _, q: _, g: _, y } => y.bits as c_int,
        Elgamal { p: _, g: _, y } => y.bits as c_int,
        EdDSA { curve: _, q } => q.bits as c_int,
        ECDSA { curve: _, q } =>  q.bits as c_int,
        ECDH { curve: _, q, hash: _, sym: _ } =>  q.bits as c_int,
        Unknown { mpis: _, rest: _ } => 0,
    }
}

/// Creates a new key pair from a Key packet with an unencrypted
/// secret key.
///
/// # Errors
///
/// Fails if the secret key is missing, or encrypted.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_p_key_into_key_pair(errp: Option<&mut *mut failure::Error>,
                                              key: *mut packet::Key)
                                              -> *mut self::openpgp::crypto::KeyPair
{
    ffi_make_fry_from_errp!(errp);
    let key = ffi_param_move!(key);
    ffi_try_box!(key.into_keypair())
}

/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_id_value(uid: *const Packet,
                                        value_len: Option<&mut size_t>)
                                        -> *const uint8_t {
    let uid = ffi_param_ref!(uid);
    if let &Packet::UserID(ref uid) = uid {
        if let Some(p) = value_len {
            *p = uid.userid().len();
        }
        uid.userid().as_ptr()
    } else {
        panic!("Not a UserID packet");
    }
}

/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_attribute_value(ua: *const Packet,
                                               value_len: Option<&mut size_t>)
                                               -> *const uint8_t {
    let ua = ffi_param_ref!(ua);
    if let &Packet::UserAttribute(ref ua) = ua {
        if let Some(p) = value_len {
            *p = ua.user_attribute().len();
        }
        ua.user_attribute().as_ptr()
    } else {
        panic!("Not a UserAttribute packet");
    }
}

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_skesk_decrypt(errp: Option<&mut *mut failure::Error>,
                                        skesk: *const Packet,
                                        password: *const uint8_t,
                                        password_len: size_t,
                                        algo: *mut uint8_t, // XXX
                                        key: *mut uint8_t,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let skesk = ffi_param_ref!(skesk);
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    if let &Packet::SKESK(ref skesk) = skesk {
        match skesk.decrypt(&password.to_owned().into()) {
            Ok((a, k)) => {
                *algo = a.into();
                if !key.is_null() && *key_len >= k.len() {
                    unsafe {
                        ::std::ptr::copy(k.as_ptr(),
                                         key,
                                         k.len());
                    }
                }
                *key_len = k.len();
                Status::Success
            },
            Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
        }
    } else {
        panic!("Not a SKESK packet");
    }
}

/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_pkesk_recipient(pkesk: *const PKESK)
                                          -> *const KeyID {
    let pkesk = ffi_param_ref!(pkesk);
    pkesk.recipient()
}

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_pkesk_decrypt(errp: Option<&mut *mut failure::Error>,
                                        pkesk: *const PKESK,
                                        secret_key: *const packet::Key,
                                        algo: *mut uint8_t, // XXX
                                        key: *mut uint8_t,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let pkesk = ffi_param_ref!(pkesk);
    let secret_key = ffi_param_ref!(secret_key);
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    if let Some(SecretKey::Unencrypted{ mpis: ref secret_part }) = secret_key.secret() {
        match pkesk.decrypt(secret_key, secret_part) {
            Ok((a, k)) => {
                *algo = a.into();
                if !key.is_null() && *key_len >= k.len() {
                    unsafe {
                        ::std::ptr::copy(k.as_ptr(),
                                         key,
                                         k.len());
                    }
                }
                *key_len = k.len();
                Status::Success
            },
            Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
        }
    } else {
        // XXX: Better message.
        panic!("No secret parts");
    }
}

/* openpgp::parse.  */

/// Starts parsing OpenPGP packets stored in a `pgp_reader_t`
/// object.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_from_reader<'a>
    (errp: Option<&mut *mut failure::Error>, reader: *mut Box<'a + Read>)
     -> *mut PacketParserResult<'a> {
    ffi_make_fry_from_errp!(errp);
    let reader = ffi_param_ref_mut!(reader);
    ffi_try_box!(PacketParser::from_reader(reader))
}

/// Starts parsing OpenPGP packets stored in a file named `path`.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_from_file
    (errp: Option<&mut *mut failure::Error>, filename: *const c_char)
     -> *mut PacketParserResult<'static> {
    ffi_make_fry_from_errp!(errp);
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    ffi_try_box!(PacketParser::from_file(&filename))
}

/// Starts parsing OpenPGP packets stored in a buffer.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_from_bytes
    (errp: Option<&mut *mut failure::Error>, b: *const uint8_t, len: size_t)
     -> *mut PacketParserResult<'static> {
    ffi_make_fry_from_errp!(errp);
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    ffi_try_box!(PacketParser::from_bytes(buf))
}

/// Frees the packet parser result
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_result_free(
    ppr: Option<&mut PacketParserResult>)
{
    ffi_free!(ppr)
}

/// Frees the packet parser.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_free(pp: Option<&mut PacketParser>) {
    ffi_free!(pp)
}

/// Frees the packet parser EOF object.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_eof_is_message(
    eof: *const PacketParserEOF) -> bool
{
    let eof = ffi_param_ref!(eof);

    eof.is_message()
}

/// Frees the packet parser EOF object.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_eof_free
    (eof: Option<&mut PacketParserEOF>)
{
    ffi_free!(eof)
}

/// Returns a reference to the packet that is being parsed.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_packet
    (pp: *const PacketParser)
     -> *const Packet {
    let pp = ffi_param_ref!(pp);
    &pp.packet
}

/// Returns the current packet's recursion depth.
///
/// A top-level packet has a recursion depth of 0.  Packets in a
/// top-level container have a recursion depth of 1, etc.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_recursion_depth
    (pp: *const PacketParser)
     -> uint8_t {
    let pp = ffi_param_ref!(pp);
    pp.recursion_depth() as u8
}

/// Finishes parsing the current packet and starts parsing the
/// following one.
///
/// This function finishes parsing the current packet.  By
/// default, any unread content is dropped.  (See
/// [`PacketParsererBuilder`] for how to configure this.)  It then
/// creates a new packet parser for the following packet.  If the
/// current packet is a container, this function does *not*
/// recurse into the container, but skips any packets it contains.
/// To recurse into the container, use the [`recurse()`] method.
///
///   [`PacketParsererBuilder`]: parse/struct.PacketParserBuilder.html
///   [`recurse()`]: #method.recurse
///
/// The return value is a tuple containing:
///
///   - A `Packet` holding the fully processed old packet;
///
///   - The old packet's recursion depth;
///
///   - A `PacketParser` holding the new packet;
///
///   - And, the recursion depth of the new packet.
///
/// A recursion depth of 0 means that the packet is a top-level
/// packet, a recursion depth of 1 means that the packet is an
/// immediate child of a top-level-packet, etc.
///
/// Since the packets are serialized in depth-first order and all
/// interior nodes are visited, we know that if the recursion
/// depth is the same, then the packets are siblings (they have a
/// common parent) and not, e.g., cousins (they have a common
/// grandparent).  This is because, if we move up the tree, the
/// only way to move back down is to first visit a new container
/// (e.g., an aunt).
///
/// Using the two positions, we can compute the change in depth as
/// new_depth - old_depth.  Thus, if the change in depth is 0, the
/// two packets are siblings.  If the value is 1, the old packet
/// is a container, and the new packet is its first child.  And,
/// if the value is -1, the new packet is contained in the old
/// packet's grandparent.  The idea is illustrated below:
///
/// ```text
///             ancestor
///             |       \
///            ...      -n
///             |
///           grandparent
///           |          \
///         parent       -1
///         |      \
///      packet    0
///         |
///         1
/// ```
///
/// Note: since this function does not automatically recurse into
/// a container, the change in depth will always be non-positive.
/// If the current container is empty, this function DOES pop that
/// container off the container stack, and returns the following
/// packet in the parent container.
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_next<'a>
    (errp: Option<&mut *mut failure::Error>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_move!(pp);

    match pp.next() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
    }
}

/// Finishes parsing the current packet and starts parsing the
/// next one, recursing if possible.
///
/// This method is similar to the [`next()`] method (see that
/// method for more details), but if the current packet is a
/// container (and we haven't reached the maximum recursion depth,
/// and the user hasn't started reading the packet's contents), we
/// recurse into the container, and return a `PacketParser` for
/// its first child.  Otherwise, we return the next packet in the
/// packet stream.  If this function recurses, then the new
/// packet's recursion depth will be `last_recursion_depth() + 1`;
/// because we always visit interior nodes, we can't recurse more
/// than one level at a time.
///
///   [`next()`]: #method.next
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_recurse<'a>
    (errp: Option<&mut *mut failure::Error>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_move!(pp);

    match pp.recurse() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
    }
}

/// Causes the PacketParser to buffer the packet's contents.
///
/// The packet's contents are stored in `packet.content`.  In
/// general, you should avoid buffering a packet's content and
/// prefer streaming its content unless you are certain that the
/// content is small.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_buffer_unread_content<'a>
    (errp: Option<&mut *mut failure::Error>,
     pp: *mut PacketParser<'a>,
     len: *mut usize)
     -> *const uint8_t {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    let len = ffi_param_ref_mut!(len);
    let buf = ffi_try!(pp.buffer_unread_content());
    *len = buf.len();
    buf.as_ptr()
}

/// Finishes parsing the current packet.
///
/// By default, this drops any unread content.  Use, for instance,
/// `PacketParserBuild` to customize the default behavior.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_finish<'a>
    (errp: Option<&mut *mut failure::Error>, pp: *mut PacketParser<'a>,
     packet: Option<&mut *const Packet>)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    match pp.finish() {
        Ok(p) => {
            if let Some(out_p) = packet {
                *out_p = p;
            }
            Status::Success
        },
        Err(e) => {
            let status = Status::from(&e);
            if let Some(errp) = errp {
                *errp = box_raw!(e);
            }
            status
        },
    }
}

/// Tries to decrypt the current packet.
///
/// On success, this function pushes one or more readers onto the
/// `PacketParser`'s reader stack, and sets the packet's
/// `decrypted` flag.
///
/// If this function is called on a packet that does not contain
/// encrypted data, or some of the data was already read, then it
/// returns `Error::InvalidOperation`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_decrypt<'a>
    (errp: Option<&mut *mut failure::Error>,
     pp: *mut PacketParser<'a>,
     algo: uint8_t, // XXX
     key: *const uint8_t, key_len: size_t)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    let key = unsafe {
        slice::from_raw_parts(key, key_len as usize)
    };
    let key = key.to_owned().into();
    ffi_try_status!(pp.decrypt((algo as u8).into(), &key))
}


/* PacketParserResult.  */

/// Returns the current packet's tag.
///
/// This is a convenience function to inspect the containing packet,
/// without turning the `PacketParserResult` into a `PacketParser`.
///
/// This function does not consume the ppr.
///
/// Returns 0 if the PacketParserResult does not contain a packet.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_result_tag<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> c_int
{
    let ppr = ffi_param_ref_mut!(ppr);

    let tag : u8 = match ppr {
        PacketParserResult::Some(ref pp) => pp.packet.tag().into(),
        PacketParserResult::EOF(_) => 0,
    };

    tag as c_int
}

/// If the `PacketParserResult` contains a `PacketParser`, returns it,
/// otherwise, returns NULL.
///
/// If the `PacketParser` reached EOF, then the `PacketParserResult`
/// contains a `PacketParserEOF` and you should use
/// `pgp_packet_parser_result_eof` to get it.
///
/// If this function returns a `PacketParser`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParser` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParser` is freed.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_result_packet_parser<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParser<'a>
{
    let ppr = ffi_param_move!(ppr);

    match *ppr {
        PacketParserResult::Some(pp) => box_raw!(pp),
        PacketParserResult::EOF(_) => {
            // Don't free ppr!
            forget(ppr);
            ptr::null_mut()
        }
    }
}

/// If the `PacketParserResult` contains a `PacketParserEOF`, returns
/// it, otherwise, returns NULL.
///
/// If the `PacketParser` did not yet reach EOF, then the
/// `PacketParserResult` contains a `PacketParser` and you should use
/// `pgp_packet_parser_result_packet_parser` to get it.
///
/// If this function returns a `PacketParserEOF`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParserEOF` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParserEOF` is freed.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_packet_parser_result_eof<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParserEOF
{
    let ppr = ffi_param_move!(ppr);

    match *ppr {
        PacketParserResult::Some(_) => {
            forget(ppr);
            ptr::null_mut()
        }
        PacketParserResult::EOF(eof) => box_raw!(eof),
    }
}

use self::openpgp::serialize::{
    writer,
    stream::{
        Message,
        Cookie,
        ArbitraryWriter,
        Signer,
        LiteralWriter,
        EncryptionMode,
        Encryptor,
    },
};


/// Streams an OpenPGP message.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_message
    (writer: *mut Box<Write>)
     -> *mut writer::Stack<'static, Cookie>
{
    let writer = ffi_param_move!(writer);
    box_raw!(Message::new(writer))
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_write
    (errp: Option<&mut *mut failure::Error>,
     writer: *mut writer::Stack<'static, Cookie>,
     buf: *const uint8_t, len: size_t)
     -> ssize_t
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_or!(writer.write(buf).map_err(|e| e.into()), -1) as ssize_t
}

/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike pgp_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_write_all
    (errp: Option<&mut *mut failure::Error>,
     writer: *mut writer::Stack<'static, Cookie>,
     buf: *const uint8_t, len: size_t)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_status!(writer.write_all(buf).map_err(|e| e.into()))
}

/// Finalizes this writer, returning the underlying writer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_finalize_one
    (errp: Option<&mut *mut failure::Error>,
     writer: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    if !writer.is_null() {
        let writer = ffi_param_move!(writer);
        maybe_box_raw!(ffi_try!(writer.finalize_one()))
    } else {
        ptr::null_mut()
    }
}

/// Finalizes all writers, tearing down the whole stack.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_finalize
    (errp: Option<&mut *mut failure::Error>,
     writer: *mut writer::Stack<'static, Cookie>)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    if !writer.is_null() {
        let writer = ffi_param_move!(writer);
        ffi_try_status!(writer.finalize())
    } else {
        Status::Success
    }
}

/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_arbitrary_writer_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     tag: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    ffi_try_box!(ArbitraryWriter::new(*inner, tag.into()))
}

/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signer_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let signers = signers.into_iter().map(
        |s| -> &mut dyn self::openpgp::crypto::Signer {
            let signer = *s;
            ffi_param_ref_mut!(signer).as_mut()
        }
    ).collect();
    ffi_try_box!(Signer::new(*inner, signers))
}

/// Creates a signer for a detached signature.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signer_new_detached
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let signers = signers.into_iter().map(
        |s| -> &mut dyn self::openpgp::crypto::Signer {
            let signer = *s;
            ffi_param_ref_mut!(signer).as_mut()
        }
    ).collect();
    ffi_try_box!(Signer::detached(*inner, signers))
}

/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_literal_writer_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    ffi_try_box!(LiteralWriter::new(*inner,
                                     DataFormat::Binary,
                                     None,
                                     None))
}

/// Creates a new encryptor.
///
/// The stream will be encrypted using a generated session key,
/// which will be encrypted using the given passwords, and all
/// encryption-capable subkeys of the given TPKs.
///
/// The stream is encrypted using AES256, regardless of any key
/// preferences.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_encryptor_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     passwords: Option<&*const c_char>, passwords_len: size_t,
     recipients: Option<&&TPK>, recipients_len: size_t,
     encryption_mode: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let mut passwords_ = Vec::new();
    if passwords_len > 0 {
        let passwords = passwords.expect("Passwords is NULL");
        let passwords = unsafe {
            slice::from_raw_parts(passwords, passwords_len)
        };
        for password in passwords {
            passwords_.push(ffi_param_cstr!(*password)
                            .to_bytes().to_owned().into());
        }
    }
    let recipients = if recipients_len > 0 {
        let recipients = recipients.expect("Recipients is NULL");
        unsafe {
            slice::from_raw_parts(recipients, recipients_len)
        }
    } else {
        &[]
    };
    let encryption_mode = match encryption_mode {
        0 => EncryptionMode::AtRest,
        1 => EncryptionMode::ForTransport,
        _ => panic!("Bad encryption mode: {}", encryption_mode),
    };
    ffi_try_box!(Encryptor::new(*inner,
                                 &passwords_.iter().collect::<Vec<&Password>>(),
                                 &recipients,
                                 encryption_mode))
}

// Secret.

/// Creates an pgp_secret_t from a decrypted session key.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_secret_cached<'a>(algo: u8,
                            session_key: *const u8,
                            session_key_len: size_t)
   -> *mut Secret
{
    let session_key = if session_key_len > 0 {
        unsafe {
            slice::from_raw_parts(session_key, session_key_len)
        }
    } else {
        &[]
    };

    box_raw!(Secret::Cached {
        algo: algo.into(),
        session_key: session_key.to_vec().into()
    })
}


// Decryptor.

/// A message's verification results.
///
/// Conceptually, the verification results are an array of an array of
/// VerificationResult.  The outer array is for the verification level
/// and is indexed by the verification level.  A verification level of
/// zero corresponds to direct signatures; A verification level of 1
/// corresponds to notorizations (i.e., signatures of signatures);
/// etc.
///
/// Within each level, there can be one or more signatures.
pub struct VerificationResults<'a> {
    results: Vec<Vec<&'a VerificationResult>>,
}

/// Returns the `VerificationResult`s at level `level.
///
/// Conceptually, the verification results are an array of an array of
/// VerificationResult.  The outer array is for the verification level
/// and is indexed by the verification level.  A verification level of
/// zero corresponds to direct signatures; A verification level of 1
/// corresponds to notorizations (i.e., signatures of signatures);
/// etc.
///
/// This function returns the verification results for a particular
/// level.  The result is an array of references to
/// `VerificationResult`.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_verification_results_at_level<'a>(results: *const VerificationResults<'a>,
                                            level: size_t,
                                            r: *mut *const &'a VerificationResult,
                                            r_count: *mut size_t) {
    let results = ffi_param_ref!(results);
    let r = ffi_param_ref_mut!(r);
    let r_count = ffi_param_ref_mut!(r_count);

    assert!(level < results.results.len());

    // The size of VerificationResult is not known in C.  Convert from
    // an array of VerificationResult to an array of
    // VerificationResult refs.
    *r = results.results[level].as_ptr();
    *r_count = results.results[level].len();
}

/// Returns the verification result code.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_verification_result_code(result: *const VerificationResult)
    -> c_int
{
    let result = ffi_param_ref!(result);
    match result {
        VerificationResult::GoodChecksum(_) => 1,
        VerificationResult::MissingKey(_) => 2,
        VerificationResult::BadChecksum(_) => 3,
    }
}

/// Returns the verification result code.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_verification_result_signature(result: *const VerificationResult)
    -> *const packet::Signature
{
    let result = ffi_param_ref!(result);
    let sig = match result {
        VerificationResult::GoodChecksum(ref sig) => sig,
        VerificationResult::MissingKey(ref sig) => sig,
        VerificationResult::BadChecksum(ref sig) => sig,
    };

    sig as *const packet::Signature
}

/// Returns the verification result code.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_verification_result_level(result: *const VerificationResult)
    -> c_int
{
    let result = ffi_param_ref!(result);
    result.level() as c_int
}


/// Passed as the first argument to the callbacks used by pgp_verify
/// and pgp_decrypt.
pub struct HelperCookie {
}

/// How to free the memory allocated by the callback.
type FreeCallback = fn(*mut c_void);

/// Returns the TPKs corresponding to the passed KeyIDs.
///
/// If the free callback is not NULL, then it is called to free the
/// returned array of TPKs.
type GetPublicKeysCallback = fn(*mut HelperCookie,
                                *const &KeyID, usize,
                                &mut *mut &mut TPK, *mut usize,
                                *mut FreeCallback) -> Status;

/// Returns a session key.
type GetSecretKeysCallback = fn(*mut HelperCookie,
                                *const &PKESK, usize,
                                *const &SKESK, usize,
                                &mut *mut Secret) -> Status;

/// Process the signatures.
///
/// If the result is not Status::Success, then this aborts the
/// Verification.
type CheckSignaturesCallback = fn(*mut HelperCookie,
                                  *const VerificationResults,
                                  usize) -> Status;

// This fetches keys and computes the validity of the verification.
struct VHelper {
    get_public_keys_cb: GetPublicKeysCallback,
    check_signatures_cb: CheckSignaturesCallback,
    cookie: *mut HelperCookie,
}

impl VHelper {
    fn new(get_public_keys: GetPublicKeysCallback,
           check_signatures: CheckSignaturesCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        VHelper {
            get_public_keys_cb: get_public_keys,
            check_signatures_cb: check_signatures,
            cookie: cookie,
        }
    }
}

impl VerificationHelper for VHelper {
    fn get_public_keys(&mut self, ids: &[KeyID])
        -> Result<Vec<TPK>, failure::Error>
    {
        // The size of KeyID is not known in C.  Convert from an array
        // of KeyIDs to an array of KeyID refs.
        let ids : Vec<&KeyID> = ids.iter().collect();

        let mut tpk_refs_raw : *mut &mut TPK = ptr::null_mut();
        let mut tpk_refs_raw_len = 0usize;

        let mut free : FreeCallback = |_| {};

        let result = (self.get_public_keys_cb)(
            self.cookie,
            ids.as_ptr(), ids.len(),
            &mut tpk_refs_raw, &mut tpk_refs_raw_len as *mut usize,
            &mut free);
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        // Convert the array of references to TPKs to a Vec<TPK>
        // (i.e., not a Vec<&TPK>).
        let mut tpks : Vec<TPK> = Vec::with_capacity(tpk_refs_raw_len);
        for i in 0..tpk_refs_raw_len {
            let tpk = unsafe { ptr::read(*tpk_refs_raw.offset(i as isize)) };
            tpks.push(tpk);
        }

        (free)(tpk_refs_raw as *mut c_void);

        Ok(tpks)
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
        -> Result<(), failure::Error>
    {
        // The size of VerificationResult is not known in C.  Convert
        // from an array of VerificationResults to an array of
        // VerificationResult refs.
        let results = VerificationResults {
            results: sigs.iter().map(
                |r| r.iter().collect::<Vec<&VerificationResult>>()).collect()
        };

        let result = (self.check_signatures_cb)(self.cookie,
                                                &results,
                                                results.results.len());
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        Ok(())
    }
}

fn verify_real<'a>(input: &'a mut Box<'a + Read>,
                   dsig: Option<&'a mut Box<'a + Read>>,
                   output: Option<&'a mut Box<'a + Write>>,
                   get_public_keys: GetPublicKeysCallback,
                   check_signatures: CheckSignaturesCallback,
                   cookie: *mut HelperCookie)
    -> Result<(), failure::Error>
{
    let h = VHelper::new(get_public_keys, check_signatures, cookie);
    let mut v = if let Some(dsig) = dsig {
        DetachedVerifier::from_reader(dsig, input, h)?
    } else {
        Verifier::from_reader(input, h)?
    };

    let r = if let Some(output) = output {
        std_io::copy(&mut v, output)
    } else {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match v.read(&mut buffer) {
                // EOF.
                Ok(0) => break Ok(0),
                // Some error.
                Err(err) => break Err(err),
                // Still something to read.
                Ok(_) => continue,
            }
        }
    };

    r.map_err(|e| if e.get_ref().is_some() {
        // Wrapped failure::Error.  Recover it.
        failure::Error::from_boxed_compat(e.into_inner().unwrap())
    } else {
        // Plain io::Error.
        e.into()
    }).context("Verification failed")?;

    Ok(())
}


/// Verifies an OpenPGP message.
///
/// No attempt is made to decrypt any encryption packets.  These are
/// treated as opaque containers.
///
/// Note: output may be NULL, if the output is not required.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_verify<'a>(errp: Option<&mut *mut failure::Error>,
                     input: *mut Box<'a + Read>,
                     dsig: Option<&'a mut Box<'a + Read>>,
                     output: Option<&'a mut Box<'a + Write>>,
                     get_public_keys: GetPublicKeysCallback,
                     check_signatures: CheckSignaturesCallback,
                     cookie: *mut HelperCookie)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let input = ffi_param_ref_mut!(input);

    let r = verify_real(input, dsig, output,
        get_public_keys, check_signatures, cookie);

    ffi_try_status!(r)
}


struct DHelper {
    vhelper: VHelper,
    get_secret_keys_cb: GetSecretKeysCallback,
}

impl DHelper {
    fn new(get_public_keys: GetPublicKeysCallback,
           get_secret_keys: GetSecretKeysCallback,
           check_signatures: CheckSignaturesCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        DHelper {
            vhelper: VHelper::new(get_public_keys, check_signatures, cookie),
            get_secret_keys_cb: get_secret_keys,
        }
    }
}

impl VerificationHelper for DHelper {
    fn get_public_keys(&mut self, ids: &[KeyID])
        -> Result<Vec<TPK>, failure::Error>
    {
        self.vhelper.get_public_keys(ids)
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
        -> Result<(), failure::Error>
    {
        self.vhelper.check(sigs)
    }
}

impl DecryptionHelper for DHelper {
    fn get_secret(&mut self, pkesks: &[&PKESK], skesks: &[&SKESK])
        -> Result<Option<Secret>, failure::Error>
    {
        let mut secret : *mut Secret = ptr::null_mut();

        let result = (self.get_secret_keys_cb)(
            self.vhelper.cookie,
            pkesks.as_ptr(), pkesks.len(), skesks.as_ptr(), skesks.len(),
            &mut secret);
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        if secret.is_null() {
            return Err(openpgp::Error::MissingSessionKey(
                "Callback did not return a session key".into()).into());
        }

        let secret = ffi_param_move!(secret);

        Ok(Some(*secret))
    }
}

// A helper function that returns a Result so that we can use ? to
// propagate errors.
fn decrypt_real<'a>(input: &'a mut Box<'a + Read>,
                    output: &'a mut Box<'a + Write>,
                    get_public_keys: GetPublicKeysCallback,
                    get_secret_keys: GetSecretKeysCallback,
                    check_signatures: CheckSignaturesCallback,
                    cookie: *mut HelperCookie)
    -> Result<(), failure::Error>
{
    let helper = DHelper::new(
        get_public_keys, get_secret_keys, check_signatures, cookie);

    let mut decryptor = Decryptor::from_reader(input, helper)
        .context("Decryption failed")?;

    std_io::copy(&mut decryptor, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            e.into()
        }).context("Decryption failed")?;

    Ok(())
}

/// Decrypts an OpenPGP message.
///
/// The message is read from `input` and the content of the
/// `LiteralData` packet is written to output.  Note: the content is
/// written even if the message is not encrypted.  You can determine
/// whether the message was actually decrypted by recording whether
/// the get_secret_keys callback was called in the cookie.
///
/// The function takes three callbacks.  The `cookie` is passed as the
/// first parameter to each of them.
///
/// Note: all of the parameters are required; none may be NULL.
#[::ffi_catch_abort] #[no_mangle]
pub fn pgp_decrypt<'a>(errp: Option<&mut *mut failure::Error>,
                      input: *mut Box<'a + Read>,
                      output: *mut Box<'a + Write>,
                      get_public_keys: GetPublicKeysCallback,
                      get_secret_keys: GetSecretKeysCallback,
                      check_signatures: CheckSignaturesCallback,
                      cookie: *mut HelperCookie)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let input = ffi_param_ref_mut!(input);
    let output = ffi_param_ref_mut!(output);

    let r = decrypt_real(input, output,
        get_public_keys, get_secret_keys, check_signatures, cookie);

    ffi_try_status!(r)
}
