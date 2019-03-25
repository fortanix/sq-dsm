//! Cryptographic primitives.
//!
//! Wraps [`sequoia-openpgp::crypto`].
//!
//! [`sequoia-openpgp::crypto`]: ../../sequoia_openpgp/crypto/index.html

use libc::{size_t, uint8_t};
use nettle::Yarrow;

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    crypto,
};
use super::packet::key::Key;

use MoveFromRaw;
use MoveIntoRaw;

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[::ffi_wrapper_type(prefix = "pgp_", name = "session_key",
                     derive = "Clone, Debug, PartialEq")]
pub struct SessionKey(openpgp::crypto::SessionKey);

/// Creates a new session key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_session_key_new(size: size_t) -> *mut SessionKey {
    openpgp::crypto::SessionKey::new(&mut Yarrow::default(), size)
        .move_into_raw()
}

/// Creates a new session key from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_session_key_from_bytes(buf: *const uint8_t, size: size_t)
                              -> *mut SessionKey {
    let buf = unsafe {
        ::std::slice::from_raw_parts(buf, size)
    };
    openpgp::crypto::SessionKey::from(buf).move_into_raw()
}

/// Holds a password.
///
/// The password is cleared when dropped.
#[::ffi_wrapper_type(prefix = "pgp_", name = "password",
                     derive = "Clone, Debug, PartialEq")]
pub struct Password(openpgp::crypto::Password);

/// Creates a new password from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_password_from_bytes(buf: *const uint8_t, size: size_t) -> *mut Password {
    let buf = unsafe {
        ::std::slice::from_raw_parts(buf, size)
    };
    openpgp::crypto::Password::from(buf).move_into_raw()
}

/// Frees a signer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_signer_free
    (s: Option<&mut &'static mut crypto::Signer>)
{
    ffi_free!(s)
}

/// Creates a new key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_key_pair_new
    (errp: Option<&mut *mut ::error::Error>, public: *mut Key, secret: *mut crypto::mpis::SecretKey)
     -> *mut crypto::KeyPair
{
    ffi_make_fry_from_errp!(errp);
    let public = public.move_from_raw();
    let secret = ffi_param_move!(secret);
    ffi_try_box!(crypto::KeyPair::new(public, *secret))
}

/// Frees a key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_key_pair_free
    (kp: Option<&mut crypto::KeyPair>)
{
    ffi_free!(kp)
}

/// Creates a signer from a key pair.
///
/// Note that the returned object merely references the key pair, and
/// must not outlive the key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_key_pair_as_signer
    (kp: *mut crypto::KeyPair)
     -> *mut &'static mut crypto::Signer
{
    let kp = ffi_param_ref_mut!(kp);
    let signer: &mut crypto::Signer = kp;
    box_raw!(signer)
    //box_raw!(kp)
}
