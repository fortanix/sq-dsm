//! Cryptographic primitives.
//!
//! Wraps [`sequoia-openpgp::crypto`].
//!
//! [`sequoia-openpgp::crypto`]: ../../../sequoia_openpgp/crypto/index.html

use libc::size_t;

use sequoia_openpgp as openpgp;
use self::openpgp::{
    crypto,
};
use super::packet::key::Key;

use crate::MoveFromRaw;
use crate::MoveIntoRaw;

/// Holds a session key.
///
/// The session key is cleared when dropped.
#[crate::ffi_wrapper_type(prefix = "pgp_", name = "session_key",
                     derive = "Clone, Debug, PartialEq")]
pub struct SessionKey(openpgp::crypto::SessionKey);

/// Creates a new session key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_session_key_new(size: size_t) -> *mut SessionKey {
    openpgp::crypto::SessionKey::new(size)
        .move_into_raw()
}

/// Creates a new session key from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_session_key_from_bytes(buf: *const u8, size: size_t)
                              -> *mut SessionKey {
    let buf = unsafe {
        ::std::slice::from_raw_parts(buf, size)
    };
    openpgp::crypto::SessionKey::from(buf).move_into_raw()
}

/// Holds a password.
///
/// The password is cleared when dropped.
#[crate::ffi_wrapper_type(prefix = "pgp_", name = "password",
                     derive = "Clone, Debug, PartialEq")]
pub struct Password(openpgp::crypto::Password);

/// Creates a new password from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_password_from_bytes(buf: *const u8, size: size_t) -> *mut Password {
    let buf = unsafe {
        ::std::slice::from_raw_parts(buf, size)
    };
    openpgp::crypto::Password::from(buf).move_into_raw()
}

/// Frees a signer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_signer_free
    (s: Option<&mut Box<dyn crypto::Signer>>)
{
    ffi_free!(s)
}

/// Creates a new key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_key_pair_new
    (errp: Option<&mut *mut crate::error::Error>, public: *mut Key,
     secret: *mut openpgp::packet::key::Unencrypted)
     -> *mut crypto::KeyPair
{
    ffi_make_fry_from_errp!(errp);
    let public = public.move_from_raw();
    let secret = ffi_param_move!(secret);
    ffi_try_box!(crypto::KeyPair::new(public.into(), *secret))
}

/// Frees a key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_key_pair_free
    (kp: Option<&mut crypto::KeyPair>)
{
    ffi_free!(kp)
}

/// Creates a signer from a key pair.
///
/// Consumes the key pair.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_key_pair_as_signer
    (kp: *mut crypto::KeyPair)
     -> *mut Box<dyn crypto::Signer>
{
    let kp = ffi_param_move!(kp);
    let signer: Box<dyn crypto::Signer> = Box::new(*kp);
    // We cannot give out a raw pointer to the trait object, because
    // Rust insists they are not "FFI-safe".  So we need to box it
    // again.  Yuck.
    box_raw!(signer)
}
