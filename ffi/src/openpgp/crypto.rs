//! Cryptographic primitives.
//!
//! Wraps [`sequoia-openpgp::crypto`].
//!
//! [`sequoia-openpgp::crypto`]: ../../../sequoia_openpgp/crypto/index.html

use ::core::Context;

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    crypto,
    packet::Key,
};

/// Frees a signer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_signer_free
    (s: Option<&mut &'static mut crypto::Signer>)
{
    ffi_free!(s)
}

/// Creates a new key pair.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_pair_new
    (ctx: *mut Context, public: *mut Key, secret: *mut crypto::mpis::SecretKey)
     -> *mut crypto::KeyPair
{
    let ctx = ffi_param_ref_mut!(ctx);
    let public = ffi_param_move!(public);
    let secret = ffi_param_move!(secret);
    fry_box!(ctx, crypto::KeyPair::new(*public, *secret))
}

/// Frees a key pair.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_pair_free
    (kp: Option<&mut crypto::KeyPair>)
{
    ffi_free!(kp)
}

/// Creates a signer from a key pair.
///
/// Note that the returned object merely references the key pair, and
/// must not outlive the key pair.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_pair_as_signer
    (kp: *mut crypto::KeyPair)
     -> *mut &'static mut crypto::Signer
{
    let kp = ffi_param_ref_mut!(kp);
    let signer: &mut crypto::Signer = kp;
    box_raw!(signer)
    //box_raw!(kp)
}
