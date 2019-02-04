//! Cryptographic primitives.
//!
//! Wraps [`sequoia-openpgp::crypto`].
//!
//! [`sequoia-openpgp::crypto`]: ../../sequoia_openpgp/crypto/index.html

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    crypto,
    packet::Key,
};

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
    let public = ffi_param_move!(public);
    let secret = ffi_param_move!(secret);
    ffi_try_box!(crypto::KeyPair::new(*public, *secret))
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
