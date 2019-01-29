//! Transferable secret keys.
//!
//! Wraps [`sequoia-openpgp::TSK`].
//!
//! [`sequoia-openpgp::TSK`]: ../../sequoia_openpgp/struct.TSK.html

use failure;
use libc::c_char;

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    packet::Signature,
    parse::Parse,
    serialize::Serialize,
};

use super::tpk::TPK;
use ::error::Status;

/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
///
/// Wraps [`sequoia-openpgp::TSK`].
///
/// [`sequoia-openpgp::TSK`]: ../../sequoia_openpgp/enum.TSK.html
#[::ffi_wrapper_type(prefix = "pgp_", name = "tsk",
                     derive = "Clone, Debug, PartialEq, Parse, Serialize")]
pub struct TSK(openpgp::TSK);

/// Generates a new RSA 3072 bit key with UID `primary_uid`.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tsk_new(errp: Option<&mut *mut ::error::Error>,
               primary_uid: *const c_char,
               tsk_out: *mut *mut TSK,
               revocation_out: *mut *mut Signature)
               -> Status
{
    let tsk_out = ffi_param_ref_mut!(tsk_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let primary_uid = ffi_param_cstr!(primary_uid).to_string_lossy();
    match openpgp::TSK::new(primary_uid) {
        Ok((tsk, revocation)) => {
            *tsk_out = tsk.move_into_raw();
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => Err::<(), failure::Error>(e).move_into_raw(errp),
    }
}

/// Returns a reference to the corresponding TPK.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tsk_tpk(tsk: *const TSK)
               -> *const TPK {
    tsk.ref_raw().tpk().move_into_raw()
}

/// Converts the TSK into a TPK.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tsk_into_tpk(tsk: *mut TSK)
                    -> *mut TPK {
    tsk.move_from_raw().into_tpk().move_into_raw()
}
