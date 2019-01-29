//! Transferable secret keys.
//!
//! Wraps [`sequoia-openpgp::TSK`].
//!
//! [`sequoia-openpgp::TSK`]: ../../sequoia_openpgp/struct.TSK.html

use failure;
use std::io::Write;
use libc::c_char;

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    TSK,
    packet::Signature,
    serialize::Serialize,
};

use super::tpk::TPK;
use ::error::Status;
use MoveIntoRaw;

/// Generates a new RSA 3072 bit key with UID `primary_uid`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tsk_new(errp: Option<&mut *mut failure::Error>,
                                  primary_uid: *const c_char,
                                  tsk_out: *mut *mut TSK,
                                  revocation_out: *mut *mut Signature)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let tsk_out = ffi_param_ref_mut!(tsk_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let primary_uid = ffi_param_cstr!(primary_uid).to_string_lossy();
    match TSK::new(primary_uid) {
        Ok((tsk, revocation)) => {
            *tsk_out = box_raw!(tsk);
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
    }
}

/// Frees the TSK.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tsk_free(tsk: Option<&mut TSK>) {
    ffi_free!(tsk)
}

/// Returns a reference to the corresponding TPK.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_tsk_tpk(tsk: *const TSK)
               -> *const TPK {
    ffi_param_ref!(tsk).tpk().move_into_raw()
}

/// Converts the TSK into a TPK.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tsk_into_tpk(tsk: *mut TSK)
                                       -> *mut TPK {
    ffi_param_move!(tsk).into_tpk().move_into_raw()
}


/// Serializes the TSK.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_tsk_serialize(errp: Option<&mut *mut failure::Error>,
                                        tsk: *const TSK,
                                        writer: *mut Box<Write>)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let tsk = ffi_param_ref!(tsk);
    let writer = ffi_param_ref_mut!(writer);
    ffi_try_status!(tsk.serialize(writer))
}
