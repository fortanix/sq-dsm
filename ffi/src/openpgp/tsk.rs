//! Handles TSKs.
//!
//! Wraps [`sequoia-openpgp::TSK`].
//!
//! [`sequoia-openpgp::TSK`]: ../../../sequoia_openpgp/struct.TSK.html

use failure;
use std::ffi::CStr;
use std::io::Write;
use libc::c_char;

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    TPK,
    TSK,
    packet::Signature,
    serialize::Serialize,
};

use ::core::Context;
use ::error::Status;

/// Generates a new RSA 3072 bit key with UID `primary_uid`.
#[no_mangle]
pub extern "system" fn sq_tsk_new(ctx: *mut Context,
                                  primary_uid: *const c_char,
                                  tsk_out: *mut *mut TSK,
                                  revocation_out: *mut *mut Signature)
    -> Status
{
    let ctx = ffi_param_ref_mut!(ctx);
    assert!(!primary_uid.is_null());
    let tsk_out = ffi_param_ref_mut!(tsk_out);
    let revocation_out = ffi_param_ref_mut!(revocation_out);
    let primary_uid = unsafe {
        CStr::from_ptr(primary_uid)
    };
    match TSK::new(primary_uid.to_string_lossy()) {
        Ok((tsk, revocation)) => {
            *tsk_out = box_raw!(tsk);
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}

/// Frees the TSK.
#[no_mangle]
pub extern "system" fn sq_tsk_free(tsk: Option<&mut TSK>) {
    ffi_free!(tsk)
}

/// Returns a reference to the corresponding TPK.
#[no_mangle]
pub extern "system" fn sq_tsk_tpk(tsk: *const TSK)
                                  -> *const TPK {
    let tsk = ffi_param_ref!(tsk);
    tsk.tpk()
}

/// Converts the TSK into a TPK.
#[no_mangle]
pub extern "system" fn sq_tsk_into_tpk(tsk: *mut TSK)
                                       -> *mut TPK {
    let tsk = ffi_param_move!(tsk);
    box_raw!(tsk.into_tpk())
}


/// Serializes the TSK.
#[no_mangle]
pub extern "system" fn sq_tsk_serialize(ctx: *mut Context,
                                        tsk: *const TSK,
                                        writer: *mut Box<Write>)
                                        -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    let tsk = ffi_param_ref!(tsk);
    let writer = ffi_param_ref_mut!(writer);
    fry_status!(ctx, tsk.serialize(writer))
}
