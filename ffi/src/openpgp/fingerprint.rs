//! Handles Fingerprints.
//!
//! Wraps [`sequoia-openpgp::Fingerprint`].
//!
//! [`sequoia-openpgp::Fingerprint`]: ../../../sequoia_openpgp/enum.Fingerprint.html

use std::ffi::{CString, CStr};
use std::hash::{Hash, Hasher};
use std::ptr;
use std::slice;
use libc::{uint8_t, uint64_t, c_char, size_t};

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{Fingerprint, KeyID};

use build_hasher;

/// Reads a binary fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_from_bytes(buf: *const uint8_t,
                                                 len: size_t)
                                                 -> *mut Fingerprint {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    Box::into_raw(Box::new(Fingerprint::from_bytes(buf)))
}

/// Reads a hexadecimal fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_from_hex(hex: *const c_char)
                                               -> *mut Fingerprint {
    assert!(!hex.is_null());
    let hex = unsafe { CStr::from_ptr(hex).to_string_lossy() };
    Fingerprint::from_hex(&hex)
        .map(|fp| Box::into_raw(Box::new(fp)))
        .unwrap_or(ptr::null_mut())
}

/// Frees a sq_fingerprint_t.
#[no_mangle]
pub extern "system" fn sq_fingerprint_free(fp: *mut Fingerprint) {
    ffi_free!(fp)
}

/// Clones the Fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_clone(fp: *const Fingerprint)
                                            -> *mut Fingerprint {
    let fp = ffi_param_ref!(fp);
    box_raw!(fp.clone())
}

/// Hashes the Fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_hash(fp: *const Fingerprint)
                                           -> uint64_t {
    let fp = ffi_param_ref!(fp);
    let mut hasher = build_hasher();
    fp.hash(&mut hasher);
    hasher.finish()
}

/// Returns a reference to the raw Fingerprint.
///
/// This returns a reference to the internal buffer that is valid as
/// long as the fingerprint is.
#[no_mangle]
pub extern "system" fn sq_fingerprint_as_bytes(fp: *const Fingerprint,
                                               fp_len: Option<&mut size_t>)
                                             -> *const uint8_t {
    let fp = ffi_param_ref!(fp);
    if let Some(p) = fp_len {
        *p = fp.as_slice().len();
    }
    fp.as_slice().as_ptr()
}

/// Converts the fingerprint to its standard representation.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_string(fp: *const Fingerprint)
                                                -> *mut c_char {
    let fp = ffi_param_ref!(fp);
    CString::new(fp.to_string())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Converts the fingerprint to a hexadecimal number.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_hex(fp: *const Fingerprint)
                                             -> *mut c_char {
    let fp = ffi_param_ref!(fp);
    CString::new(fp.to_hex())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Converts the fingerprint to a key ID.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_keyid(fp: *const Fingerprint)
                                               -> *mut KeyID {
    let fp = ffi_param_ref!(fp);
    Box::into_raw(Box::new(fp.to_keyid()))
}

/// Compares Fingerprints.
#[no_mangle]
pub extern "system" fn sq_fingerprint_equal(a: *const Fingerprint,
                                            b: *const Fingerprint)
                                            -> bool {
    let a = ffi_param_ref!(a);
    let b = ffi_param_ref!(b);
    a == b
}
