//! Handles KeyIDs.
//!
//! Wraps [`sequoia-openpgp::KeyID`].
//!
//! [`sequoia-openpgp::KeyID`]: ../../../sequoia_openpgp/enum.KeyID.html

use std::hash::{Hash, Hasher};
use std::ptr;
use std::slice;
use libc::{uint8_t, uint64_t, c_char};

extern crate sequoia_openpgp;
use self::sequoia_openpgp::KeyID;

use build_hasher;

/// Reads a binary key ID.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <stdlib.h>
/// #include <string.h>
/// #include <sequoia.h>
///
/// sq_keyid_t mr_b = sq_keyid_from_bytes ("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb");
///
/// char *mr_b_as_string = sq_keyid_to_string (mr_b);
/// assert (strcmp (mr_b_as_string, "BBBB BBBB BBBB BBBB") == 0);
///
/// sq_keyid_free (mr_b);
/// free (mr_b_as_string);
/// ```
#[no_mangle]
pub extern "system" fn sq_keyid_from_bytes(id: *const uint8_t) -> *mut KeyID {
    assert!(!id.is_null());
    let id = unsafe { slice::from_raw_parts(id, 8) };
    Box::into_raw(Box::new(KeyID::from_bytes(id)))
}

/// Reads a hex-encoded Key ID.
#[no_mangle]
pub extern "system" fn sq_keyid_from_hex(id: *const c_char) -> *mut KeyID {
    let id = ffi_param_cstr!(id).to_string_lossy();
    KeyID::from_hex(&id)
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}

/// Frees an `KeyID` object.
#[no_mangle]
pub extern "system" fn sq_keyid_free(keyid: Option<&mut KeyID>) {
    ffi_free!(keyid)
}

/// Clones the KeyID.
#[no_mangle]
pub extern "system" fn sq_keyid_clone(id: *const KeyID)
                                      -> *mut KeyID {
    let id = ffi_param_ref!(id);
    box_raw!(id.clone())
}

/// Hashes the KeyID.
#[no_mangle]
pub extern "system" fn sq_keyid_hash(id: *const KeyID)
                                     -> uint64_t {
    let id = ffi_param_ref!(id);
    let mut hasher = build_hasher();
    id.hash(&mut hasher);
    hasher.finish()
}

/// Converts the KeyID to its standard representation.
#[no_mangle]
pub extern "system" fn sq_keyid_to_string(id: *const KeyID)
                                          -> *mut c_char {
    let id = ffi_param_ref!(id);
    ffi_return_string!(id.to_string())
}

/// Converts the KeyID to a hexadecimal number.
#[no_mangle]
pub extern "system" fn sq_keyid_to_hex(id: *const KeyID)
                                       -> *mut c_char {
    let id = ffi_param_ref!(id);
    ffi_return_string!(id.to_hex())
}

/// Compares KeyIDs.
#[no_mangle]
pub extern "system" fn sq_keyid_equal(a: *const KeyID,
                                      b: *const KeyID)
                                      -> bool {
    let a = ffi_param_ref!(a);
    let b = ffi_param_ref!(b);
    a == b
}
