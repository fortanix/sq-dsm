//! KeyIDs.
//!
//! A KeyID is a fingerprint fragment.  It identifies a public key,
//! but is easy to forge.  For more details about how a KeyID is
//! generated, see [Section 12.2 of RFC 4880].
//!
//!   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
//!
//! Wraps [`sequoia-openpgp::KeyID`].
//!
//! [`sequoia-openpgp::KeyID`]: ../../sequoia_openpgp/enum.KeyID.html

use std::hash::{Hash, Hasher};
use std::ptr;
use std::slice;
use libc::{uint8_t, uint64_t, c_char};

extern crate sequoia_openpgp as openpgp;

use build_hasher;

/// Reads a binary key ID.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <stdlib.h>
/// #include <string.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_keyid_t mr_b = pgp_keyid_from_bytes ("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb");
///
/// char *mr_b_as_string = pgp_keyid_to_string (mr_b);
/// assert (strcmp (mr_b_as_string, "BBBB BBBB BBBB BBBB") == 0);
///
/// pgp_keyid_free (mr_b);
/// free (mr_b_as_string);
/// ```
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_from_bytes(id: *const uint8_t) -> *mut openpgp::KeyID {
    assert!(!id.is_null());
    let id = unsafe { slice::from_raw_parts(id, 8) };
    Box::into_raw(Box::new(openpgp::KeyID::from_bytes(id)))
}

/// Reads a hex-encoded Key ID.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_from_hex(id: *const c_char) -> *mut openpgp::KeyID {
    let id = ffi_param_cstr!(id).to_string_lossy();
    openpgp::KeyID::from_hex(&id)
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}

/// Frees an `KeyID` object.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_free(keyid: Option<&mut openpgp::KeyID>) {
    ffi_free!(keyid)
}

/// Clones the KeyID.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_clone(id: *const openpgp::KeyID)
                                      -> *mut openpgp::KeyID {
    let id = ffi_param_ref!(id);
    box_raw!(id.clone())
}

/// Hashes the KeyID.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_hash(id: *const openpgp::KeyID)
                                     -> uint64_t {
    let id = ffi_param_ref!(id);
    let mut hasher = build_hasher();
    id.hash(&mut hasher);
    hasher.finish()
}

/// Converts the KeyID to its standard representation.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_to_string(id: *const openpgp::KeyID)
                                          -> *mut c_char {
    let id = ffi_param_ref!(id);
    ffi_return_string!(id.to_string())
}

/// Converts the KeyID to a hexadecimal number.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_to_hex(id: *const openpgp::KeyID)
                                       -> *mut c_char {
    let id = ffi_param_ref!(id);
    ffi_return_string!(id.to_hex())
}

/// Compares KeyIDs.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_keyid_equal(a: *const openpgp::KeyID,
                                       b: *const openpgp::KeyID)
                                      -> bool {
    let a = ffi_param_ref!(a);
    let b = ffi_param_ref!(b);
    a == b
}
