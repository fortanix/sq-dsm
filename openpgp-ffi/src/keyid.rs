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

use std::slice;
use libc::{uint8_t, c_char};

extern crate sequoia_openpgp as openpgp;

use Maybe;

/// Holds a KeyID.
///
/// A KeyID is a fingerprint fragment.  It identifies a public key,
/// but is easy to forge.  For more details about how a KeyID is
/// generated, see [Section 12.2 of RFC 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
///
/// Wraps [`sequoia-openpgp::KeyID`].
///
/// [`sequoia-openpgp::KeyID`]: ../../sequoia_openpgp/enum.KeyID.html
#[::ffi_wrapper_type(prefix = "pgp_", name = "keyid",
                     derive = "Clone, Debug, Display, Hash, PartialEq")]
pub struct KeyID(openpgp::KeyID);

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
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_keyid_from_bytes(id: *const uint8_t) -> *mut KeyID {
    assert!(!id.is_null());
    let id = unsafe { slice::from_raw_parts(id, 8) };
    openpgp::KeyID::from_bytes(id).move_into_raw()
}

/// Reads a hex-encoded Key ID.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <stdlib.h>
/// #include <string.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_keyid_t mr_b = pgp_keyid_from_hex ("bbbbbbbbbbbbbbbb");
///
/// char *mr_b_as_string = pgp_keyid_to_string (mr_b);
/// assert (strcmp (mr_b_as_string, "BBBB BBBB BBBB BBBB") == 0);
///
/// free (mr_b_as_string);
/// pgp_keyid_free (mr_b);
/// ```
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_keyid_from_hex(id: *const c_char) -> Maybe<KeyID> {
    let id = ffi_param_cstr!(id).to_string_lossy();
    openpgp::KeyID::from_hex(&id).ok().move_into_raw()
}

/// Converts the KeyID to a hexadecimal number.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_keyid_to_hex(id: *const KeyID) -> *mut c_char {
    ffi_return_string!(id.ref_raw().to_hex())
}
