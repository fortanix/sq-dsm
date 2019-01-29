//! Symmetrically encrypted session keys.

use std::slice;
use libc::{uint8_t, size_t};

use failure;
extern crate sequoia_openpgp as openpgp;
use self::openpgp::Packet;

use error::Status;

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_skesk_decrypt(errp: Option<&mut *mut ::error::Error>,
                                        skesk: *const Packet,
                                        password: *const uint8_t,
                                        password_len: size_t,
                                        algo: *mut uint8_t, // XXX
                                        key: *mut uint8_t,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let skesk = ffi_param_ref!(skesk);
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    if let &Packet::SKESK(ref skesk) = skesk {
        match skesk.decrypt(&password.to_owned().into()) {
            Ok((a, k)) => {
                *algo = a.into();
                if !key.is_null() && *key_len >= k.len() {
                    unsafe {
                        ::std::ptr::copy(k.as_ptr(),
                                         key,
                                         k.len());
                    }
                }
                *key_len = k.len();
                Status::Success
            },
            Err(e) => ffi_try_status!(Err::<(), failure::Error>(e)),
        }
    } else {
        panic!("Not a SKESK packet");
    }
}
