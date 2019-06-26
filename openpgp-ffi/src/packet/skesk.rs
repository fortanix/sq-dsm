//! Symmetrically encrypted session keys.

use std::slice;
use libc::size_t;

use failure;
extern crate sequoia_openpgp as openpgp;
use super::Packet;

use error::Status;
use RefRaw;

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_skesk_decrypt(errp: Option<&mut *mut ::error::Error>,
                                        skesk: *const Packet,
                                        password: *const u8,
                                        password_len: size_t,
                                        algo: *mut u8, // XXX
                                        key: *mut u8,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    if let &openpgp::Packet::SKESK(ref skesk) = skesk.ref_raw() {
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
