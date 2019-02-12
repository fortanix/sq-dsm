//! Asymmetrically encrypted session keys.

use failure;
use libc::{uint8_t, size_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::packet::{Key, PKESK, key::SecretKey};
use super::super::keyid::KeyID;

use error::Status;

use MoveIntoRaw;

/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_pkesk_recipient(pkesk: *const PKESK)
                                           -> *const KeyID {
    let pkesk = ffi_param_ref!(pkesk);
    pkesk.recipient().move_into_raw()
}

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_pkesk_decrypt(errp: Option<&mut *mut ::error::Error>,
                                        pkesk: *const PKESK,
                                        secret_key: *const Key,
                                        algo: *mut uint8_t, // XXX
                                        key: *mut uint8_t,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let pkesk = ffi_param_ref!(pkesk);
    let secret_key = ffi_param_ref!(secret_key);
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    if let Some(SecretKey::Unencrypted{ mpis: ref secret_part }) = secret_key.secret() {
        match pkesk.decrypt(secret_key, secret_part) {
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
        // XXX: Better message.
        panic!("No secret parts");
    }
}
