//! Asymmetrically encrypted session keys.

use failure;
use libc::size_t;

extern crate sequoia_openpgp as openpgp;
use self::openpgp::packet::PKESK;
use super::super::keyid::KeyID;
use super::super::packet::key::Key;

use crate::error::Status;

use crate::MoveIntoRaw;
use crate::RefRaw;

/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_pkesk_recipient(pkesk: *const PKESK)
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
pub extern "C" fn pgp_pkesk_decrypt(errp: Option<&mut *mut crate::error::Error>,
                                        pkesk: *const PKESK,
                                        secret_key: *const Key,
                                        algo: *mut u8, // XXX
                                        key: *mut u8,
                                        key_len: *mut size_t)
                                        -> Status {
    ffi_make_fry_from_errp!(errp);
    let pkesk = ffi_param_ref!(pkesk);
    let secret_key = secret_key.ref_raw();
    let algo = ffi_param_ref_mut!(algo);
    let key_len = ffi_param_ref_mut!(key_len);

    match secret_key.clone().mark_parts_secret().into_keypair() {
        Ok(mut keypair) => {
            match pkesk.decrypt(&mut keypair) {
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
        },
        Err(e) => {
            // XXX: Better message, don't panic.
            panic!("Secret parts not unencrypted in {:?}: {}", secret_key, e);
        },
    }
}
