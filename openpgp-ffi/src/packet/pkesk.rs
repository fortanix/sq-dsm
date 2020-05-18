//! Asymmetrically encrypted session keys.

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
/// The return value is a reference to a `KeyID`.  The caller must not
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

    match ffi_try_or_status!(secret_key.clone().parts_into_secret())
        .into_keypair()
    {
        Ok(mut keypair) => {
            match pkesk.decrypt(&mut keypair, None /* XXX */) {
                Some((a, k)) => {
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
                None => ffi_try_status!(Err::<(), anyhow::Error>(
                    openpgp::Error::InvalidSessionKey(
                        "Decryption failed".into()).into())),
            }
        },
        Err(e) => {
            ffi_try_status!(Err::<(), anyhow::Error>(
                    openpgp::Error::InvalidOperation(
                        format!("Unusable secret parts: {}", e)).into()))
        },
    }
}
