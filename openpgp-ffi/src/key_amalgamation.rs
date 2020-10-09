//! `KeyAmalgamation`s.
//!
//!
//! Wraps [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`].
//!
//! [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`]: ../../../sequoia_openpgp/cert/key_amalgamation/struct.KeyAmalgamation.html

use std::slice;
use libc::{size_t, time_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::packet::key;
use self::openpgp::cert::amalgamation::ValidAmalgamation;
use self::openpgp::cert::amalgamation::ValidateAmalgamation;
use self::openpgp::crypto;

use super::packet::key::Key;
use super::packet::signature::Signature;
use super::policy::Policy;
use super::revocation_status::RevocationStatus;

use crate::error::Status;
use crate::Maybe;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::RefRaw;
use crate::MoveFromRaw;
use crate::maybe_time;

/// A local alias to appease the proc macro transformation.
type ErasedKeyAmalgamation<'a> =
    openpgp::cert::amalgamation::key::ErasedKeyAmalgamation<'a, key::UnspecifiedParts>;

/// A `KeyAmalgamation` holds a `Key` and associated data.
///
/// Wraps [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`].
///
/// [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`]: ../../../sequoia_openpgp/cert/key_amalgamation/struct.KeyAmalgamation.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug")]
pub struct KeyAmalgamation<'a>(ErasedKeyAmalgamation<'a>);

/// A local alias to appease the proc macro transformation.
type ValidErasedKeyAmalgamation<'a> =
    openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation<'a, key::UnspecifiedParts>;

/// Returns a reference to the `Key`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_key_amalgamation_key<'a>(ka: *const KeyAmalgamation<'a>)
    -> *const Key
{
    let ka = ka.ref_raw();

    ka.key().parts_as_unspecified().role_as_unspecified()
        .move_into_raw()
}

/// A `ValidKeyAmalgamation` holds a `Key` and associated data
/// including a policy and a reference time.
///
/// Wraps [`sequoia-openpgp::cert::key_amalgamation::ValidKeyAmalgamation`].
///
/// [`sequoia-openpgp::cert::key_amalgamation::ValidKeyAmalgamation`]: ../../../sequoia_openpgp/cert/key_amalgamation/struct.ValidKeyAmalgamation.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug")]
pub struct ValidKeyAmalgamation<'a>(ValidErasedKeyAmalgamation<'a>);

/// Returns a reference to the `Key`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_key<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> *const Key
{
    let ka = ka.ref_raw();

    ka.key().parts_as_unspecified().role_as_unspecified()
        .move_into_raw()
}

/// Returns the Key Amalgamation's revocation status.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_revocation_status<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> *mut RevocationStatus<'a>
{
    ka.ref_raw()
        .revocation_status()
        .move_into_raw()
}

/// Returns the Key Amalgamation's binding signature.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_binding_signature<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> *const Signature
{
    ka.ref_raw()
        .binding_signature()
        .move_into_raw()
}

/// Returns whether the key is certification capable.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_for_certification<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> bool
{
    ka.ref_raw().for_certification()
}

/// Returns whether the key is signing capable.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_for_signing<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> bool
{
    ka.ref_raw().for_signing()
}

/// Returns whether the key is authentication capable.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_for_authentication<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> bool
{
    ka.ref_raw().for_authentication()
}

/// Returns whether the key is intended for encrypting data at rest.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_for_storage_encryption<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> bool
{
    ka.ref_raw().for_storage_encryption()
}

/// Returns whether the key is intended for encrypting data in transit.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_for_transport_encryption<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> bool
{
    ka.ref_raw().for_transport_encryption()
}

/// Creates one or more self-signatures that when merged with the
/// certificate cause the key to expire at the specified time.
///
/// `subkey_signer` must be `NULL` when updating the expiration of the
/// primary key, or updating the expiration of a non-signing capable
/// subkey.  Otherwise, a signer for the subkey must be given.
///
/// The returned buffer must be freed using libc's allocator.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_valid_key_amalgamation_set_expiration_time(
    errp: Option<&mut *mut crate::error::Error>,
    ka: *const ValidKeyAmalgamation,
    primary_signer: *mut Box<dyn crypto::Signer>,
    subkey_signer: Option<&'static mut Box<dyn crypto::Signer + 'static>>,
    expiry: time_t,
    sigs: *mut *mut *mut Signature, sig_count: *mut size_t)
    -> Status
{
    ffi_make_fry_from_errp!(errp);

    let ka = ka.ref_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let expiry = maybe_time(expiry);
    let sigs = ffi_param_ref_mut!(sigs);
    let sig_count = ffi_param_ref_mut!(sig_count);

    match ka.set_expiration_time(signer.as_mut(),
                                 subkey_signer.map(|s| s.as_mut()),
                                 expiry)
    {
        Ok(new_sigs) => {
            let buffer = unsafe {
                libc::calloc(new_sigs.len(), std::mem::size_of::<*mut Signature>())
                    as *mut *mut Signature
            };
            let sl = unsafe {
                slice::from_raw_parts_mut(buffer, new_sigs.len())
            };
            *sig_count = new_sigs.len();
            sl.iter_mut().zip(new_sigs.into_iter())
                .for_each(|(e, sig)| *e = sig.move_into_raw());
            *sigs = buffer;
            Status::Success
        }
        Err(err) => {
            Err::<(), anyhow::Error>(err).move_into_raw(errp)
        }
    }
}

/// Changes the policy applied to the `ValidKeyAmalgamation`.
///
/// This consumes the key amalgamation.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_valid_key_amalgamation_with_policy<'a>(errp: Option<&mut *mut crate::error::Error>,
                                              ka: *mut ValidKeyAmalgamation<'a>,
                                              policy: *const Policy,
                                              time: time_t)
    -> Maybe<ValidKeyAmalgamation<'a>>
{
    ffi_make_fry_from_errp!(errp);

    let ka = ka.move_from_raw();
    let policy = policy.ref_raw();
    let time = maybe_time(time);

    ka.with_policy(&**policy, time).move_into_raw(errp)
}
