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
use self::openpgp::crypto;

use super::packet::key::Key;
use super::packet::signature::Signature;
use super::packet::Packet;
use super::revocation_status::RevocationStatus;

use crate::error::Status;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::RefRaw;
use crate::maybe_time;

/// A local alias to appease the proc macro transformation.
type ErasedKeyAmalgamation<'a> =
    openpgp::cert::key_amalgamation::ErasedKeyAmalgamation<'a, key::UnspecifiedParts>;

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
    openpgp::cert::key_amalgamation::ValidErasedKeyAmalgamation<'a, key::UnspecifiedParts>;

/// Returns a reference to the `Key`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_key_amalgamation_key<'a>(ka: *const KeyAmalgamation<'a>)
    -> *const Key
{
    let ka = ka.ref_raw();

    ka.key().mark_parts_unspecified_ref().mark_role_unspecified_ref()
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

    ka.key().mark_parts_unspecified_ref().mark_role_unspecified_ref()
        .move_into_raw()
}

/// Returns the Key Amalgamation's revocation status.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_key_amalgamation_revocation_status<'a>(ka: *const ValidKeyAmalgamation<'a>)
    -> *mut RevocationStatus<'a>
{
    ka.ref_raw()
        .revoked()
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

/// Creates one or more self-signatures that when merged with the
/// certificate cause the key to expire at the specified time.
///
/// The returned buffer must be freed using libc's allocator.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_valid_key_amalgamation_set_expiration_time(
    errp: Option<&mut *mut crate::error::Error>,
    ka: *const ValidKeyAmalgamation,
    primary_signer: *mut Box<dyn crypto::Signer>,
    expiry: time_t,
    packets: *mut *mut *mut Packet, packet_count: *mut size_t)
    -> Status
{
    ffi_make_fry_from_errp!(errp);

    let ka = ka.ref_raw();
    let signer = ffi_param_ref_mut!(primary_signer);
    let expiry = maybe_time(expiry);
    let packets = ffi_param_ref_mut!(packets);
    let packet_count = ffi_param_ref_mut!(packet_count);

    match ka.set_expiration_time(signer.as_mut(), expiry) {
        Ok(sigs) => {
            let buffer = unsafe {
                libc::calloc(sigs.len(), std::mem::size_of::<*mut Packet>())
                    as *mut *mut Packet
            };
            let sl = unsafe {
                slice::from_raw_parts_mut(buffer, sigs.len())
            };
            *packet_count = sigs.len();
            sl.iter_mut().zip(sigs.into_iter())
                .for_each(|(e, sig)| *e = sig.move_into_raw());
            *packets = buffer;
            Status::Success
        }
        Err(err) => {
            Err::<(), anyhow::Error>(err).move_into_raw(errp)
        }
    }
}
