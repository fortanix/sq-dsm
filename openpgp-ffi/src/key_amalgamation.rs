//! `KeyAmalgamation`s.
//!
//!
//! Wraps [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`].
//!
//! [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`]: ../../../sequoia_openpgp/cert/key_amalgamation/struct.KeyAmalgamation.html

extern crate sequoia_openpgp as openpgp;
use self::openpgp::packet::key;
use self::openpgp::cert::amalgamation::ValidAmalgamation;

use super::packet::key::Key;
use super::packet::signature::Signature;
use super::revocation_status::RevocationStatus;

use crate::MoveIntoRaw;
use crate::RefRaw;

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
