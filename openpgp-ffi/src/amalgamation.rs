//! `KeyAmalgamation`s.
//!
//!
//! Wraps [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`].
//!
//! [`sequoia-openpgp::cert::key_amalgamation::KeyAmalgamation`]: ../../../sequoia_openpgp/cert/key_amalgamation/struct.KeyAmalgamation.html

use libc::time_t;

use sequoia_openpgp as openpgp;

use self::openpgp::cert::amalgamation::ValidAmalgamation as _;
use self::openpgp::cert::amalgamation::ValidateAmalgamation as _;

use super::packet::Packet;
use super::packet::signature::Signature;
use super::policy::Policy;
use super::revocation_status::RevocationStatus;

use crate::Maybe;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::RefRaw;
use crate::MoveFromRaw;
use crate::maybe_time;

/// A local alias to appease the proc macro transformation.
type UserIDAmalgamationType<'a>
    = openpgp::cert::amalgamation::UserIDAmalgamation<'a>;

/// A `UserIDAmalgamation` holds a `UserID` and associated data.
///
/// Wraps [`sequoia-openpgp::cert::amalgamation::ComponentAmalgamation`].
///
/// [`sequoia-openpgp::cert::amalgamation::ComponentAmalgamation`]: ../../../sequoia_openpgp/cert/amalgamation/struct.ComponentAmalgamation.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug")]
pub struct UserIDAmalgamation<'a>(UserIDAmalgamationType<'a>);

/// Returns a copy of the `UserID`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_id_amalgamation_user_id<'a>(ua: *const UserIDAmalgamation<'a>)
    -> *mut Packet
{
    let ua = ua.ref_raw();

    openpgp::Packet::from(ua.userid().clone()).move_into_raw()
}

/// A local alias to appease the proc macro transformation.
type ValidUserIDAmalgamationType<'a>
    = openpgp::cert::amalgamation::ValidUserIDAmalgamation<'a>;

/// A `ValidUserIDAmalgamation` holds a `UserID` and associated data
/// including a policy and a reference time.
///
/// Wraps [`sequoia-openpgp::cert::amalgamation::ValidComponentAmalgamation`].
///
/// [`sequoia-openpgp::cert::amalgamation::ValidComponentAmalgamation`]: ../../../sequoia_openpgp/cert/amalgamation/struct.ValidComponentAmalgamation.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug")]
pub struct ValidUserIDAmalgamation<'a>(ValidUserIDAmalgamationType<'a>);

/// Returns a reference to the `UserID`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_user_id_amalgamation_user_id<'a>(ua: *const ValidUserIDAmalgamation<'a>)
    -> *const Packet
{
    let ua = ua.ref_raw();

    openpgp::Packet::from(ua.userid().clone()).move_into_raw()
}

/// Returns the UserID's revocation status.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_user_id_amalgamation_revocation_status<'a>(ua: *const ValidUserIDAmalgamation<'a>)
    -> *mut RevocationStatus<'a>
{
    ua.ref_raw()
        .revocation_status()
        .move_into_raw()
}

/// Returns the User ID's binding signature.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_valid_user_id_amalgamation_binding_signature<'a>(ua: *const ValidUserIDAmalgamation<'a>)
    -> *const Signature
{
    ua.ref_raw()
        .binding_signature()
        .move_into_raw()
}

/// Changes the policy applied to the `ValidUserIDAmalgamation`.
///
/// This consumes the User ID amalgamation.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_valid_user_id_amalgamation_with_policy<'a>(errp: Option<&mut *mut crate::error::Error>,
                                                  ua: *mut ValidUserIDAmalgamation<'a>,
                                                  policy: *const Policy,
                                                  time: time_t)
    -> Maybe<ValidUserIDAmalgamation<'a>>
{
    ffi_make_fry_from_errp!(errp);

    let ua = ua.move_from_raw();
    let policy = policy.ref_raw();
    let time = maybe_time(time);

    ua.with_policy(&**policy, time).move_into_raw(errp)
}
