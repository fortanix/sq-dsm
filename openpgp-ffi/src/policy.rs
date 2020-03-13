//! Policy objects.
//!
//! This module allows the caller to specify low-level policy like
//! what algorithms are allowed.
//!
//! Wraps the policy object functions, see
//! [`sequoia-openpgp::policy`].
//!
//! [`sequoia-openpgp::policy`]: ../../sequoia_openpgp/policy/index.html

extern crate sequoia_openpgp as openpgp;

use crate::MoveIntoRaw;

use self::openpgp::policy;

/// A policy object.
#[crate::ffi_wrapper_type(
    prefix = "pgp_",
    derive = "Clone, Debug")]
pub struct Policy(Box<dyn policy::Policy>);

/// A StandardPolicy object.
#[crate::ffi_wrapper_type(
    prefix = "pgp_",
    derive = "Clone, Debug")]
pub struct StandardPolicy<'a>(policy::StandardPolicy<'a>);

/// A NullPolicy object.
#[crate::ffi_wrapper_type(
    prefix = "pgp_",
    derive = "Clone, Debug")]
pub struct NullPolicy(policy::NullPolicy);

/// Returns a new standard policy.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_standard_policy()
    -> *mut Policy
{
    let p : Box<dyn policy::Policy> = Box::new(policy::StandardPolicy::new());
    p.move_into_raw()
}

/// Returns a new null policy.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_null_policy()
    -> *mut Policy
{
    let p : Box<dyn policy::Policy> = Box::new(policy::NullPolicy::new());
    p.move_into_raw()
}
