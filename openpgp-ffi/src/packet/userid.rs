//! User Id packets.
//!
//! See [Section 5.11 of RFC 4880] for details.
//!
//!   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11

extern crate sequoia_openpgp as openpgp;
use libc::{c_char, size_t};
use crate::error::Status;
use super::Packet;

use crate::RefRaw;
use crate::MoveIntoRaw;

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
///
/// Wraps [`sequoia-openpgp::packet::UserID`].
///
/// [`sequoia-openpgp::packet::UserID`]: ../../../sequoia_openpgp/packet/struct.UserID.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq")]
pub struct UserID(openpgp::packet::UserID);

/// Create a new User ID with the value `value`.
///
/// `value` need not be valid UTF-8, but it must be NUL terminated.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_new(value: *const c_char)
    -> *mut Packet
{
    let value : &[u8] = ffi_param_cstr!(value).to_bytes();
    let packet : openpgp::Packet = openpgp::packet::UserID::from(value).into();
    packet.move_into_raw()
}

/// Constructs a User ID.
///
/// This does a basic check and any necessary escaping to form a de
/// facto User ID.  Only the address is required.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_from_address(
    errp: Option<&mut *mut crate::error::Error>,
    name: Option<&c_char>,
    comment: Option<&c_char>,
    address: *const c_char)
    -> *mut Packet
{
    ffi_make_fry_from_errp!(errp);

    let name = if let Some(name) = name {
        Some(ffi_try!(ffi_param_cstr!(name as *const c_char).to_str()))
    } else {
        None
    };
    let comment = if let Some(comment) = comment {
        Some(ffi_try!(ffi_param_cstr!(comment as *const c_char).to_str()))
    } else {
        None
    };
    let address = ffi_try!(ffi_param_cstr!(address).to_str());

    let packet : openpgp::Packet
        = ffi_try!(openpgp::packet::UserID::from_address(name, comment,
                                                         address)).into();
    packet.move_into_raw()
}

/// Constructs a User ID.
///
/// This does a basic check and any necessary escaping to form a de
/// facto User ID.  The address is not checked.
///
/// This is useful when you want to specify a URI instead of an
/// email address.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_from_unchecked_address(
    errp: Option<&mut *mut crate::error::Error>,
    name: Option<&c_char>,
    comment: Option<&c_char>,
    address: *const c_char)
    -> *mut Packet
{
    ffi_make_fry_from_errp!(errp);

    let name = if let Some(name) = name {
        Some(ffi_try!(ffi_param_cstr!(name as *const c_char).to_str()))
    } else {
        None
    };
    let comment = if let Some(comment) = comment {
        Some(ffi_try!(ffi_param_cstr!(comment as *const c_char).to_str()))
    } else {
        None
    };
    let address = ffi_try!(ffi_param_cstr!(address).to_str());

    let packet : openpgp::Packet
        = ffi_try!(openpgp::packet::UserID::from_unchecked_address(
            name, comment, address)).into();
    packet.move_into_raw()
}

/// Create a new User ID with the value `value`.
///
/// `value` need not be valid UTF-8.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_from_raw(value: *const u8, len: size_t)
    -> *mut Packet
{
    let value : &[u8] = unsafe { std::slice::from_raw_parts(value, len) };
    let packet : openpgp::Packet = openpgp::packet::UserID::from(value).into();
    packet.move_into_raw()
}

/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_value(uid: *const Packet, value_len: Option<&mut size_t>)
    -> *const u8
{
    if let &openpgp::Packet::UserID(ref uid) = uid.ref_raw() {
        if let Some(p) = value_len {
            *p = uid.value().len();
        }
        uid.value().as_ptr()
    } else {
        panic!("Not a UserID packet");
    }
}

/// Returns the User ID's name component, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// name component is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a name component, *namep is set to
/// NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_name(
    errp: Option<&mut *mut crate::error::Error>, uid: *const Packet,
    namep: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.name() {
            Ok(Some(name)) =>
                *namep = ffi_return_string!(name),
            Ok(None) =>
                *namep = ::std::ptr::null_mut(),
            Err(err) => {
                use crate::MoveIntoRaw;
                let status = crate::error::Status::from(&err);
                if let Some(errp) = errp {
                    *errp = err.move_into_raw();
                }
                return status;
            }
        }
    } else {
        panic!("Not a UserID packet");
    }

    Status::Success
}

/// Returns the User ID's comment field, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// comment field is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a comment, *commentp is set
/// to NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_comment(
    errp: Option<&mut *mut crate::error::Error>, uid: *const Packet,
    commentp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.comment() {
            Ok(Some(comment)) =>
                *commentp = ffi_return_string!(comment),
            Ok(None) =>
                *commentp = ::std::ptr::null_mut(),
            Err(err) => {
                use crate::MoveIntoRaw;
                let status = crate::error::Status::from(&err);
                if let Some(errp) = errp {
                    *errp = err.move_into_raw();
                }
                return status;
            }
        }
    } else {
        panic!("Not a UserID packet");
    }

    Status::Success
}

/// Returns the User ID's email address, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// email address is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain an email address, *addressp is set
/// to NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_email(
    errp: Option<&mut *mut crate::error::Error>, uid: *const Packet,
    addressp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.email() {
            Ok(Some(address)) =>
                *addressp = ffi_return_string!(address),
            Ok(None) =>
                *addressp = ::std::ptr::null_mut(),
            Err(err) => {
                use crate::MoveIntoRaw;
                let status = crate::error::Status::from(&err);
                if let Some(errp) = errp {
                    *errp = err.move_into_raw();
                }
                return status;
            }
        }
    } else {
        panic!("Not a UserID packet");
    }

    Status::Success
}

/// Returns the User ID's URI, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// URI is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a URI, *urip is set to NULL.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_uri(
    errp: Option<&mut *mut crate::error::Error>, uid: *const Packet,
    urip: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.uri() {
            Ok(Some(uri)) =>
                *urip = ffi_return_string!(uri),
            Ok(None) =>
                *urip = ::std::ptr::null_mut(),
            Err(err) => {
                use crate::MoveIntoRaw;
                let status = crate::error::Status::from(&err);
                if let Some(errp) = errp {
                    *errp = err.move_into_raw();
                }
                return status;
            }
        }
    } else {
        panic!("Not a UserID packet");
    }

    Status::Success
}

/// Returns a normalized version of the UserID's email address.
///
/// Normalized email addresses are primarily needed when email
/// addresses are compared.
///
/// Note: normalized email addresses are still valid email
/// addresses.
///
/// This function normalizes an email address by doing [puny-code
/// normalization] on the domain, and lowercasing the local part in
/// the so-called [empty locale].
///
/// Note: this normalization procedure is the same as the
/// normalization procedure recommended by [Autocrypt].
///
///   [puny-code normalization]: https://tools.ietf.org/html/rfc5891.html#section-4.4
///   [empty locale]: https://www.w3.org/International/wiki/Case_folding
///   [Autocrypt]: https://autocrypt.org/level1.html#e-mail-address-canonicalization
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_email_normalized(
    errp: Option<&mut *mut crate::error::Error>, uid: *const Packet,
    emailp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.email_normalized() {
            Ok(Some(email)) =>
                *emailp = ffi_return_string!(email),
            Ok(None) =>
                *emailp = ::std::ptr::null_mut(),
            Err(err) => {
                use crate::MoveIntoRaw;
                let status = crate::error::Status::from(&err);
                if let Some(errp) = errp {
                    *errp = err.move_into_raw();
                }
                return status;
            }
        }
    } else {
        panic!("Not a UserID packet");
    }

    Status::Success
}
