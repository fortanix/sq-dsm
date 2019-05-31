//! User Id packets.
//!
//! See [Section 5.11 of RFC 4880] for details.
//!
//!   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11

extern crate sequoia_openpgp as openpgp;
use libc::{uint8_t, c_char, size_t};
use error::Status;
use super::Packet;

use RefRaw;
use MoveIntoRaw;

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
/// This escapes the name.  The comment and address must be well
/// formed according to RFC 2822.  Only the address is required.
///
/// If you already have a full RFC 2822 mailbox, then you can just
/// use `UserID::from()`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_from_address(
    errp: Option<&mut *mut ::error::Error>,
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
/// This escapes the name.  The comment must be well formed, the
/// address can be arbitrary.
///
/// This is useful when you want to specify a URI instead of an
/// email address.
///
/// If you have a full RFC 2822 mailbox, then you can just use
/// `UserID::from()`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_from_unchecked_address(
    errp: Option<&mut *mut ::error::Error>,
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
fn pgp_user_id_from_raw(value: *const uint8_t, len: size_t)
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
    -> *const uint8_t
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

/// Returns the User ID's display name, if any.
///
/// The User ID is parsed as an [RFC 2822 mailbox], and the display
/// name is extracted.
///
/// Note: invalid email addresses are accepted in order to support
/// things like URIs of the form `Hostname
/// <ssh://server@example.net>`.
///
/// If the User ID is otherwise not a valid RFC 2822 mailbox
/// production, then an error is returned.
///
///
/// If the User ID does not contain a display, *name is set
/// to NULL.
///
///   [RFC 2822 mailbox]: https://tools.ietf.org/html/rfc2822#section-3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_name(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
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
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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

/// Returns the User ID's comment, if any.
///
/// The User ID is parsed as an [RFC 2822 mailbox], and the first
/// comment is extracted.
///
/// Note: invalid email addresses are accepted in order to support
/// things like URIs of the form `Hostname
/// <ssh://server@example.net>`.
///
/// If the User ID is otherwise not a valid RFC 2822 mailbox
/// production, then an error is returned.
///
/// If the User ID does not contain a comment, *commentp is set
/// to NULL.
///
///   [RFC 2822 mailbox]: https://tools.ietf.org/html/rfc2822#section-3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_comment(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
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
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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
/// The User ID is parsed as an [RFC 2822 mailbox], and the email
/// address is extracted.
///
/// Note: invalid email addresses are accepted in order to support
/// things like URIs of the form `Hostname
/// <ssh://server@example.net>`.
///
/// If the User ID is otherwise not a valid RFC 2822 mailbox
/// production, then an error is returned.
///
/// If the User ID does not contain an email address, *addressp is set
/// to NULL.
///
///   [RFC 2822 mailbox]: https://tools.ietf.org/html/rfc2822#section-3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_address(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
    addressp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.address() {
            Ok(Some(address)) =>
                *addressp = ffi_return_string!(address),
            Ok(None) =>
                *addressp = ::std::ptr::null_mut(),
            Err(err) => {
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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

/// Returns the User ID's invalid address, if any.
///
/// The User ID is parsed as an [RFC 2822 mailbox], and if the address
/// is invalid, that is returned.
///
/// Note: invalid email addresses are accepted in order to support
/// things like URIs of the form `Hostname
/// <ssh://server@example.net>`.
///
/// If the User ID is otherwise not a valid RFC 2822 mailbox
/// production, then an error is returned.
///
/// If the User ID does not contain an invalid address, *otherp is
/// set to NULL.
///
///   [RFC 2822 mailbox]: https://tools.ietf.org/html/rfc2822#section-3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_other(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
    otherp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.other() {
            Ok(Some(other)) =>
                *otherp = ffi_return_string!(other),
            Ok(None) =>
                *otherp = ::std::ptr::null_mut(),
            Err(err) => {
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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
/// The User ID is parsed as an [RFC 2822 mailbox], and the email
/// address, whether it is valid or not, is extracted.
///
/// Note: invalid email addresses are accepted in order to support
/// things like URIs of the form `Hostname
/// <ssh://server@example.net>`.
///
/// If the User ID is otherwise not a valid RFC 2822 mailbox
/// production, then an error is returned.
///
/// If the User ID does not contain an address (valid or invalid),
/// *addressp is set to NULL.
///
///   [RFC 2822 mailbox]: https://tools.ietf.org/html/rfc2822#section-3.4
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C"
fn pgp_user_id_address_or_other(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
    addressp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.address() {
            Ok(Some(address)) =>
                *addressp = ffi_return_string!(address),
            Ok(None) =>
                match uid.other() {
                    Ok(Some(other)) =>
                        *addressp = ffi_return_string!(other),
                    Ok(None) =>
                        *addressp = ::std::ptr::null_mut(),
                    Err(err) => {
                        use MoveIntoRaw;
                        let status = ::error::Status::from(&err);
                        if let Some(errp) = errp {
                            *errp = err.move_into_raw();
                        }
                        return status;
                    }
                },
            Err(err) => {
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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
fn pgp_user_id_address_normalized(
    errp: Option<&mut *mut ::error::Error>, uid: *const Packet,
    addressp: &mut *mut c_char)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let uid = uid.ref_raw();

    if let &openpgp::Packet::UserID(ref uid) = uid {
        match uid.address_normalized() {
            Ok(Some(address)) =>
                *addressp = ffi_return_string!(address),
            Ok(None) =>
                *addressp = ::std::ptr::null_mut(),
            Err(err) => {
                use MoveIntoRaw;
                let status = ::error::Status::from(&err);
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
