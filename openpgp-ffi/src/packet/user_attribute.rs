//! User Attribute packets.
//!
//! See [Section 5.12 of RFC 4880] for details.
//!
//!   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12

use libc::{uint8_t, size_t};
extern crate sequoia_openpgp as openpgp;
use self::openpgp::Packet;

/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_user_attribute_value(ua: *const Packet,
                                               value_len: Option<&mut size_t>)
                                               -> *const uint8_t {
    let ua = ffi_param_ref!(ua);
    if let &Packet::UserAttribute(ref ua) = ua {
        if let Some(p) = value_len {
            *p = ua.user_attribute().len();
        }
        ua.user_attribute().as_ptr()
    } else {
        panic!("Not a UserAttribute packet");
    }
}
