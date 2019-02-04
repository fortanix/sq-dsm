//! User Id packets.
//!
//! See [Section 5.11 of RFC 4880] for details.
//!
//!   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11

use libc::{uint8_t, size_t};
extern crate sequoia_openpgp as openpgp;
use self::openpgp::Packet;

/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_user_id_value(uid: *const Packet,
                                        value_len: Option<&mut size_t>)
                                        -> *const uint8_t {
    let uid = ffi_param_ref!(uid);
    if let &Packet::UserID(ref uid) = uid {
        if let Some(p) = value_len {
            *p = uid.userid().len();
        }
        uid.userid().as_ptr()
    } else {
        panic!("Not a UserID packet");
    }
}
