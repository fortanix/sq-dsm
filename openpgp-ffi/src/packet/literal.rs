//! Literal data packets.
//!
//! Literal data packets hold the actual message content and some
//! optional meta-data.
//!
//! See [Section 5.8 of RFC 4880] for details.
//!
//!   [Section 5.8 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.8

use libc::c_char;

extern crate sequoia_openpgp as openpgp;

use super::Packet;

use MoveFromRaw;
use MoveIntoRaw;
use RefRaw;

/// Holds a Literal Data packet.
///
/// Literal data packets hold the actual message content and some
/// optional meta-data.
///
/// See [Section 5.8 of RFC 4880] for details.
///
///   [Section 5.8 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.8
///
/// Wraps [`sequoia-openpgp::packet::literal::Literal`].
///
/// [`sequoia-openpgp::packet::literal::Literal`]: ../../sequoia_openpgp/packet/literal/struct.Literal.html
#[::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Debug, Parse, Serialize")]
pub struct Literal(openpgp::packet::Literal);

/// Converts the literal data packet to a packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_literal_into_packet(l: *mut Literal) -> *mut Packet {
    let p : openpgp::Packet = l.move_from_raw().into();
    p.move_into_raw()
}

/// Returns the filename as a c string.
///
/// If the filename is not set, returns NULL.
///
/// Note: the filename is *not* protected by any signature and thus
/// can be modified in transit without detection.
///
/// Note: the filename may contain embedded NULs.  This function
/// returns NULL in such cases.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_literal_filename(l: *const Literal) -> *mut c_char {
    let l : &openpgp::packet::Literal = l.ref_raw().into();
    if let Some(filename) = l.filename() {
        ffi_return_maybe_string!(filename)
    } else {
        ::std::ptr::null_mut()
    }
}
