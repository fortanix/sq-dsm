//! Packet-related types.
//!
//! See [Section 4 of RFC 4880] for more details.
//!
//!   [Section 4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4

use libc::c_char;

use sequoia_openpgp as openpgp;

use self::openpgp::{
    packet::Tag,
};


pub mod key;
pub mod pkesk;
pub mod signature;
pub mod skesk;
pub mod user_attribute;
pub mod userid;
pub mod literal;

use crate::Maybe;
use crate::MoveIntoRaw;
use crate::RefRaw;

/// The OpenPGP packets that Sequoia understands.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 4880].
///
/// The `Unknown` packet allows Sequoia to deal with packets that it
/// doesn't understand.  The `Unknown` packet is basically a binary
/// blob that includes the packet's tag.
///
/// The unknown packet is also used for packets that are understood,
/// but use unsupported options.  For instance, when the packet parser
/// encounters a compressed data packet with an unknown compression
/// algorithm, it returns the packet in an `Unknown` packet rather
/// than a `CompressedData` packet.
///
///   [Section 5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5
///
/// Wraps [`sequoia-openpgp::Packet`].
///
/// [`sequoia-openpgp::Packet`]: sequoia_openpgp::Packet
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, Hash, PartialEq")]
pub struct Packet(openpgp::Packet);

/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_packet_tag(p: *const Packet) -> u32 {
    u8::from(p.ref_raw().tag()) as u32
}

/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `PGP_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_packet_kind(p: *const Packet) -> u32 {
    if let Some(kind) = p.ref_raw().kind() {
        u8::from(kind) as u32
    } else {
        0
    }
}

/// Returns a human-readable tag name.
///
/// ```c
/// #include <assert.h>
/// #include <string.h>
/// #include <sequoia/openpgp.h>
///
/// assert (strcmp (pgp_tag_to_string (2), "SIGNATURE") == 0);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_tag_to_string(tag: u8) -> *const c_char {
    match Tag::from(tag) {
        Tag::PKESK => "PKESK\x00",
        Tag::Signature => "SIGNATURE\x00",
        Tag::SKESK => "SKESK\x00",
        Tag::OnePassSig => "ONE PASS SIG\x00",
        Tag::SecretKey => "SECRET KEY\x00",
        Tag::PublicKey => "PUBLIC KEY\x00",
        Tag::SecretSubkey => "SECRET SUBKEY\x00",
        Tag::CompressedData => "COMPRESSED DATA\x00",
        Tag::SED => "SED\x00",
        Tag::Marker => "MARKER\x00",
        Tag::Literal => "LITERAL\x00",
        Tag::Trust => "TRUST\x00",
        Tag::UserID => "USER ID\x00",
        Tag::PublicSubkey => "PUBLIC SUBKEY\x00",
        Tag::UserAttribute => "USER ATTRIBUTE\x00",
        Tag::SEIP => "SEIP\x00",
        Tag::MDC => "MDC\x00",
        _ => "OTHER\x00",
    }.as_bytes().as_ptr() as *const c_char
}

/// Given a packet references the contained signature, if any.
///
/// If the Packet is not of the `Packet::Signature` variant, this
/// function returns `NULL`.  Objects returned from this function must
/// be deallocated using `pgp_signature_free` even though they only
/// reference the given packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_packet_ref_signature(p: *const Packet) -> Maybe<signature::Signature> {
    if let openpgp::Packet::Signature(ref p) = p.ref_raw() {
        ::std::ptr::NonNull::new(p.move_into_raw())
    } else {
        None
    }
}

/// Given a packet references the contained literal data packet, if
/// any.
///
/// If the Packet is not of the `Packet::Literal` variant, this
/// function returns `NULL`.  Objects returned from this function must
/// be deallocated using `pgp_literal_data_free` even though they only
/// reference the given packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_packet_ref_literal(p: *const Packet) -> Maybe<literal::Literal> {
    if let openpgp::Packet::Literal(ref p) = p.ref_raw() {
        ::std::ptr::NonNull::new(p.move_into_raw())
    } else {
        None
    }
}
