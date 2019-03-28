//! Packet-related types.
//!
//! See [Section 4 of RFC 4880] for more details.
//!
//!   [Section 4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4

use libc::{uint8_t, c_char};

extern crate sequoia_openpgp as openpgp;
extern crate time;

use self::openpgp::{
    Packet,
    packet::Tag,
};


pub mod key;
pub mod pkesk;
pub mod signature;
pub mod skesk;
pub mod user_attribute;
pub mod userid;

/// Frees the Packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_packet_free(p: Option<&mut Packet>) {
    ffi_free!(p)
}

/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_packet_tag(p: *const Packet)
                                     -> uint8_t {
    let p = ffi_param_ref!(p);
    let tag: u8 = p.tag().into();
    tag as uint8_t
}

/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `PGP_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_packet_kind(p: *const Packet)
                                      -> uint8_t {
    let p = ffi_param_ref!(p);
    if let Some(kind) = p.kind() {
        kind.into()
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
pub extern "system" fn pgp_tag_to_string(tag: uint8_t) -> *const c_char {
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

/// Pretty prints a packet
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_packet_debug(p: *const Packet) -> *const c_char {
    let p = ffi_param_ref!(p);
    format!("{:?}", p).as_ptr() as *const c_char
}

