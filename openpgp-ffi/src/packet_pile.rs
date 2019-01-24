//! `PacketPile`s, deserialized sequences of OpenPGP messages.
//!
//!
//! Wraps [`sequoia-openpgp::PacketPile`].
//!
//! [`sequoia-openpgp::PacketPile`]: ../../sequoia_openpgp/struct.PacketPile.html

use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, c_char, size_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    parse::Parse,
    serialize::Serialize,
};

use Maybe;
use ::error::Status;

/// A `PacketPile` holds a deserialized sequence of OpenPGP messages.
///
/// Wraps [`sequoia-openpgp::PacketPile`].
///
/// [`sequoia-openpgp::PacketPile`]: ../../sequoia_openpgp/struct.PacketPile.html
#[::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq")]
pub struct PacketPile(openpgp::PacketPile);

/// Deserializes the OpenPGP message stored in a `std::io::Read`
/// object.
///
/// Although this method is easier to use to parse an OpenPGP
/// message than a `PacketParser` or a `PacketPileParser`, this
/// interface buffers the whole message in memory.  Thus, the
/// caller must be certain that the *deserialized* message is not
/// too large.
///
/// Note: this interface *does* buffer the contents of packets.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_packet_pile_from_reader(errp: Option<&mut *mut failure::Error>,
                               reader: *mut Box<Read>)
                               -> Maybe<PacketPile> {
    let reader = ffi_param_ref_mut!(reader);
    openpgp::PacketPile::from_reader(reader).move_into_raw(errp)
}

/// Deserializes the OpenPGP message stored in the file named by
/// `filename`.
///
/// See `pgp_packet_pile_from_reader` for more details and caveats.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_packet_pile_from_file(errp: Option<&mut *mut failure::Error>,
                             filename: *const c_char)
                             -> Maybe<PacketPile> {
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    openpgp::PacketPile::from_file(&filename).move_into_raw(errp)
}

/// Deserializes the OpenPGP message stored in the provided buffer.
///
/// See `pgp_packet_pile_from_reader` for more details and caveats.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_packet_pile_from_bytes(errp: Option<&mut *mut failure::Error>,
                              b: *const uint8_t, len: size_t)
                              -> Maybe<PacketPile> {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    openpgp::PacketPile::from_bytes(buf).move_into_raw(errp)
}

/// Serializes the packet pile.
#[::ffi_catch_abort] #[no_mangle] pub extern "system"
fn pgp_packet_pile_serialize(errp: Option<&mut *mut failure::Error>,
                             packet_pile: *const PacketPile,
                             writer: *mut Box<Write>)
                             -> Status {
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    ffi_try_status!(packet_pile.ref_raw().serialize(writer))
}
