//! Handles PacketPiles.
//!
//! Wraps [`sequoia-openpgp::PacketPile`].
//!
//! [`sequoia-openpgp::PacketPile`]: ../../../sequoia_openpgp/struct.PacketPile.html

use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, c_char, size_t};

extern crate sequoia_openpgp;
use self::sequoia_openpgp::{
    PacketPile,
    parse::Parse,
    serialize::Serialize,
};

use ::core::Context;
use ::error::Status;

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
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_reader(ctx: Option<&mut Context>,
                                                  reader: Option<&mut Box<Read>>)
                                                  -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry_box!(ctx, PacketPile::from_reader(reader))
}

/// Deserializes the OpenPGP message stored in the file named by
/// `filename`.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_file(ctx: Option<&mut Context>,
                                                filename: *const c_char)
                                                -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, PacketPile::from_file(&filename))
}

/// Deserializes the OpenPGP message stored in the provided buffer.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_bytes(ctx: Option<&mut Context>,
                                                 b: *const uint8_t, len: size_t)
                                                 -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, PacketPile::from_bytes(buf))
}

/// Frees the packet_pile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_free(packet_pile: *mut PacketPile) {
    ffi_free!(packet_pile)
}

/// Clones the PacketPile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_clone(packet_pile: Option<&PacketPile>)
                                            -> *mut PacketPile {
    let packet_pile = packet_pile.expect("PacketPile is NULL");
    box_raw!(packet_pile.clone())
}

/// Serializes the packet pile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_serialize(ctx: Option<&mut Context>,
                                                packet_pile: Option<&PacketPile>,
                                                writer: Option<&mut Box<Write>>)
                                                -> Status {
    let ctx = ctx.expect("Context is NULL");
    let packet_pile = packet_pile.expect("PacketPile is NULL");
    let writer = writer.expect("Writer is NULL");
    fry_status!(ctx, packet_pile.serialize(writer))
}
