//! `PacketPile`s, deserialized sequences of OpenPGP messages.
//!
//!
//! Wraps [`sequoia-openpgp::PacketPile`].
//!
//! [`sequoia-openpgp::PacketPile`]: ../../sequoia_openpgp/struct.PacketPile.html

use std::io::Write;

extern crate sequoia_openpgp as openpgp;
use self::openpgp::{
    parse::Parse,
    serialize::Serialize,
};

use ::error::Status;

/// A `PacketPile` holds a deserialized sequence of OpenPGP messages.
///
/// Wraps [`sequoia-openpgp::PacketPile`].
///
/// [`sequoia-openpgp::PacketPile`]: ../../sequoia_openpgp/struct.PacketPile.html
#[::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq, Parse, Serialize")]
pub struct PacketPile(openpgp::PacketPile);
