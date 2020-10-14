//! `PacketPile`s, deserialized sequences of OpenPGP messages.
//!
//!
//! Wraps [`sequoia-openpgp::PacketPile`].
//!
//! [`sequoia-openpgp::PacketPile`]: ../../../sequoia_openpgp/struct.PacketPile.html

use sequoia_openpgp as openpgp;

/// A `PacketPile` holds a deserialized sequence of OpenPGP messages.
///
/// Wraps [`sequoia-openpgp::PacketPile`].
///
/// [`sequoia-openpgp::PacketPile`]: ../../../sequoia_openpgp/struct.PacketPile.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq, Parse, Serialize")]
pub struct PacketPile(openpgp::PacketPile);
