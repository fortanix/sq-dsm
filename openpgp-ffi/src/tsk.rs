//! Transferable secret keys.
//!
//! Wraps [`sequoia-openpgp::tpk::TSK`].
//!
//! [`sequoia-openpgp::tpk::TSK`]: ../../sequoia_openpgp/struct.TSK.html

extern crate sequoia_openpgp as openpgp;

/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
///
/// Wraps [`sequoia-openpgp::tpk::TSK`].
///
/// [`sequoia-openpgp::tpk::TSK`]: ../../sequoia_openpgp/enum.TSK.html
#[crate::ffi_wrapper_type(prefix = "pgp_", name = "tsk", derive = "Serialize")]
pub struct TSK<'a>(openpgp::serialize::TSK<'a>);
