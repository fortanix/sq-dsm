//! A modular OpenPGP implementation.
//!
//! Sequoia consists of several modules.  This crate conveniently
//! re-exports the other crates.
//!
//! # Example
//!
//! ```
//! use std::io::Read;
//! extern crate sequoia_openpgp as openpgp;
//! # use std::io::Result;
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//!
//! let mut reader = openpgp::armor::Reader::from_bytes(
//!    b"-----BEGIN PGP ARMORED FILE-----
//!
//!      SGVsbG8gd29ybGQh
//!      =s4Gu
//!      -----END PGP ARMORED FILE-----", None);
//!
//! let mut content = String::new();
//! reader.read_to_string(&mut content)?;
//! assert_eq!(content, "Hello world!");
//! # Ok(())
//! # }
//! ```

// XXX: It would be nice to re-export the macros too.
pub extern crate sequoia_openpgp as openpgp;
pub extern crate sequoia_core as core;
pub extern crate sequoia_net as net;
pub extern crate sequoia_store as store;

extern crate buffered_reader;
