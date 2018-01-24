//! A modular OpenPGP implementation.
//!
//! Sequoia consists of several modules.  This crate conveniently
//! re-exports the other crates.
//!
//! # Example
//!
//! ```
//! use std::io::Read;
//! #[macro_use] extern crate openpgp;
//! use openpgp::armor;
//! # use std::io::Result;
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//!
//! let mut reader = armored!(
//!     "-----BEGIN PGP ARMORED FILE-----
//!
//!      SGVsbG8gd29ybGQh
//!      =s4Gu
//!      -----END PGP ARMORED FILE-----"
//! );
//!
//! let mut content = String::new();
//! reader.read_to_string(&mut content)?;
//! assert_eq!(content, "Hello world!");
//! # Ok(())
//! # }
//! ```

// XXX: It would be nice to re-export the macros too.
pub extern crate openpgp;
pub extern crate sequoia_core as core;
pub extern crate sequoia_net as net;
pub extern crate sequoia_store as store;

extern crate buffered_reader;
