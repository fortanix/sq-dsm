//! A modular OpenPGP implementation.
//!
//! Sequoia consists of several modules.  This crate conveniently
//! re-exports the other crates.

pub extern crate openpgp;
pub extern crate sequoia_core as core;
pub extern crate sequoia_net as net;
pub extern crate sequoia_store as store;

extern crate buffered_reader;
