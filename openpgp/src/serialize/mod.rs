//! OpenPGP packet serializer.
//!
//! There are two interfaces to serialize OpenPGP data.  Which one is
//! applicable depends on whether or not the packet structure is
//! already assembled in memory, with all information already in place
//! (e.g. because it was parsed).
//!
//! If it is, you can use the `Serialize` or `SerializeKey`.
//!
//! Otherwise, please use our streaming serialization interface.

// Hack so that the file doesn't have to be named mod.rs.
include!("serialize.rs");
