//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! sqv is a command-line OpenPGP signature verification tool.
//!
//! USAGE:
//!     sqv [FLAGS] [OPTIONS] <SIG-FILE> <FILE> --keyring <FILE>...
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!         --trace      Trace execution.
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --keyring <FILE>...          A keyring.  Can be given multiple times.
//!         --not-after <YYYY-MM-DD>     Consider signatures created after YYYY-MM-DD as invalid.  Default: now
//!         --not-before <YYYY-MM-DD>    Consider signatures created before YYYY-MM-DD as invalid.  Default: no constraint
//!     -n, --signatures <N>             The number of valid signatures to return success.  Default: 1
//!
//! ARGS:
//!     <SIG-FILE>    File containing the detached signature.
//!     <FILE>        File to verify.
//! ```

include!("sqv.rs");
