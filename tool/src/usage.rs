//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! sq 0.1.0
//! Sequoia is an implementation of OpenPGP.  This is a command-line frontend.
//!
//! USAGE:
//!     sq [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     dearmor    Removes ASCII Armor from a file
//!     dump       Lists OpenPGP packets
//!     enarmor    Applies ASCII Armor to a file
//!     help       Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ## Subcommand dearmor
//!
//! ```text
//! sq-dearmor
//! Removes ASCII Armor from a file
//!
//! USAGE:
//!     sq dearmor [OPTIONS]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -i, --input <FILE>     Sets the input file to use
//!     -o, --output <FILE>    Sets the output file to use
//! ```
//!
//! ## Subcommand dump
//!
//! ```text
//! sq-dump
//! Lists OpenPGP packets
//!
//! USAGE:
//!     sq dump [FLAGS] [OPTIONS]
//!
//! FLAGS:
//!     -A, --dearmor    Remove ASCII Armor from input
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -i, --input <FILE>     Sets the input file to use
//!     -o, --output <FILE>    Sets the output file to use
//! ```
//!
//! ## Subcommand enarmor
//!
//! ```text
//! sq-enarmor
//! Applies ASCII Armor to a file
//!
//! USAGE:
//!     sq enarmor [OPTIONS]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -i, --input <FILE>     Sets the input file to use
//!     -o, --output <FILE>    Sets the output file to use
//! ```

include!("main.rs");
