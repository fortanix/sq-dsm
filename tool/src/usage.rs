//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! Sequoia is an implementation of OpenPGP.  This is a command-line frontend.
//!
//! USAGE:
//!     sq [OPTIONS] [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -d, --domain <DOMAIN>            Sets the domain to use
//!     -p, --policy <NETWORK-POLICY>    Sets the network policy to use
//!
//! SUBCOMMANDS:
//!     dearmor      Removes ASCII Armor from a file
//!     dump         Lists OpenPGP packets
//!     enarmor      Applies ASCII Armor to a file
//!     help         Prints this message or the help of the given subcommand(s)
//!     keyserver    Interacts with keyservers
//! ```
//!
//! ## Subcommand dearmor
//!
//! ```text
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
//!
//! ## Subcommand keyserver
//!
//! ```text
//! Interacts with keyservers
//!
//! USAGE:
//!     sq keyserver [OPTIONS] [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -s, --server <URI>    Sets the keyserver to use
//!
//! SUBCOMMANDS:
//!     get     Retrieves a key
//!     help    Prints this message or the help of the given subcommand(s)
//!     send    Sends a key
//! ```
//!
//! ### Subcommand keyserver get
//!
//! ```text
//! Retrieves a key
//!
//! USAGE:
//!     sq keyserver get [FLAGS] [OPTIONS] <KEYID>
//!
//! FLAGS:
//!     -A, --armor      Write armored data to file
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <KEYID>    ID of the key to retrieve
//! ```
//!
//! ### Subcommand keyserver send
//!
//! ```text
//! Sends a key
//!
//! USAGE:
//!     sq keyserver send [FLAGS] [OPTIONS]
//!
//! FLAGS:
//!     -A, --dearmor    Remove ASCII Armor from input
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -i, --input <FILE>    Sets the input file to use
//! ```

include!("main.rs");
