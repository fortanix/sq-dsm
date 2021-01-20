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
//!     -V, --version    Prints version information
//!     -v, --verbose    Be verbose.
//!
//! OPTIONS:
//!         --keyring <FILE>...         A keyring.  Can be given multiple times.
//!         --not-after <TIMESTAMP>     Consider signatures created after TIMESTAMP as invalid.  If a date is given,
//!                                     23:59:59 is used for the time.
//!                                     [default: now]
//!         --not-before <TIMESTAMP>    Consider signatures created before TIMESTAMP as invalid.  If a date is given,
//!                                     00:00:00 is used for the time.
//!                                     [default: no constraint]
//!     -n, --signatures <N>            The number of valid signatures to return success.  Default: 1
//!
//! ARGS:
//!     <SIG-FILE>    File containing the detached signature.
//!     <FILE>        File to verify.
//!
//! TIMESTAMPs must be given in ISO 8601 format (e.g. '2017-03-04T13:25:35Z', '2017-03-04T13:25', '20170304T1325+0830',
//! '2017-03-04', '2017031', ...). If no timezone is specified, UTC is assumed.
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

include!("sqv.rs");
