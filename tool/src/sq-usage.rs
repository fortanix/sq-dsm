//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! Sequoia is an implementation of OpenPGP.  This is a command-line frontend.
//!
//! USAGE:
//!     sq [FLAGS] [OPTIONS] [SUBCOMMAND]
//!
//! FLAGS:
//!     -f, --force      Overwrite existing files
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -d, --domain <DOMAIN>            Sets the domain to use
//!         --home <DIRECTORY>           Sets the home directory to use
//!     -p, --policy <NETWORK-POLICY>    Sets the network policy to use
//!     -s, --store <STORE>              Sets the store to use (default: 'default')
//!
//! SUBCOMMANDS:
//!     decrypt      Decrypts an OpenPGP message
//!     encrypt      Encrypts a message
//!     sign         Signs a message
//!     verify       Verifies a message
//!     store        Interacts with key stores
//!     keyserver    Interacts with keyservers
//!     autocrypt    Autocrypt support
//!     dearmor      Removes ASCII Armor from a file
//!     enarmor      Applies ASCII Armor to a file
//!     help         Prints this message or the help of the given subcommand(s)
//!     inspect      Inspects a sequence of OpenPGP packets
//!     key          Manipulates keys
//!     list         Lists key stores and known keys
//!     packet       OpenPGP Packet manipulation
//! ```
//!
//! ## Subcommand decrypt
//!
//! ```text
//! Decrypts an OpenPGP message
//!
//! USAGE:
//!     sq decrypt [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!         --dump                Print a packet dump to stderr
//!         --dump-session-key    Prints the session key to stderr
//!     -h, --help                Prints help information
//!     -x, --hex                 Print a hexdump (implies --dump)
//!     -V, --version             Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                    Sets the output file to use
//!         --public-key-file <TPK-FILE>...    Public key to verify with, given as a file (can be given multiple times)
//!         --secret-key-file <TSK-FILE>...    Secret key to decrypt with, given as a file (can be given multiple times)
//!     -n, --signatures <N>                   The number of valid signatures required.  Default: 0
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand encrypt
//!
//! ```text
//! Encrypts a message
//!
//! USAGE:
//!     sq encrypt [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -B, --binary       Don't ASCII-armor encode the OpenPGP data
//!     -h, --help         Prints help information
//!     -s, --symmetric    Encrypt with a password (can be given multiple times)
//!     -V, --version      Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                       Sets the output file to use
//!     -r, --recipient <LABEL>...                Recipient to encrypt for (can be given multiple times)
//!         --recipient-key-file <TPK-FILE>...    Recipient to encrypt for, given as a file (can be given multiple times)
//!         --signer-key-file <TSK-FILE>...       Secret key to sign with, given as a file (can be given multiple times)
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand sign
//!
//! ```text
//! Signs a message
//!
//! USAGE:
//!     sq sign [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -a, --append      Append signature to existing signature
//!     -B, --binary      Don't ASCII-armor encode the OpenPGP data
//!         --detached    Create a detached signature
//!     -h, --help        Prints help information
//!     -n, --notarize    Signs a message and all existing signatures
//!     -V, --version     Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                    Sets the output file to use
//!         --secret-key-file <TSK-FILE>...    Secret key to sign with, given as a file (can be given multiple times)
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand verify
//!
//! ```text
//! Verifies a message
//!
//! USAGE:
//!     sq verify [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --detached <SIG-FILE>              Verifies a detached signature
//!     -o, --output <FILE>                    Sets the output file to use
//!         --public-key-file <TPK-FILE>...    Public key to verify with, given as a file (can be given multiple times)
//!     -n, --signatures <N>                   The number of valid signatures required.  Default: 0
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand store
//!
//! ```text
//! Interacts with key stores
//!
//! USAGE:
//!     sq store [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     add       Add a key identified by fingerprint
//!     delete    Deletes bindings or stores
//!     export    Exports a key
//!     help      Prints this message or the help of the given subcommand(s)
//!     import    Imports a key
//!     list      Lists keys in the store
//!     log       Lists the keystore log
//!     stats     Get stats for the given label
//! ```
//!
//! ### Subcommand store add
//!
//! ```text
//! Add a key identified by fingerprint
//!
//! USAGE:
//!     sq store add <LABEL> <FINGERPRINT>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <LABEL>          Label to use
//!     <FINGERPRINT>    Key to add
//! ```
//!
//! ### Subcommand store delete
//!
//! ```text
//! Deletes bindings or stores
//!
//! USAGE:
//!     sq store delete [FLAGS] [LABEL]
//!
//! FLAGS:
//!     -h, --help         Prints help information
//!         --the-store    Delete the selected store (change with --store)
//!     -V, --version      Prints version information
//!
//! ARGS:
//!     <LABEL>    Delete binding with this label
//! ```
//!
//! ### Subcommand store export
//!
//! ```text
//! Exports a key
//!
//! USAGE:
//!     sq store export [FLAGS] [OPTIONS] <LABEL>
//!
//! FLAGS:
//!     -B, --binary     Don't ASCII-armor encode the OpenPGP data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <LABEL>    Label to use
//! ```
//!
//! ### Subcommand store import
//!
//! ```text
//! Imports a key
//!
//! USAGE:
//!     sq store import <LABEL> [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <LABEL>    Label to use
//!     <FILE>     Sets the input file to use
//! ```
//!
//! ### Subcommand store list
//!
//! ```text
//! Lists keys in the store
//!
//! USAGE:
//!     sq store list
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//! ```
//!
//! ### Subcommand store log
//!
//! ```text
//! Lists the keystore log
//!
//! USAGE:
//!     sq store log [LABEL]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <LABEL>    List messages related to this label
//! ```
//!
//! ### Subcommand store stats
//!
//! ```text
//! Get stats for the given label
//!
//! USAGE:
//!     sq store stats <LABEL>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <LABEL>    Label to use
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
//!     -B, --binary     Don't ASCII-armor encode the OpenPGP data
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
//!     sq keyserver send [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand autocrypt
//!
//! ```text
//! Autocrypt support
//!
//! USAGE:
//!     sq autocrypt [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     decode    Converts Autocrypt-encoded keys to OpenPGP TPKs
//!     help      Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand autocrypt decode
//!
//! ```text
//! Converts Autocrypt-encoded keys to OpenPGP TPKs
//!
//! USAGE:
//!     sq autocrypt decode [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand dearmor
//!
//! ```text
//! Removes ASCII Armor from a file
//!
//! USAGE:
//!     sq dearmor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand enarmor
//!
//! ```text
//! Applies ASCII Armor to a file
//!
//! USAGE:
//!     sq enarmor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --kind <KIND>      Selects the kind of header line to produce [default: file]  [possible values: message,
//!                            publickey, secretkey, signature, file]
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand inspect
//!
//! ```text
//! Inspects a sequence of OpenPGP packets
//!
//! USAGE:
//!     sq inspect [FLAGS] [FILE]
//!
//! FLAGS:
//!         --certifications    Print third-party certifications
//!     -h, --help              Prints help information
//!         --keygrips          Print keygrips of keys and subkeys
//!     -V, --version           Prints version information
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand key
//!
//! ```text
//! Manipulates keys
//!
//! USAGE:
//!     sq key [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     generate    Generates a new key
//!     help        Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand key generate
//!
//! ```text
//! Generates a new key
//!
//! USAGE:
//!     sq key generate [FLAGS] [OPTIONS] --export <OUTFILE>
//!
//! FLAGS:
//!         --can-sign          The key has a signing-capable subkey (default)
//!         --cannot-encrypt    The key will not be able to encrypt data
//!         --cannot-sign       The key will not be able to sign data
//!     -h, --help              Prints help information
//!     -V, --version           Prints version information
//!         --with-password     Prompt for a password to protect the generated key with.
//!
//! OPTIONS:
//!         --can-encrypt <PURPOSE>          The key has an encryption-capable subkey (default) [default: all]  [possible
//!                                          values: transport, rest, all]
//!     -c, --cipher-suite <CIPHER-SUITE>    Cryptographic algorithms used for the key. [default: rsa3k]  [possible values:
//!                                          rsa3k, cv25519]
//!     -e, --export <OUTFILE>               Exports the key instead of saving it in the store
//!         --rev-cert <FILE or ->           Sets the output file for the revocation certificate. Default is <OUTFILE>.rev,
//!                                          mandatory if OUTFILE is '-'.
//!     -u, --userid <EMAIL>                 Primary user ID
//! ```
//!
//! ## Subcommand list
//!
//! ```text
//! Lists key stores and known keys
//!
//! USAGE:
//!     sq list [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     bindings    Lists all bindings in all key stores
//!     help        Prints this message or the help of the given subcommand(s)
//!     keys        Lists all keys in the common key pool
//!     log         Lists the server log
//!     stores      Lists key stores
//! ```
//!
//! ### Subcommand list bindings
//!
//! ```text
//! Lists all bindings in all key stores
//!
//! USAGE:
//!     sq list bindings [PREFIX]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <PREFIX>    List only bindings from stores with the given domain prefix
//! ```
//!
//! ### Subcommand list keys
//!
//! ```text
//! Lists all keys in the common key pool
//!
//! USAGE:
//!     sq list keys
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//! ```
//!
//! ### Subcommand list log
//!
//! ```text
//! Lists the server log
//!
//! USAGE:
//!     sq list log
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//! ```
//!
//! ### Subcommand list stores
//!
//! ```text
//! Lists key stores
//!
//! USAGE:
//!     sq list stores [PREFIX]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <PREFIX>    List only stores with the given domain prefix
//! ```
//!
//! ## Subcommand packet
//!
//! ```text
//! OpenPGP Packet manipulation
//!
//! USAGE:
//!     sq packet [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     dump     Lists OpenPGP packets
//!     help     Prints this message or the help of the given subcommand(s)
//!     split    Splits a message into OpenPGP packets
//! ```
//!
//! ### Subcommand packet dump
//!
//! ```text
//! Lists OpenPGP packets
//!
//! USAGE:
//!     sq packet dump [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -x, --hex        Print a hexdump
//!         --mpis       Print MPIs
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                Sets the output file to use
//!         --session-key <SESSION-KEY>    Session key to decrypt encryption containers
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ### Subcommand packet split
//!
//! ```text
//! Splits a message into OpenPGP packets
//!
//! USAGE:
//!     sq packet split [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -p, --prefix <FILE>    Sets the prefix to use for output files (defaults to the input filename with a dash, or
//!                            'output')
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```

include!("sq.rs");
