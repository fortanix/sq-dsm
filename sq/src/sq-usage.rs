//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! Sequoia is an implementation of OpenPGP.  This is a command-line frontend.
//!
//! USAGE:
//!     sq [FLAGS] [OPTIONS] <SUBCOMMAND>
//!
//! FLAGS:
//!     -f, --force      Overwrite existing files
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --home <DIRECTORY>                Sets the home directory to use
//!         --known-notation <NOTATION>...    The notation name is considered known. This is used when validating
//!                                           signatures. Signatures that have unknown notations with the critical bit set
//!                                           are considered invalid.
//!     -m, --mapping <MAPPING>               Sets the realm and mapping to use [default: org.sequoia-pgp.contacts/default]
//!     -p, --policy <NETWORK-POLICY>         Sets the network policy to use
//!
//! SUBCOMMANDS:
//!     decrypt      Decrypts an OpenPGP message
//!     encrypt      Encrypts a message
//!     sign         Signs a message
//!     verify       Verifies a message
//!     mapping      Interacts with key mappings
//!     keyserver    Interacts with keyservers
//!     autocrypt    Autocrypt support
//!     dearmor      Removes ASCII Armor from a file
//!     enarmor      Applies ASCII Armor to a file
//!     help         Prints this message or the help of the given subcommand(s)
//!     inspect      Inspects a sequence of OpenPGP packets
//!     key          Manipulates keys
//!     list         Lists key mappings and known keys
//!     packet       OpenPGP Packet manipulation
//!     wkd          Interacts with Web Key Directories
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
//!     -o, --output <FILE>                      Sets the output file to use
//!         --secret-key-file <TSK-FILE>...      Secret key to decrypt with, given as a file (can be given multiple times)
//!         --sender-cert-file <CERT-FILE>...    The sender's certificate verify signatures with, given as a file (can be
//!                                              given multiple times)
//!     -n, --signatures <N>                     The number of valid signatures required.  Default: 0
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
//!     -B, --binary                Don't ASCII-armor encode the OpenPGP data
//!     -h, --help                  Prints help information
//!     -s, --symmetric             Encrypt with a password (can be given multiple times)
//!         --use-expired-subkey    If a certificate has only expired encryption-capable subkeys, fall back to using the one
//!                                 that expired last
//!     -V, --version               Prints version information
//!
//! OPTIONS:
//!         --compression <KIND>
//!             Selects compression scheme to use [default: pad]  [possible values: none, pad, zip, zlib, bzip2]
//!
//!         --mode <MODE>
//!             Selects what kind of keys are considered for encryption.  Transport select subkeys marked as suitable for
//!             transport encryption, rest selects those for encrypting data at rest, and all selects all encryption-capable
//!             subkeys [default: all]  [possible values: transport, rest, all]
//!     -o, --output <FILE>                           Sets the output file to use
//!     -r, --recipient <LABEL>...                    Recipient to encrypt for (can be given multiple times)
//!         --recipients-cert-file <CERTS-FILE>...
//!             Recipients to encrypt for, given as a file (can be given multiple times)
//!
//!         --signer-key-file <TSK-FILE>...           Secret key to sign with, given as a file (can be given multiple times)
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's creation time
//!
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
//!     -t, --time <TIME>                      Chooses keys valid at the specified time and sets the signature's creation
//!                                            time
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
//!         --detached <SIG-FILE>                Verifies a detached signature
//!     -o, --output <FILE>                      Sets the output file to use
//!         --sender-cert-file <CERT-FILE>...    The sender's certificate verify signatures with, given as a file (can be
//!                                              given multiple times)
//!     -n, --signatures <N>                     The number of valid signatures required.  Default: 0
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand mapping
//!
//! ```text
//! Interacts with key mappings
//!
//! USAGE:
//!     sq mapping <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     add       Add a key identified by fingerprint
//!     delete    Deletes bindings or mappings
//!     export    Exports a key
//!     help      Prints this message or the help of the given subcommand(s)
//!     import    Imports a key
//!     list      Lists keys in the mapping
//!     log       Lists the keystore log
//!     stats     Get stats for the given label
//! ```
//!
//! ### Subcommand mapping add
//!
//! ```text
//! Add a key identified by fingerprint
//!
//! USAGE:
//!     sq mapping add <LABEL> <FINGERPRINT>
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
//! ### Subcommand mapping delete
//!
//! ```text
//! Deletes bindings or mappings
//!
//! USAGE:
//!     sq mapping delete [FLAGS] [LABEL]
//!
//! FLAGS:
//!     -h, --help           Prints help information
//!         --the-mapping    Delete the selected mapping (change with --mapping)
//!     -V, --version        Prints version information
//!
//! ARGS:
//!     <LABEL>    Delete binding with this label
//! ```
//!
//! ### Subcommand mapping export
//!
//! ```text
//! Exports a key
//!
//! USAGE:
//!     sq mapping export [FLAGS] [OPTIONS] <LABEL>
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
//! ### Subcommand mapping import
//!
//! ```text
//! Imports a key
//!
//! USAGE:
//!     sq mapping import <LABEL> [FILE]
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
//! ### Subcommand mapping list
//!
//! ```text
//! Lists keys in the mapping
//!
//! USAGE:
//!     sq mapping list
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//! ```
//!
//! ### Subcommand mapping log
//!
//! ```text
//! Lists the keystore log
//!
//! USAGE:
//!     sq mapping log [LABEL]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <LABEL>    List messages related to this label
//! ```
//!
//! ### Subcommand mapping stats
//!
//! ```text
//! Get stats for the given label
//!
//! USAGE:
//!     sq mapping stats <LABEL>
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
//!     sq keyserver [OPTIONS] <SUBCOMMAND>
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
//!     sq keyserver get [FLAGS] [OPTIONS] <QUERY>
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
//!     <QUERY>    Fingerprint, KeyID, or email address of the cert(s) to retrieve
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
//!     sq autocrypt <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     decode           Converts Autocrypt-encoded keys to OpenPGP Certificates
//!     encode-sender    Encodes the sender's OpenPGP Certificates into an Autocrypt header
//!     help             Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand autocrypt decode
//!
//! ```text
//! Converts Autocrypt-encoded keys to OpenPGP Certificates
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
//! ### Subcommand autocrypt encode-sender
//!
//! ```text
//! Encodes the sender's OpenPGP Certificates into an Autocrypt header
//!
//! USAGE:
//!     sq autocrypt encode-sender [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --address <address>                  Select userid to use.  [default: primary userid]
//!     -o, --output <FILE>                      Sets the output file to use
//!         --prefer-encrypt <prefer-encrypt>    Sets the prefer-encrypt attribute [default: nopreference]  [possible
//!                                              values: nopreference, mutual]
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
//!     sq key <SUBCOMMAND>
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
//!         --can-encrypt <PURPOSE>          The key has an encryption-capable subkey (default: universal) [possible values:
//!                                          transport, storage, universal]
//!     -c, --cipher-suite <CIPHER-SUITE>    Cryptographic algorithms used for the key. [default: cv25519]  [possible
//!                                          values: rsa3k, rsa4k, cv25519]
//!         --expires <TIME>                 Absolute time When the key should expire, or 'never'.
//!         --expires-in <DURATION>          Relative time when the key should expire.  Either 'N[ymwd]', for N years,
//!                                          months, weeks, or days, or 'never'.
//!     -e, --export <OUTFILE>               Exports the key instead of saving it in the store
//!         --rev-cert <FILE or ->           Sets the output file for the revocation certificate. Default is <OUTFILE>.rev,
//!                                          mandatory if OUTFILE is '-'.
//!     -u, --userid <EMAIL>...              Add userid to the key (can be given multiple times)
//! ```
//!
//! ## Subcommand list
//!
//! ```text
//! Lists key mappings and known keys
//!
//! USAGE:
//!     sq list <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     bindings    Lists all bindings in all key mappings
//!     help        Prints this message or the help of the given subcommand(s)
//!     keys        Lists all keys in the common key pool
//!     log         Lists the server log
//!     mappings    Lists key mappings
//! ```
//!
//! ### Subcommand list bindings
//!
//! ```text
//! Lists all bindings in all key mappings
//!
//! USAGE:
//!     sq list bindings [PREFIX]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <PREFIX>    List only bindings from mappings with the given realm prefix
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
//! ### Subcommand list mappings
//!
//! ```text
//! Lists key mappings
//!
//! USAGE:
//!     sq list mappings [PREFIX]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <PREFIX>    List only mappings with the given realm prefix
//! ```
//!
//! ## Subcommand packet
//!
//! ```text
//! OpenPGP Packet manipulation
//!
//! USAGE:
//!     sq packet <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     decrypt    Decrypts an OpenPGP message, dumping the content of the encryption container without further
//!                processing
//!     dump       Lists OpenPGP packets
//!     help       Prints this message or the help of the given subcommand(s)
//!     join       Joins OpenPGP packets split across files
//!     split      Splits a message into OpenPGP packets
//! ```
//!
//! ### Subcommand packet decrypt
//!
//! ```text
//! Decrypts an OpenPGP message, dumping the content of the encryption container without further processing
//!
//! USAGE:
//!     sq packet decrypt [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -B, --binary              Don't ASCII-armor encode the OpenPGP data
//!         --dump-session-key    Prints the session key to stderr
//!     -h, --help                Prints help information
//!     -V, --version             Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                    Sets the output file to use
//!         --secret-key-file <TSK-FILE>...    Secret key to decrypt with, given as a file (can be given multiple times)
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
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
//! ### Subcommand packet join
//!
//! ```text
//! Joins OpenPGP packets split across files
//!
//! USAGE:
//!     sq packet join [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary     Don't ASCII-armor encode the OpenPGP data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --kind <KIND>      Selects the kind of header line to produce [default: file]  [possible values: message,
//!                            publickey, secretkey, signature, file]
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>...    Sets the input files to use
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
//!
//! ## Subcommand wkd
//!
//! ```text
//! Interacts with Web Key Directories
//!
//! USAGE:
//!     sq wkd <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     generate    Generates a Web Key Directory for the given domain and keys.  If the WKD exists, the new keys will
//!                 be inserted and it is updated and existing ones will be updated.
//!     get         Writes to the standard output the Cert retrieved from a Web Key Directory, given an email address
//!     help        Prints this message or the help of the given subcommand(s)
//!     url         Prints the Web Key Directory URL of an email address.
//! ```
//!
//! ### Subcommand wkd generate
//!
//! ```text
//! Generates a Web Key Directory for the given domain and keys.  If the WKD exists, the new keys will be inserted and it is
//! updated and existing ones will be updated.
//!
//! USAGE:
//!     sq wkd generate [FLAGS] <WEB-ROOT> <DOMAIN> [KEYRING]
//!
//! FLAGS:
//!     -d, --direct_method    Use the direct method. [default: advanced method]
//!     -h, --help             Prints help information
//!     -V, --version          Prints version information
//!
//! ARGS:
//!     <WEB-ROOT>    The location to write the WKD to. This must be the directory the webserver is serving the '.well-
//!                   known' directory from.
//!     <DOMAIN>      The domain for the WKD.
//!     <KEYRING>     The keyring file with the keys to add to the WKD.
//! ```
//!
//! ### Subcommand wkd get
//!
//! ```text
//! Writes to the standard output the Cert retrieved from a Web Key Directory, given an email address
//!
//! USAGE:
//!     sq wkd get [FLAGS] <EMAIL_ADDRESS>
//!
//! FLAGS:
//!     -B, --binary     Don't ASCII-armor encode the OpenPGP data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <EMAIL_ADDRESS>    The email address from which to obtain the Cert from a WKD.
//! ```
//!
//! ### Subcommand wkd url
//!
//! ```text
//! Prints the Web Key Directory URL of an email address.
//!
//! USAGE:
//!     sq wkd url <EMAIL_ADDRESS>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <EMAIL_ADDRESS>    The email address from which to obtain the WKD URI.
//! ```

include!("sq.rs");
