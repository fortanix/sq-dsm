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
//!         --known-notation <NOTATION>...
//!             The notation name is considered known. This is used when validating
//!             signatures. Signatures that have unknown notations with the critical
//!             bit set are considered invalid.
//!     -p, --policy <NETWORK-POLICY>         Sets the network policy to use
//!
//! SUBCOMMANDS:
//!     encrypt             Encrypts a message
//!     decrypt             Decrypts an OpenPGP message
//!     sign                Signs a message
//!     verify              Verifies a message
//!     merge-signatures    Merges two signatures
//!     key                 Manipulates keys
//!     certring            Manipulates certificate rings
//!     autocrypt           Autocrypt support
//!     keyserver           Interacts with keyservers
//!     wkd                 Interacts with Web Key Directories
//!     armor               Applies ASCII Armor to a file
//!     dearmor             Removes ASCII Armor from a file
//!     inspect             Inspects a sequence of OpenPGP packets
//!     packet              OpenPGP Packet manipulation
//!     help                Prints this message or the help of the given
//!                         subcommand(s)
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
//!     -s, --symmetric             Encrypt with a password (can be given multiple
//!                                 times)
//!         --use-expired-subkey    If a certificate has only expired encryption-
//!                                 capable subkeys, fall back to using
//!                                 the one that expired last
//!     -V, --version               Prints version information
//!
//! OPTIONS:
//!         --compression <KIND>
//!             Selects compression scheme to use [default: pad]  [possible values:
//!             none, pad, zip, zlib, bzip2]
//!         --mode <MODE>
//!             Selects what kind of keys are considered for encryption.  Transport
//!             select subkeys marked as suitable for transport encryption, rest
//!             selects those for encrypting data at rest, and all selects all
//!             encryption-capable subkeys [default: all]  [possible values:
//!             transport, rest, all]
//!     -o, --output <FILE>                    Sets the output file to use
//!         --recipient-cert <CERT-RING>...
//!             Recipients to encrypt for, given as a file (can be given multiple
//!             times)
//!         --signer-key <KEY>...
//!             Secret key to sign with, given as a file (can be given multiple
//!             times)
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's
//!             creation time
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
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
//!     -o, --output <FILE>             Sets the output file to use
//!         --recipient-key <KEY>...
//!             Secret key to decrypt with, given as a file (can be given multiple
//!             times)
//!         --signer-cert <CERT>...
//!             The sender's certificate to verify signatures with, given as a file
//!             (can be given multiple times)
//!     -n, --signatures <N>
//!             The number of valid signatures required.  Default: 0
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
//!     -o, --output <FILE>          Sets the output file to use
//!         --signer-key <KEY>...
//!             Secret key to sign with, given as a file (can be given multiple
//!             times)
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's
//!             creation time
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
//!         --detached <SIG>           Verifies a detached signature
//!     -o, --output <FILE>            Sets the output file to use
//!         --signer-cert <CERT>...
//!             The sender's certificate to verify signatures with, given as a file
//!             (can be given multiple times)
//!     -n, --signatures <N>
//!             The number of valid signatures required.  Default: 0
//!
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ## Subcommand merge-signatures
//!
//! ```text
//! Merges two signatures
//!
//! USAGE:
//!     sq merge-signatures [OPTIONS] [ARGS]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>    Sets the first input file to use
//!     <FILE>    Sets the second input file to use
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
//!     adopt                    Bind keys from one certificate to another.
//!     attest-certifications
//!             Attests third-party certifications allowing for their distribution
//!
//!     generate                 Generates a new key
//!     help
//!             Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand key adopt
//!
//! ```text
//! Bind keys from one certificate to another.
//!
//! USAGE:
//!     sq key adopt [FLAGS] [OPTIONS] <CERT> --key <KEY>...
//!
//! FLAGS:
//!         --allow-broken-crypto
//!             Allows adopting keys from certificates using broken cryptography.
//!
//!     -h, --help                   Prints help information
//!     -V, --version                Prints version information
//!
//! OPTIONS:
//!     -k, --key <KEY>...
//!             Adds the specified key or subkey to the certificate.
//!
//!     -r, --keyring <KEYRING>...
//!             A keyring containing the keys specified in --key.
//!
//!
//! ARGS:
//!     <CERT>    The certificate to add keys to.
//! ```
//!
//! ### Subcommand key attest-certifications
//!
//! ```text
//! Attests third-party certifications allowing for their distribution
//!
//! USAGE:
//!     sq key attest-certifications [FLAGS] <KEY>
//!
//! FLAGS:
//!         --all        Attest to all certifications
//!     -h, --help       Prints help information
//!         --none       Remove all prior attestations
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <KEY>    Change attestations on this key.
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
//!         --with-password     Prompt for a password to protect the generated key
//!                             with.
//!
//! OPTIONS:
//!         --can-encrypt <PURPOSE>
//!             The key has an encryption-capable subkey (default: universal)
//!             [possible values: transport, storage, universal]
//!     -c, --cipher-suite <CIPHER-SUITE>
//!             Cryptographic algorithms used for the key. [default: cv25519]
//!             [possible values: rsa3k, rsa4k, cv25519]
//!         --expires <TIME>
//!             Absolute time When the key should expire, or 'never'.
//!
//!         --expires-in <DURATION>
//!             Relative time when the key should expire.  Either 'N[ymwd]', for N
//!             years, months, weeks, or days, or 'never'.
//!     -e, --export <OUTFILE>
//!             Exports the key instead of saving it in the store
//!
//!         --rev-cert <FILE or ->
//!             Sets the output file for the revocation certificate. Default is
//!             <OUTFILE>.rev, mandatory if OUTFILE is '-'.
//!     -u, --userid <EMAIL>...
//!             Add userid to the key (can be given multiple times)
//! ```
//!
//! ## Subcommand certring
//!
//! ```text
//! Manipulates certificate rings
//!
//! USAGE:
//!     sq certring <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! SUBCOMMANDS:
//!     filter    Joins certs into a certring applying a filter
//!     help      Prints this message or the help of the given subcommand(s)
//!     join      Joins certs into a certring
//!     list      Lists certs in a certring
//!     split     Splits a certring into individual certs
//! ```
//!
//! ### Subcommand certring filter
//!
//! ```text
//! If multiple predicates are given, they are or'ed, i.e. a certificate matches if
//! any of the predicates match.  To require all predicates to match, chain multiple
//! invocations of this command.
//!
//! USAGE:
//!     sq certring filter [FLAGS] [OPTIONS] [--] [FILE]...
//!
//! FLAGS:
//!     -B, --binary
//!             Don't ASCII-armor the certring
//!
//!     -h, --help
//!             Prints help information
//!
//!     -P, --prune-certs
//!             Remove certificate components not matching the filter
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --domain <FQDN>...
//!             Match on this email domain name
//!
//!         --email <ADDRESS>...
//!             Match on this email address
//!
//!         --name <NAME>...
//!             Match on this name
//!
//!     -o, --output <FILE>
//!             Sets the output file to use
//!
//!
//! ARGS:
//!     <FILE>...
//!             Sets the input files to use
//! ```
//!
//! ### Subcommand certring join
//!
//! ```text
//! Joins certs into a certring
//!
//! USAGE:
//!     sq certring join [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary     Don't ASCII-armor the certring
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Sets the output file to use
//!
//! ARGS:
//!     <FILE>...    Sets the input files to use
//! ```
//!
//! ### Subcommand certring list
//!
//! ```text
//! Lists certs in a certring
//!
//! USAGE:
//!     sq certring list [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```
//!
//! ### Subcommand certring split
//!
//! ```text
//! Splits a certring into individual certs
//!
//! USAGE:
//!     sq certring split [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -p, --prefix <FILE>    Sets the prefix to use for output files (defaults to
//!                            the input filename with a dash, or 'output' if
//!                            certring is read from stdin)
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
//!     encode-sender    Encodes the sender's OpenPGP Certificates into an
//!                      Autocrypt header
//!     help             Prints this message or the help of the given
//!                      subcommand(s)
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
//!         --address <address>
//!             Select userid to use.  [default: primary userid]
//!
//!     -o, --output <FILE>                      Sets the output file to use
//!         --prefer-encrypt <prefer-encrypt>
//!             Sets the prefer-encrypt attribute [default: nopreference]  [possible
//!             values: nopreference, mutual]
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
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
//!     <QUERY>    Fingerprint, KeyID, or email address of the cert(s) to
//!                retrieve
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
//!     generate    Generates a Web Key Directory for the given domain and keys.
//!                 If the WKD exists, the new keys will be inserted and it is
//!                 updated and existing ones will be updated.
//!     get         Writes to the standard output the Cert retrieved from a Web
//!                 Key Directory, given an email address
//!     help        Prints this message or the help of the given subcommand(s)
//!     url         Prints the Web Key Directory URL of an email address.
//! ```
//!
//! ### Subcommand wkd generate
//!
//! ```text
//! Generates a Web Key Directory for the given domain and keys.  If the WKD exists,
//! the new keys will be inserted and it is updated and existing ones will be
//! updated.
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
//!     <WEB-ROOT>    The location to write the WKD to. This must be the
//!                   directory the webserver is serving the '.well-known'
//!                   directory from.
//!     <DOMAIN>      The domain for the WKD.
//!     <KEYRING>     The keyring file with the keys to add to the WKD.
//! ```
//!
//! ### Subcommand wkd get
//!
//! ```text
//! Writes to the standard output the Cert retrieved from a Web Key Directory, given
//! an email address
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
//!     <EMAIL_ADDRESS>    The email address from which to obtain the Cert from
//!                        a WKD.
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
//!
//! ## Subcommand armor
//!
//! ```text
//! Applies ASCII Armor to a file
//!
//! USAGE:
//!     sq armor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --kind <KIND>      Selects the kind of header line to produce [default:
//!                            file]  [possible values: message, publickey,
//!                            secretkey, signature, file]
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
//!     -V, --version           Prints version information
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
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
//!     decrypt    Decrypts an OpenPGP message, dumping the content of the
//!                encryption container without further processing
//!     dump       Lists OpenPGP packets
//!     help       Prints this message or the help of the given subcommand(s)
//!     join       Joins OpenPGP packets split across files
//!     split      Splits a message into OpenPGP packets
//! ```
//!
//! ### Subcommand packet decrypt
//!
//! ```text
//! Decrypts an OpenPGP message, dumping the content of the encryption container
//! without further processing
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
//!     -o, --output <FILE>             Sets the output file to use
//!         --recipient-key <KEY>...
//!             Secret key to decrypt with, given as a file (can be given multiple
//!             times)
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
//!         --session-key <SESSION-KEY>
//!             Session key to decrypt encryption containers
//!
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
//!         --kind <KIND>      Selects the kind of header line to produce [default:
//!                            file]  [possible values: message, publickey,
//!                            secretkey, signature, file]
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
//!     -p, --prefix <FILE>    Sets the prefix to use for output files (defaults to
//!                            the input filename with a dash, or 'output')
//!
//! ARGS:
//!     <FILE>    Sets the input file to use
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

include!("sq.rs");
