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
//!     -f, --force
//!             Overwrites existing files
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --known-notation <NOTATION>...
//!             Adds NOTATION to the list of known notations. This is used when
//!             validating signatures. Signatures that have unknown notations with
//!             the critical bit set are considered invalid.
//!
//! SUBCOMMANDS:
//!     encrypt      Encrypts a message
//!     decrypt      Decrypts a message
//!     sign         Signs messages or data files
//!     verify       Verifies signed messages or detached signatures
//!     key          Manages keys
//!     certring     Manages collections of certificates
//!     certify      Certifies a User ID for a Certificate
//!     autocrypt    Communicates certificates using Autocrypt
//!     keyserver    Interacts with keyservers
//!     wkd          Interacts with Web Key Directories
//!     armor        Converts binary data to ASCII
//!     dearmor      Converts ASCII to binary
//!     inspect      Inspects data, like file(1)
//!     packet       Low-level packet manipulation
//!     help         Prints this message or the help of the given subcommand(s)
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
//!     -B, --binary
//!             Emits binary data
//!
//!     -h, --help
//!             Prints help information
//!
//!     -s, --symmetric
//!             Adds a password to encrypt with.  The message can be decrypted with
//!             either one of the recipient's keys, or any password.
//!         --use-expired-subkey
//!             If a certificate has only expired encryption-capable subkeys, falls
//!             back to using the one that expired last
//!
//! OPTIONS:
//!         --compression <KIND>
//!             Selects compression scheme to use [default: pad]  [possible values:
//!             none, pad, zip, zlib, bzip2]
//!         --mode <MODE>
//!             Selects what kind of keys are considered for encryption.  Transport
//!             select subkeys marked as suitable for transport encryption, rest
//!             selects those for encrypting data at rest, and all selects all
//!             encryption-capable subkeys. [default: all]  [possible values:
//!             transport, rest, all]
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --recipient-cert <CERT-RING>...
//!             Encrypts for all recipients in CERT-RING
//!
//!         --signer-key <KEY>...
//!             Signs the message with KEY
//!
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's
//!             creation time
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand decrypt
//!
//! ```text
//! Decrypts a message
//!
//! USAGE:
//!     sq decrypt [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!         --dump
//!             Prints a packet dump to stderr
//!
//!         --dump-session-key
//!             Prints the session key to stderr
//!
//!     -h, --help
//!             Prints help information
//!
//!     -x, --hex
//!             Prints a hexdump (implies --dump)
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --recipient-key <KEY>...
//!             Decrypts with KEY
//!
//!         --signer-cert <CERT>...
//!             Verifies signatures with CERT
//!
//!     -n, --signatures <N>
//!             Sets the threshold of valid signatures to N. If this threshold is
//!             not reached, the message will not be considered verified. [default:
//!             0]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand sign
//!
//! ```text
//! Signs messages or data files
//!
//! USAGE:
//!     sq sign [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -a, --append      Appends a signature to existing signature
//!     -B, --binary      Emits binary data
//!         --detached    Creates a detached signature
//!     -h, --help        Prints help information
//!     -n, --notarize    Signs a message and all existing signatures
//!
//! OPTIONS:
//!         --merge <SIGNED-MESSAGE>
//!             Merges signatures from the input and SIGNED-MESSAGE
//!
//!     -o, --output <FILE>             Writes to FILE or stdout if omitted
//!         --signer-key <KEY>...       Signs using KEY
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's
//!             creation time
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand verify
//!
//! ```text
//! Verifies signed messages or detached signatures
//!
//! USAGE:
//!     sq verify [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! OPTIONS:
//!         --detached <SIG>
//!             Verifies a detached signature
//!
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --signer-cert <CERT>...
//!             Verifies signatures with CERT
//!
//!     -n, --signatures <N>
//!             Sets the threshold of valid signatures to N. If this threshold is
//!             not reached, the message will not be considered verified. [default:
//!             0]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand key
//!
//! ```text
//! Manages keys
//!
//! USAGE:
//!     sq key <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help    Prints help information
//!
//! SUBCOMMANDS:
//!     generate                 Generates a new key
//!     attest-certifications
//!             Attests third-party certifications allowing for their distribution
//!
//!     adopt                    Binds keys from one certificate to another
//!     help
//!             Prints this message or the help of the given subcommand(s)
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
//!         --can-sign
//!             Adds a signing-capable subkey (default)
//!
//!         --cannot-encrypt
//!             Adds no encryption-capable subkey
//!
//!         --cannot-sign
//!             Adds no signing-capable subkey
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!         --with-password
//!             Protects the key with a password
//!
//!
//! OPTIONS:
//!         --can-encrypt <PURPOSE>
//!             Adds an encryption-capable subkey. Encryption-capable subkeys can be
//!             marked as suitable for transport encryption, storage encryption, or
//!             both. [default: universal] [possible values: transport, storage,
//!             universal]
//!     -c, --cipher-suite <CIPHER-SUITE>
//!             Selects the cryptographic algorithms for the key [default: cv25519]
//!             [possible values: rsa3k, rsa4k, cv25519]
//!         --expires <TIME>
//!             Makes the key expire at TIME (as ISO 8601). Use 'never' to create
//!             keys that do not expire.
//!         --expires-in <DURATION>
//!             Makes the key expire after DURATION. Either 'N[ymwd]', for N years,
//!             months, weeks, or days, or 'never'.
//!     -e, --export <OUTFILE>
//!             Writes the key to OUTFILE
//!
//!         --rev-cert <FILE or ->
//!             Writes the revocation certificate to FILE. mandatory if OUTFILE is
//!             '-'. [default: <OUTFILE>.rev]
//!     -u, --userid <EMAIL>...
//!             Adds a userid to the key
//! ```
//!
//! ### Subcommand key attest-certifications
//!
//! ```text
//! Attests third-party certifications allowing for their distribution
//!
//! USAGE:
//!     sq key attest-certifications [FLAGS] [OPTIONS] <KEY>
//!
//! FLAGS:
//!         --all        Attests to all certifications
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!         --none       Removes all prior attestations
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <KEY>    Changes attestations on KEY
//! ```
//!
//! ### Subcommand key adopt
//!
//! ```text
//! Binds keys from one certificate to another
//!
//! USAGE:
//!     sq key adopt [FLAGS] [OPTIONS] <TARGET-KEY> --key <KEY>...
//!
//! FLAGS:
//!         --allow-broken-crypto
//!             Allows adopting keys from certificates using broken cryptography
//!
//!     -B, --binary                 Emits binary data
//!     -h, --help                   Prints help information
//!     -V, --version                Prints version information
//!
//! OPTIONS:
//!     -k, --key <KEY>...             Adds the key or subkey KEY to the TARGET-KEY
//!     -r, --keyring <KEY-RING>...    Supplies keys for use in --key.
//!     -o, --output <FILE>            Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <TARGET-KEY>    Adds keys to TARGET-KEY
//! ```
//!
//! ## Subcommand certring
//!
//! ```text
//! Manages collections of certificates (also known as 'keyrings').
//!
//! USAGE:
//!     sq certring <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! SUBCOMMANDS:
//!     filter    Joins certs into a certring applying a filter
//!     help      Prints this message or the help of the given subcommand(s)
//!     join      Joins certs or certrings into a single certring
//!     list      Lists certs in a certring
//!     merge     Merges certs or certrings into a single certring
//!     split     Splits a certring into individual certs
//! ```
//!
//! ### Subcommand certring filter
//!
//! ```text
//! Joins certs into a certring applying a filter
//!
//! USAGE:
//!     sq certring filter [FLAGS] [OPTIONS] [--] [FILE]...
//!
//! FLAGS:
//!     -B, --binary         Emits binary data
//!     -h, --help           Prints help information
//!     -P, --prune-certs    Removes certificate components not matching the filter
//!     -V, --version        Prints version information
//!
//! OPTIONS:
//!         --domain <FQDN>...      Matches on email domain FQDN
//!         --email <ADDRESS>...    Matches on email ADDRESS
//!         --name <NAME>...        Matches on NAME
//!     -o, --output <FILE>         Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <FILE>...    Reads from FILE or stdin if omitted
//!
//! If multiple predicates are given, they are or'ed, i.e. a certificate matches if
//! any of the predicates match.  To require all predicates to match, chain multiple
//! invocations of this command:
//!
//! $ cat certs.pgp | sq certring filter --domain example.org | sq certring filter
//! --name Juliett
//! ```
//!
//! ### Subcommand certring join
//!
//! ```text
//! Joins certs or certrings into a single certring.
//!
//! Unlike 'sq certring merge', multiple versions of the same certificate are not
//! merged together.
//!
//! USAGE:
//!     sq certring join [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary
//!             Don't ASCII-armor the certring
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Sets the output file to use
//!
//!
//! ARGS:
//!     <FILE>...
//!             Sets the input files to use
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
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ### Subcommand certring merge
//!
//! ```text
//! Merges certs or certrings into a single certring.
//!
//! Unlike 'sq certring join', the certificates are buffered and multiple versions
//! of the same certificate are merged together.  Where data is replaced (e.g.,
//! secret key material), data from the later certificate is preferred.
//!
//! USAGE:
//!     sq certring merge [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary
//!             Emits binary data
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!
//! ARGS:
//!     <FILE>...
//!             Reads from FILE
//! ```
//!
//! ### Subcommand certring split
//!
//! ```text
//! Splits a certring into individual certs
//!
//! USAGE:
//!     sq certring split [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -p, --prefix <FILE>    Writes to files with prefix FILE [defaults to the
//!                            input filename with a dash, or 'output' if certring
//!                            is read from stdin]
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand certify
//!
//! ```text
//! Certifies a User ID for a Certificate
//!
//! USAGE:
//!     sq certify [FLAGS] [OPTIONS] <CERTIFIER-KEY> <CERTIFICATE> <USERID>
//!
//! FLAGS:
//!     -B, --binary
//!             Emits binary data
//!
//!     -h, --help
//!             Prints help information
//!
//!     -l, --local
//!             Makes the certification a local certification.  Normally, local
//!             certifications are not exported.
//!         --non-revocable
//!             Marks the certification as being non-revocable. That is, you cannot
//!             later revoke this certification.  This should normally only be used
//!             with an expiration.
//!
//! OPTIONS:
//!     -a, --amount <TRUST_AMOUNT>
//!             Sets the amount of trust.  Values between 1 and 120 are meaningful.
//!             120 means fully trusted.  Values less than 120 indicate the degree
//!             of trust.  60 is usually used for partially trusted.  The default is
//!             120.
//!     -d, --depth <TRUST_DEPTH>
//!             Sets the trust depth (sometimes referred to as the trust level).  0
//!             means a normal certification of <CERTIFICATE, USERID>.  1 means
//!             CERTIFICATE is also a trusted introducer, 2 means CERTIFICATE is a
//!             meta-trusted introducer, etc.  The default is 0.
//!         --expires <TIME>
//!             Makes the certification expire at TIME (as ISO 8601). Use 'never' to
//!             create certifications that do not expire.
//!         --expires-in <DURATION>
//!             Makes the certification expire after DURATION. Either 'N[ymwd]', for
//!             N years, months, weeks, or days, or 'never'.  [default: 5y]
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!     -r, --regex <REGEX>...
//!             Adds a regular expression to constrain what a trusted introducer can
//!             certify.  The regular expression must match the certified User ID in
//!             all intermediate introducers, and the certified certificate.
//!             Multiple regular expressions may be specified.  In that case, at
//!             least one must match.
//!
//! ARGS:
//!     <CERTIFIER-KEY>
//!             Creates the certificate using CERTIFIER-KEY.
//!
//!     <CERTIFICATE>
//!             Certifies CERTIFICATE.
//!
//!     <USERID>
//!             Certifies USERID for CERTIFICATE.
//! ```
//!
//! ## Subcommand autocrypt
//!
//! ```text
//! Communicates certificates using Autocrypt
//!
//! USAGE:
//!     sq autocrypt <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help    Prints help information
//!
//! SUBCOMMANDS:
//!     decode           Reads Autocrypt-encoded certificates
//!     encode-sender    Encodes the sender's OpenPGP Certificates into an
//!                      Autocrypt header
//!     help             Prints this message or the help of the given
//!                      subcommand(s)
//! ```
//!
//! ### Subcommand autocrypt decode
//!
//! ```text
//! Reads Autocrypt-encoded certificates
//!
//! USAGE:
//!     sq autocrypt decode [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
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
//!         --email <ADDRESS>
//!             Sets the address [default: primary userid]
//!
//!     -o, --output <FILE>                      Writes to FILE or stdout if omitted
//!         --prefer-encrypt <prefer-encrypt>
//!             Sets the prefer-encrypt attribute [default: nopreference]  [possible
//!             values: nopreference, mutual]
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
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
//!     -h, --help    Prints help information
//!
//! OPTIONS:
//!     -p, --policy <NETWORK-POLICY>
//!             Sets the network policy to use [default: encrypted]  [possible
//!             values: offline, anonymized, encrypted, insecure]
//!     -s, --server <URI>               Sets the keyserver to use
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
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <QUERY>    Retrieve certificate(s) using QUERY. This may be a
//!                fingerprint, a KeyID, or an email address.
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
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand wkd
//!
//! ```text
//! Interacts with Web Key Directories
//!
//! USAGE:
//!     sq wkd [OPTIONS] <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help    Prints help information
//!
//! OPTIONS:
//!     -p, --policy <NETWORK-POLICY>
//!             Sets the network policy to use [default: encrypted]  [possible
//!             values: offline, anonymized, encrypted, insecure]
//!
//! SUBCOMMANDS:
//!     generate    Generates a Web Key Directory for the given domain and keys.
//!                 If the WKD exists, the new keys will be inserted and it is
//!                 updated and existing ones will be updated.
//!     get         Queries for certs using Web Key Directory
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
//!     sq wkd generate [FLAGS] <WEB-ROOT> <FQDN> [CERT-RING]
//!
//! FLAGS:
//!     -d, --direct-method
//!             Uses the direct method [default: advanced method]
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! ARGS:
//!     <WEB-ROOT>
//!             Writes the WKD to WEB-ROOT. Transfer this directory to the
//!             webserver.
//!     <FQDN>
//!             Generates a WKD for FQDN
//!
//!     <CERT-RING>
//!             Adds certificates from CERT-RING to the WKD
//! ```
//!
//! ### Subcommand wkd get
//!
//! ```text
//! Queries for certs using Web Key Directory
//!
//! USAGE:
//!     sq wkd get [FLAGS] <ADDRESS>
//!
//! FLAGS:
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <ADDRESS>    Queries a cert for ADDRESS
//! ```
//!
//! ### Subcommand wkd url
//!
//! ```text
//! Prints the Web Key Directory URL of an email address.
//!
//! USAGE:
//!     sq wkd url <ADDRESS>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! ARGS:
//!     <ADDRESS>    Queries for ADDRESS
//! ```
//!
//! ## Subcommand armor
//!
//! ```text
//! Converts binary data to ASCII
//!
//! USAGE:
//!     sq armor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help    Prints help information
//!
//! OPTIONS:
//!         --kind <KIND>      Selects the kind of armor header [default: file]
//!                            [possible values: message, publickey, secretkey,
//!                            signature, file]
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand dearmor
//!
//! ```text
//! Converts ASCII to binary
//!
//! USAGE:
//!     sq dearmor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help    Prints help information
//!
//! OPTIONS:
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand inspect
//!
//! ```text
//! Inspects data, like file(1)
//!
//! USAGE:
//!     sq inspect [FLAGS] [FILE]
//!
//! FLAGS:
//!         --certifications    Prints third-party certifications
//!     -h, --help              Prints help information
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ## Subcommand packet
//!
//! ```text
//! Low-level packet manipulation
//!
//! USAGE:
//!     sq packet <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! SUBCOMMANDS:
//!     dump       Lists packets
//!     decrypt    Unwraps an encryption container
//!     split      Splits a message into packets
//!     join       Joins packets split across files
//!     help       Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand packet dump
//!
//! ```text
//! Lists packets
//!
//! USAGE:
//!     sq packet dump [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -x, --hex        Prints a hexdump
//!         --mpis       Prints cryptographic artifacts
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -o, --output <FILE>                Writes to FILE or stdout if omitted
//!         --session-key <SESSION-KEY>
//!             Decrypts an encrypted message using SESSION-KEY
//!
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ### Subcommand packet decrypt
//!
//! ```text
//! Decrypts a message, dumping the content of the encryption container without
//! further processing
//!
//! USAGE:
//!     sq packet decrypt [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -B, --binary
//!             Emits binary data
//!
//!         --dump-session-key
//!             Prints the session key to stderr
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --recipient-key <KEY>...
//!             Decrypts the message with KEY
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//! ```
//!
//! ### Subcommand packet split
//!
//! ```text
//! Splits a message into packets
//!
//! USAGE:
//!     sq packet split [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -p, --prefix <PREFIX>    Writes to files with PREFIX [defaults: FILE a dash,
//!                              or 'output' if read from stdin)
//!
//! ARGS:
//!     <FILE>    Reads from FILE or stdin if omitted
//! ```
//!
//! ### Subcommand packet join
//!
//! ```text
//! Joins packets split across files
//!
//! USAGE:
//!     sq packet join [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary     Emits binary data
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!         --kind <KIND>      Selects the kind of armor header [default: file]
//!                            [possible values: message, publickey, secretkey,
//!                            signature, file]
//!     -o, --output <FILE>    Writes to FILE or stdout if omitted
//!
//! ARGS:
//!     <FILE>...    Reads from FILE or stdin if omitted
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

include!("sq.rs");
