//! A command-line frontend for Sequoia.
//!
//! # Usage
//!
//! ```text
//! A command-line frontend for Sequoia, an implementation of OpenPGP
//!
//! Functionality is grouped and available using subcommands.  Currently,
//! this interface is completely stateless.  Therefore, you need to supply
//! all configuration and certificates explicitly on each invocation.
//!
//! OpenPGP data can be provided in binary or ASCII armored form.  This
//! will be handled automatically.  Emitted OpenPGP data is ASCII armored
//! by default.
//!
//! We use the term "certificate", or cert for short, to refer to OpenPGP
//! keys that do not contain secrets.  Conversely, we use the term "key"
//! to refer to OpenPGP keys that do contain secrets.
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
//!     keyring      Manages collections of keys or certs
//!     certify      Certifies a User ID for a Certificate
//!     autocrypt    Communicates certificates using Autocrypt
//!     keyserver    Interacts with keyservers
//!     wkd          Interacts with Web Key Directories
//!     armor        Converts binary to ASCII
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
//! Encrypts a message for any number of recipients and with any number of
//! passwords, optionally signing the message in the process.
//!
//! The converse operation is "sq decrypt".
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
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
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
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!         --private-key-store <KEY_STORE>
//!             Provides parameters for private key store
//!
//!         --recipient-cert <CERT-RING>...
//!             Encrypts for all recipients in CERT-RING
//!
//!         --signer-dsm-key <DSM-KEY-NAME>
//!             Signs the message with a key stored in Fortanix DSM
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
//!
//!
//! EXAMPLES:
//!
//! # Encrypt a file using a certificate
//! $ sq encrypt --recipient-cert romeo.pgp message.txt
//!
//! # Encrypt a file creating a signature in the process
//! $ sq encrypt --recipient-cert romeo.pgp --signer-key juliet.pgp message.txt
//!
//! # Encrypt a file using a password
//! $ sq encrypt --symmetric message.txt
//! ```
//!
//! ## Subcommand decrypt
//!
//! ```text
//! Decrypts a message
//!
//! Decrypts a message using either supplied keys, or by prompting for a
//! password.  If message tampering is detected, an error is returned.
//! See below for details.
//!
//! If certificates are supplied using the "--signer-cert" option, any
//! signatures that are found are checked using these certificates.
//! Verification is only successful if there is no bad signature, and the
//! number of successfully verified signatures reaches the threshold
//! configured with the "--signatures" parameter.
//!
//! If the signature verification fails, or if message tampering is
//! detected, the program terminates with an exit status indicating
//! failure.  In addition to that, the last 25 MiB of the message are
//! withheld, i.e. if the message is smaller than 25 MiB, no output is
//! produced, and if it is larger, then the output will be truncated.
//!
//! The converse operation is "sq encrypt".
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
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Decrypts with secrets stored inside the Fortanix Self-Defending Key-
//!             Management System
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!         --private-key-store <KEY_STORE>
//!             Provides parameters for private key store
//!
//!         --recipient-key <KEY>...
//!             Decrypts with KEY
//!
//!         --signer-cert <CERT>...
//!             Verifies signatures with CERT
//!
//!     -n, --signatures <N>
//!             Sets the threshold of valid signatures to N. The message will only
//!             be considered verified if this threshold is reached. [default: 1 if
//!             at least one signer cert file is given, 0 otherwise]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Decrypt a file using a secret key
//! $ sq decrypt --recipient-key juliet.pgp ciphertext.pgp
//!
//! # Decrypt a file verifying signatures
//! $ sq decrypt --recipient-key juliet.pgp --signer-cert romeo.pgp ciphertext.pgp
//!
//! # Decrypt a file using a password
//! $ sq decrypt ciphertext.pgp
//! ```
//!
//! ## Subcommand sign
//!
//! ```text
//! Signs messages or data files
//!
//! Creates signed messages or detached signatures.  Detached signatures
//! are often used to sign software packages.
//!
//! The converse operation is "sq verify".
//!
//! USAGE:
//!     sq sign [FLAGS] [OPTIONS] [--] [FILE]
//!
//! FLAGS:
//!     -a, --append
//!             Appends a signature to existing signature
//!
//!     -B, --binary
//!             Emits binary data
//!
//!         --cleartext-signature
//!             Creates a cleartext signature
//!
//!         --detached
//!             Creates a detached signature
//!
//!     -h, --help
//!             Prints help information
//!
//!     -n, --notarize
//!             Signs a message and all existing signatures
//!
//!
//! OPTIONS:
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Signs the message with the Fortanix DSM key
//!
//!         --merge <SIGNED-MESSAGE>
//!             Merges signatures from the input and SIGNED-MESSAGE
//!
//!         --notation <NAME> <VALUE>
//!             Adds a notation to the certification.  A user-defined notation's
//!             name must be of the form "name@a.domain.you.control.org". If the
//!             notation's name starts with a !, then the notation is marked as
//!             being critical.  If a consumer of a signature doesn't understand a
//!             critical notation, then it will ignore the signature.  The notation
//!             is marked as being human readable.
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!         --private-key-store <KEY_STORE>
//!             Provides parameters for private key store
//!
//!         --signer-key <KEY>...
//!             Signs using KEY
//!
//!     -t, --time <TIME>
//!             Chooses keys valid at the specified time and sets the signature's
//!             creation time
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Create a signed message
//! $ sq sign --signer-key juliet.pgp message.txt
//!
//! # Create a detached signature
//! $ sq sign --detached --signer-key juliet.pgp message.txt
//! ```
//!
//! ## Subcommand verify
//!
//! ```text
//! Verifies signed messages or detached signatures
//!
//! When verifying signed messages, the message is written to stdout or
//! the file given to --output.
//!
//! When a detached message is verified, no output is produced.  Detached
//! signatures are often used to sign software packages.
//!
//! Verification is only successful if there is no bad signature, and the
//! number of successfully verified signatures reaches the threshold
//! configured with the "--signatures" parameter.  If the verification
//! fails, the program terminates with an exit status indicating failure.
//! In addition to that, the last 25 MiB of the message are withheld,
//! i.e. if the message is smaller than 25 MiB, no output is produced, and
//! if it is larger, then the output will be truncated.
//!
//! The converse operation is "sq sign".
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
//!             1]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Verify a signed message
//! $ sq verify --signer-cert juliet.pgp signed-message.pgp
//!
//! # Verify a detached message
//! $ sq verify --signer-cert juliet.pgp --detached message.sig message.txt
//!
//! SEE ALSO:
//!
//! If you are looking for a standalone program to verify detached
//! signatures, consider using sequoia-sqv.
//! ```
//!
//! ## Subcommand key
//!
//! ```text
//! Manages keys
//!
//! We use the term "key" to refer to OpenPGP keys that do contain
//! secrets.  This subcommand provides primitives to generate and
//! otherwise manipulate keys.
//!
//! Conversely, we use the term "certificate", or cert for short, to refer
//! to OpenPGP keys that do not contain secrets.  See "sq keyring" for
//! operations on certificates.
//!
//! USAGE:
//!     sq key <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! SUBCOMMANDS:
//!     generate                 Generates a new key
//!     password                 Changes password protecting secrets
//!     extract-cert             Converts a key to a cert
//!     extract-dsm-secret       Extracts a secret key from Fortanix DSM
//!     dsm-import
//!             Imports a Transferable Public Key (TPK)/Transferable Secret Key
//!             (TSK) into Fortanix DSM
//!     attest-certifications    Attests to third-party certifications
//!     info                     List details on DSM key
//!     list-dsm-keys            List all accessible keys for the App
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
//! Generating a key is the prerequisite to receiving encrypted messages
//! and creating signatures.  There are a few parameters to this process,
//! but we provide reasonable defaults for most users.
//!
//! When generating a key, we also generate a revocation certificate.
//! This can be used in case the key is superseded, lost, or compromised.
//! It is a good idea to keep a copy of this in a safe place.
//!
//! After generating a key, use "sq key extract-cert" to get the
//! certificate corresponding to the key.  The key must be kept secure,
//! while the certificate should be handed out to correspondents, e.g. by
//! uploading it to a keyserver.
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
//!         --dsm-exportable
//!             (DANGER) Configure the key to be exportable from DSM
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
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --can-encrypt <PURPOSE>
//!             Adds an encryption-capable subkey. Encryption-capable subkeys can be
//!             marked as suitable for transport encryption, storage encryption, or
//!             both. [default: universal] [possible values: transport, storage,
//!             universal]
//!     -c, --cipher-suite <CIPHER-SUITE>
//!             Selects the cryptographic algorithms for the key [default: cv25519]
//!             [possible values: rsa2k, rsa3k, rsa4k, rsa8k, cv25519, nistp256,
//!             nistp384, nistp521]
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Generate secrets inside Fortanix DSM with the given name
//!
//!         --expires <TIME>
//!             Makes the key expire at TIME (as ISO 8601). Use "never" to create
//!             keys that do not expire.
//!         --expires-in <DURATION>
//!             Makes the key expire after DURATION. Either "N[ymwd]", for N years,
//!             months, weeks, or days, or "never".
//!     -e, --export <OUTFILE>
//!             Writes the key to OUTFILE
//!
//!         --key-flags <[C,S,EtEr | CS,EtEr]>
//!             Generate keys using 2-key (CS,EtEr) or 3-key structure (C,S,EtEr)
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!         --rev-cert <FILE or ->
//!             Writes the revocation certificate to FILE. mandatory if OUTFILE is
//!             "-". [default: <OUTFILE>.rev]
//!     -u, --userid <EMAIL>...
//!             Adds a userid to the key
//!
//!
//! EXAMPLES:
//!
//! # First, this generates a key
//! $ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp
//!
//! # Then, this extracts the certificate for distribution
//! $ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
//!
//! # Generates a key protecting it with a password
//! $ sq key generate --userid "<juliet@example.org>" --with-password
//!
//! # Generates a key with multiple userids
//! $ sq key generate --userid "<juliet@example.org>" --userid "Juliet Capulet"
//! ```
//!
//! ### Subcommand key password
//!
//! ```text
//! Changes password protecting secrets
//!
//! Secret key material in keys can be protected by a password.  This
//! subcommand changes or clears this encryption password.
//!
//! To emit the key with unencrypted secrets, either use `--clear` or
//! supply a zero-length password when prompted for the new password.
//!
//! USAGE:
//!     sq key password [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -B, --binary
//!             Emits binary data
//!
//!         --clear
//!             Emit a key with unencrypted secrets
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
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # First, generate a key
//! $ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp
//!
//! # Then, encrypt the secrets in the key with a password.
//! $ sq key password < juliet.key.pgp > juliet.encrypted_key.pgp
//!
//! # And remove the password again.
//! $ sq key password --clear < juliet.encrypted_key.pgp > juliet.decrypted_key.pgp
//! ```
//!
//! ### Subcommand key extract-cert
//!
//! ```text
//! Converts a key to a cert
//!
//! After generating a key, use this command to get the certificate
//! corresponding to the key.  The key must be kept secure, while the
//! certificate should be handed out to correspondents, e.g. by uploading
//! it to a keyserver.
//!
//! USAGE:
//!     sq key extract-cert [FLAGS] [OPTIONS] [FILE]
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
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Extracts the certificate from Fortanix DSM
//!
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # First, this generates a key
//! $ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp
//!
//! # Then, this extracts the certificate for distribution
//! $ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
//! ```
//!
//! ### Subcommand key extract-dsm-secret
//!
//! ```text
//! Extracts key from Fortanix DSM
//!
//! Is a Fortanix DSM key was generated using the `--dsm-exportable` flag, this
//! command exfiltrates secrets from DSM and outputs a Key.
//!
//! USAGE:
//!     sq key extract-dsm-secret [FLAGS] [OPTIONS] --dsm-key <DSM-KEY-NAME>
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
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Name of the DSM key
//!
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//! ```
//!
//! ### Subcommand key dsm-import
//!
//! ```text
//! Imports a Transferable Public Key (TPK)/Transferable Secret Key (TSK) info
//! Fortanix DSM
//!
//! This command unlocks the TSK (if encrypted), and imports it into Fortanix DSM
//! for secure storage and usage.
//!
//! USAGE:
//!     sq key dsm-import [FLAGS] [OPTIONS] --dsm-key <DSM-KEY-NAME>
//!
//! FLAGS:
//!         --dsm-exportable
//!             (DANGER) Configure the key to be exportable from DSM
//!
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --api-key <API-KEY>
//!             Authenticates to Fortanix DSM using the given API key
//!
//!         --app-uuid <APP-UUID>
//!             Authenticates to Fortanix DSM with the given App  (cert-based
//!             authentication)
//!         --client-cert <P12-FILE>
//!             Authenticates to Fortanix DSM with the given client certificate
//!
//!         --dsm-key <DSM-KEY-NAME>
//!             Name of the DSM key
//!
//!         --input <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!         --pkcs12-passphrase <PKCS12-PASSPHRASE>
//!             Passphrase for unlocking the PKCS12 identity file (cert-based
//!             authentication)
//!
//! EXAMPLES:
//!
//! # Import the key into DSM
//! $ sq-dsm key dsm-import --dsm-key="Imported by sq-dsm" < my_priv_key.asc
//! ```
//!
//! ### Subcommand key attest-certifications
//!
//! ```text
//!
//! Attests to third-party certifications allowing for their distribution
//!
//! To prevent certificate flooding attacks, modern key servers prevent
//! uncontrolled distribution of third-party certifications on
//! certificates.  To make the key holder the sovereign over the
//! information over what information is distributed with the certificate,
//! the key holder needs to explicitly attest to third-party
//! certifications.
//!
//! After the attestation has been created, the certificate has to be
//! distributed, e.g. by uploading it to a keyserver.
//!
//! USAGE:
//!     sq key attest-certifications [FLAGS] [OPTIONS] [KEY]
//!
//! FLAGS:
//!         --all
//!             Attests to all certifications [default]
//!
//!     -B, --binary
//!             Emits binary data
//!
//!     -h, --help
//!             Prints help information
//!
//!         --none
//!             Removes all prior attestations
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
//!     <KEY>
//!             Changes attestations on KEY
//!
//!
//! EXAMPLES:
//!
//! # Attest to all certifications present on the key
//! $ sq key attest-certifications juliet.pgp
//!
//! # Retract prior attestations on the key
//! $ sq key attest-certifications --none juliet.pgp
//! ```
//!
//! ### Subcommand key info
//!
//! ```text
//!
//! This command prints data on a given DSM key name, if the key is present.
//!
//! USAGE:
//!     sq key info --dsm-key <DSM-KEY-NAME>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --dsm-key <DSM-KEY-NAME>
//!             Name of the DSM key
//!
//!
//! EXAMPLES:
//!
//! # Prints details on given key
//! $ sq key info --dsm-key 0123456789A
//! ```
//!
//! ### Subcommand key list-dsm-keys
//!
//! ```text
//!
//! This command prints details about all the keys accessible to the app.
//! Command will query DSM list keys API for each group, and club the outputs
//! to print on STDOUT.
//!
//! USAGE:
//!     sq key list-dsm-keys [FLAGS]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -l, --long
//!             prints long details of key
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! EXAMPLES:
//!
//! # Print list of keys which app can access
//! $ sq key list-dsm-keys
//!
//! # Print detailed list of keys which app can access
//! $ sq key list-dsm-keys -l
//! ```
//!
//! ### Subcommand key adopt
//!
//! ```text
//!
//! Binds keys from one certificate to another
//!
//! This command allows one to transfer primary keys and subkeys into an
//! existing certificate.  Say you want to transition to a new
//! certificate, but have an authentication subkey on your current
//! certificate.  You want to keep the authentication subkey because it
//! allows access to SSH servers and updating their configuration is not
//! feasible.
//!
//! USAGE:
//!     sq key adopt [FLAGS] [OPTIONS] --key <KEY>... [--] [TARGET-KEY]
//!
//! FLAGS:
//!         --allow-broken-crypto
//!             Allows adopting keys from certificates using broken cryptography
//!
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
//!     -k, --key <KEY>...
//!             Adds the key or subkey KEY to the TARGET-KEY
//!
//!     -r, --keyring <KEY-RING>...
//!             Supplies keys for use in --key.
//!
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!
//! ARGS:
//!     <TARGET-KEY>
//!             Adds keys to TARGET-KEY
//!
//!
//! EXAMPLES:
//!
//! # Adopt an subkey into the new cert
//! $ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF -- juliet-new.pgp
//! ```
//!
//! ## Subcommand keyring
//!
//! ```text
//! Manages collections of keys or certs
//!
//! Collections of keys or certficicates (also known as "keyrings" when
//! they contain secret key material, and "certrings" when they don't) are
//! any number of concatenated certificates.  This subcommand provides
//! tools to list, split, join, merge, and filter keyrings.
//!
//! Note: In the documentation of this subcommand, we sometimes use the
//! terms keys and certs interchangeably.
//!
//! USAGE:
//!     sq keyring <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! SUBCOMMANDS:
//!     list      Lists keys in a keyring
//!     split     Splits a keyring into individual keys
//!     join      Joins keys or keyrings into a single keyring
//!     merge     Merges keys or keyrings into a single keyring
//!     filter    Joins keys into a keyring applying a filter
//!     help      Prints this message or the help of the given subcommand(s)
//! ```
//!
//! ### Subcommand keyring list
//!
//! ```text
//! Lists keys in a keyring
//!
//! Prints the fingerprint as well as the primary userid for every
//! certificate encountered in the keyring.
//!
//! USAGE:
//!     sq keyring list [FLAGS] [FILE]
//!
//! FLAGS:
//!         --all-userids
//!             Lists all user ids, even those that are expired, revoked, or not
//!             valid under the standard policy.
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # List all certs
//! $ sq keyring list certs.pgp
//!
//! # List all certs with a userid on example.org
//! $ sq keyring filter --domain example.org certs.pgp | sq keyring list
//! ```
//!
//! ### Subcommand keyring split
//!
//! ```text
//! Splits a keyring into individual keys
//!
//! Splitting up a keyring into individual keys helps with curating a
//! keyring.
//!
//! The converse operation is "sq keyring join".
//!
//! USAGE:
//!     sq keyring split [FLAGS] [OPTIONS] [FILE]
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
//!     -p, --prefix <FILE>
//!             Writes to files with prefix FILE [defaults to the input filename
//!             with a dash, or "output" if keyring is read from stdin]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Split all certs
//! $ sq keyring split certs.pgp
//!
//! # Split all certs, merging them first to avoid duplicates
//! $ sq keyring merge certs.pgp | sq keyring split
//! ```
//!
//! ### Subcommand keyring join
//!
//! ```text
//! Joins keys or keyrings into a single keyring
//!
//! Unlike "sq keyring merge", multiple versions of the same key are not
//! merged together.
//!
//! The converse operation is "sq keyring split".
//!
//! USAGE:
//!     sq keyring join [FLAGS] [OPTIONS] [FILE]...
//!
//! FLAGS:
//!     -B, --binary
//!             Don't ASCII-armor the keyring
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
//!
//!
//! EXAMPLES:
//!
//! # Collect certs for an email conversation
//! $ sq keyring join juliet.pgp romeo.pgp alice.pgp
//! ```
//!
//! ### Subcommand keyring merge
//!
//! ```text
//! Merges keys or keyrings into a single keyring
//!
//! Unlike "sq keyring join", the certificates are buffered and multiple
//! versions of the same certificate are merged together.  Where data is
//! replaced (e.g., secret key material), data from the later certificate
//! is preferred.
//!
//! USAGE:
//!     sq keyring merge [FLAGS] [OPTIONS] [FILE]...
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
//!
//!
//! EXAMPLES:
//!
//! # Merge certificate updates
//! $ sq keyring merge certs.pgp romeo-updates.pgp
//! ```
//!
//! ### Subcommand keyring filter
//!
//! ```text
//! Joins keys into a keyring applying a filter
//!
//! This can be used to filter keys based on given predicates,
//! e.g. whether they have a user id containing an email address with a
//! certain domain.  Additionally, the keys can be pruned to only include
//! components matching the predicates.
//!
//! If no filters are supplied, everything matches.
//!
//! If multiple predicates are given, they are or'ed, i.e. a key matches
//! if any of the predicates match.  To require all predicates to match,
//! chain multiple invocations of this command.  See EXAMPLES for
//! inspiration.
//!
//! USAGE:
//!     sq keyring filter [FLAGS] [OPTIONS] [--] [FILE]...
//!
//! FLAGS:
//!     -B, --binary
//!             Emits binary data
//!
//!     -h, --help
//!             Prints help information
//!
//!     -P, --prune-certs
//!             Removes certificate components not matching the filter
//!
//!         --to-cert
//!             Converts any keys in the input to certificates.  Converting a key to
//!             a certificate removes secret key material from the key thereby
//!             turning it into a certificate.
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --domain <FQDN>...
//!             Parses user ids into name and email address and case-sensitively
//!             matches on the domain of the email address, requiring an exact
//!             match.
//!         --email <ADDRESS>...
//!             Parses user ids into name and email address and case-sensitively
//!             matches on the email address, requiring an exact match.
//!         --name <NAME>...
//!             Parses user ids into name and email and case-sensitively matches on
//!             the name, requiring an exact match.
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --userid <USERID>...
//!             Case-sensitively matches on the user id, requiring an exact match.
//!
//!
//! ARGS:
//!     <FILE>...
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Converts a key to a cert (i.e., remove any secret key material)
//! $ sq keyring filter --to-cert cat juliet.pgp
//!
//! # Gets the keys with a user id on example.org
//! $ sq keyring filter --domain example.org keys.pgp
//!
//! # Gets the keys with a user id on example.org or example.net
//! $ sq keyring filter --domain example.org --domain example.net keys.pgp
//!
//! # Gets the keys with a user id with the name Juliet
//! $ sq keyring filter --name Juliet keys.pgp
//!
//! # Gets the keys with a user id with the name Juliet on example.org
//! $ sq keyring filter --domain example.org keys.pgp | \
//!   sq keyring filter --name Juliet
//!
//! # Gets the keys with a user id on example.org, pruning other userids
//! $ sq keyring filter --domain example.org --prune-certs certs.pgp
//! ```
//!
//! ## Subcommand certify
//!
//! ```text
//!
//! Certifies a User ID for a Certificate
//!
//! Using a certification a keyholder may vouch for the fact that another
//! certificate legitimately belongs to a user id.  In the context of
//! emails this means that the same entity controls the key and the email
//! address.  These kind of certifications form the basis for the Web Of
//! Trust.
//!
//! This command emits the certificate with the new certification.  The
//! updated certificate has to be distributed, preferably by sending it to
//! the certificate holder for attestation.  See also "sq key
//! attest-certification".
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
//!             Makes the certification expire at TIME (as ISO 8601). Use "never" to
//!             create certifications that do not expire.
//!         --expires-in <DURATION>
//!             Makes the certification expire after DURATION. Either "N[ymwd]", for
//!             N years, months, weeks, or days, or "never".  [default: 5y]
//!         --notation <NAME> <VALUE>
//!             Adds a notation to the certification.  A user-defined notation's
//!             name must be of the form "name@a.domain.you.control.org". If the
//!             notation's name starts with a !, then the notation is marked as
//!             being critical.  If a consumer of a signature doesn't understand a
//!             critical notation, then it will ignore the signature.  The notation
//!             is marked as being human readable.
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
//!
//!
//! EXAMPLES:
//!
//! # Juliet certifies that Romeo controls romeo.pgp and romeo@example.org
//! $ sq certify juliet.pgp romeo.pgp "<romeo@example.org>"
//! ```
//!
//! ## Subcommand autocrypt
//!
//! ```text
//! Communicates certificates using Autocrypt
//!
//! Autocrypt is a standard for mail user agents to provide convenient
//! end-to-end encryption of emails.  This subcommand provides a limited
//! way to produce and consume headers that are used by Autocrypt to
//! communicate certificates between clients.
//!
//! See https://autocrypt.org/
//!
//! USAGE:
//!     sq autocrypt <SUBCOMMAND>
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! SUBCOMMANDS:
//!     decode           Reads Autocrypt-encoded certificates
//!     encode-sender    Encodes a certificate into an Autocrypt header
//!     help             Prints this message or the help of the given
//!                      subcommand(s)
//! ```
//!
//! ### Subcommand autocrypt decode
//!
//! ```text
//! Reads Autocrypt-encoded certificates
//!
//! Given an autocrypt header (or an key-gossip header), this command
//! extracts the certificate encoded within it.
//!
//! The converse operation is "sq autocrypt encode-sender".
//!
//! USAGE:
//!     sq autocrypt decode [FLAGS] [OPTIONS] [FILE]
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
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Extract all certificates from a mail
//! $ sq autocrypt decode autocrypt.eml
//! ```
//!
//! ### Subcommand autocrypt encode-sender
//!
//! ```text
//! Encodes a certificate into an Autocrypt header
//!
//! A certificate can be encoded and included in a header of an email
//! message.  This command encodes the certificate, adds the senders email
//! address (which must match the one used in the "From" header), and the
//! senders "prefer-encrypt" state (see the Autocrypt spec for more
//! information).
//!
//! The converse operation is "sq autocrypt decode".
//!
//! USAGE:
//!     sq autocrypt encode-sender [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!         --email <ADDRESS>
//!             Sets the address [default: primary userid]
//!
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --prefer-encrypt <prefer-encrypt>
//!             Sets the prefer-encrypt attribute [default: nopreference]  [possible
//!             values: nopreference, mutual]
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Encodes a certificate
//! $ sq autocrypt encode-sender juliet.pgp
//!
//! # Encodes a certificate with an explicit sender address
//! $ sq autocrypt encode-sender --email juliet@example.org juliet.pgp
//!
//! # Encodes a certificate while indicating the willingness to encrypt
//! $ sq autocrypt encode-sender --prefer-encrypt mutual juliet.pgp
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
//! Converts binary to ASCII
//!
//! To make encrypted data easier to handle and transport, OpenPGP data
//! can be transformed to an ASCII representation called ASCII Armor.  sq
//! emits armored data by default, but this subcommand can be used to
//! convert existing OpenPGP data to its ASCII-encoded representation.
//!
//! The converse operation is "sq dearmor".
//!
//! USAGE:
//!     sq armor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! OPTIONS:
//!         --label <LABEL>
//!             Selects the kind of armor header [default: auto]  [possible values:
//!             auto, message, cert, key, sig, file]
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Convert a binary certificate to ASCII
//! $ sq armor binary-juliet.pgp
//!
//! # Convert a binary message to ASCII
//! $ sq armor binary-message.pgp
//! ```
//!
//! ## Subcommand dearmor
//!
//! ```text
//! Converts ASCII to binary
//!
//! To make encrypted data easier to handle and transport, OpenPGP data
//! can be transformed to an ASCII representation called ASCII Armor.  sq
//! transparently handles armored data, but this subcommand can be used to
//! explicitly convert existing ASCII-encoded OpenPGP data to its binary
//! representation.
//!
//! The converse operation is "sq armor".
//!
//! USAGE:
//!     sq dearmor [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Convert a ASCII certificate to binary
//! $ sq dearmor ascii-juliet.pgp
//!
//! # Convert a ASCII message to binary
//! $ sq dearmor ascii-message.pgp
//! ```
//!
//! ## Subcommand inspect
//!
//! ```text
//! Inspects data, like file(1)
//!
//! It is often difficult to tell from cursory inspection using cat(1) or
//! file(1) what kind of OpenPGP one is looking at.  This subcommand
//! inspects the data and provides a meaningful human-readable description
//! of it.
//!
//! USAGE:
//!     sq inspect [FLAGS] [FILE]
//!
//! FLAGS:
//!         --certifications
//!             Prints third-party certifications
//!
//!     -h, --help
//!             Prints help information
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Inspects a certificate
//! $ sq inspect juliet.pgp
//!
//! # Inspects a certificate ring
//! $ sq inspect certs.pgp
//!
//! # Inspects a message
//! $ sq inspect message.pgp
//!
//! # Inspects a detached signature
//! $ sq inspect message.sig
//! ```
//!
//! ## Subcommand packet
//!
//! ```text
//!
//! Low-level packet manipulation
//!
//! An OpenPGP data stream consists of packets.  These tools allow working
//! with packet streams.  They are mostly of interest to developers, but
//! "sq packet dump" may be helpful to a wider audience both to provide
//! valuable information in bug reports to OpenPGP-related software, and
//! as a learning tool.
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
//!
//! Lists packets
//!
//! Creates a human-readable description of the packet sequence.
//! Additionally, it can print cryptographic artifacts, and print the raw
//! octet stream similar to hexdump(1), annotating specifically which
//! bytes are parsed into OpenPGP values.
//!
//! To inspect encrypted messages, either supply the session key, or see
//! "sq decrypt --dump" or "sq packet decrypt".
//!
//! USAGE:
//!     sq packet dump [FLAGS] [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -x, --hex
//!             Prints a hexdump
//!
//!         --mpis
//!             Prints cryptographic artifacts
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!         --session-key <SESSION-KEY>
//!             Decrypts an encrypted message using SESSION-KEY
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Prints the packets of a certificate
//! $ sq packet dump juliet.pgp
//!
//! # Prints cryptographic artifacts of a certificate
//! $ sq packet dump --mpis juliet.pgp
//!
//! # Prints a hexdump of a certificate
//! $ sq packet dump --hex juliet.pgp
//!
//! # Prints the packets of an encrypted message
//! $ sq packet dump --session-key AAAABBBBCCCC... ciphertext.pgp
//! ```
//!
//! ### Subcommand packet decrypt
//!
//! ```text
//!
//! Unwraps an encryption container
//!
//! Decrypts a message, dumping the content of the encryption container
//! without further processing.  The result is a valid OpenPGP message
//! that can, among other things, be inspected using "sq packet dump".
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
//!         --private-key-store <KEY_STORE>
//!             Provides parameters for private key store
//!
//!         --recipient-key <KEY>...
//!             Decrypts the message with KEY
//!
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Unwraps the encryption revealing the signed message
//! $ sq packet decrypt --recipient-key juliet.pgp ciphertext.pgp
//! ```
//!
//! ### Subcommand packet split
//!
//! ```text
//!
//! Splits a message into packets
//!
//! Splitting a packet sequence into individual packets, then recombining
//! them freely with "sq packet join" is a great way to experiment with
//! OpenPGP data.
//!
//! The converse operation is "sq packet join".
//!
//! USAGE:
//!     sq packet split [OPTIONS] [FILE]
//!
//! FLAGS:
//!     -h, --help
//!             Prints help information
//!
//!     -V, --version
//!             Prints version information
//!
//!
//! OPTIONS:
//!     -p, --prefix <PREFIX>
//!             Writes to files with PREFIX [defaults: FILE a dash, or "output" if
//!             read from stdin)
//!
//! ARGS:
//!     <FILE>
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Split a certificate into individual packets
//! $ sq packet split juliet.pgp
//! ```
//!
//! ### Subcommand packet join
//!
//! ```text
//!
//! Joins packets split across files
//!
//! Splitting a packet sequence into individual packets, then recombining
//! them freely with "sq packet join" is a great way to experiment with
//! OpenPGP data.
//!
//! The converse operation is "sq packet split".
//!
//! USAGE:
//!     sq packet join [FLAGS] [OPTIONS] [FILE]...
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
//!         --label <LABEL>
//!             Selects the kind of armor header [default: auto]  [possible values:
//!             auto, message, cert, key, sig, file]
//!     -o, --output <FILE>
//!             Writes to FILE or stdout if omitted
//!
//!
//! ARGS:
//!     <FILE>...
//!             Reads from FILE or stdin if omitted
//!
//!
//! EXAMPLES:
//!
//! # Split a certificate into individual packets
//! $ sq packet split juliet.pgp
//!
//! # Then join only a subset of these packets
//! $ sq packet join juliet.pgp-[0-3]*
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

include!("sq.rs");
