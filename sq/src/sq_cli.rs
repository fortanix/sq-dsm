/// Command-line parser for sq.

use clap::{App, Arg, ArgGroup, SubCommand, AppSettings};

pub fn build() -> App<'static, 'static> {
    configure(App::new("sq"),
              cfg!(feature = "net"),
              cfg!(feature = "autocrypt"),
    )
}

/// Defines the CLI.
///
/// The order of top-level subcommands is:
///
///   - Encryption & decryption             (1xx)
///   - Signing & verification              (2xx)
///   - Key & cert-ring management          (3xx)
///   - Key discovery & networking          (4xx)
///   - Armor                               (5xx)
///   - Inspection & packet manipulation    (6xx)
pub fn configure(
    app: App<'static, 'static>,
    feature_net: bool,
    feature_autocrypt: bool,
) -> App<'static, 'static> {
    let version = Box::leak(
        format!("{} (sequoia-openpgp {})",
                env!("CARGO_PKG_VERSION"),
                sequoia_openpgp::VERSION)
            .into_boxed_str()) as &str;

    let app = app
        .version(version)
        .about("A command-line frontend for Sequoia, \
                an implementation of OpenPGP")
        .long_about(
"A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  Currently,
this interface is completely stateless.  Therefore, you need to supply
all configuration and certificates explicitly on each invocation.

OpenPGP data can be provided in binary or ASCII armored form.  This
will be handled automatically.  Emitted OpenPGP data is ASCII armored
by default.

We use the term \"certificate\", or cert for short, to refer to OpenPGP
keys that do not contain secrets.  Conversely, we use the term \"key\"
to refer to OpenPGP keys that do contain secrets.
")
        .settings(&[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::VersionlessSubcommands,
        ])
        .arg(Arg::with_name("force")
             .short("f").long("force")
             .help("Overwrites existing files"))
        .arg(Arg::with_name("known-notation")
             .long("known-notation").value_name("NOTATION")
             .multiple(true).number_of_values(1)
             .help("Adds NOTATION to the list of known notations")
             .long_help("Adds NOTATION to the list of known notations. \
               This is used when validating signatures. \
               Signatures that have unknown notations with the \
               critical bit set are considered invalid."))

        .subcommand(SubCommand::with_name("decrypt")
                    .display_order(110)
                    .about("Decrypts a message")
                    .long_about(
"Decrypts a message

Decrypts a message using either supplied keys, or by prompting for a
password.  Any signatures are checked using the supplied certificates.

The converse operation is \"sq encrypt\".
")
                    .after_help(
"EXAMPLES:

# Decrypt a file using a secret key
$ sq decrypt --recipient-key juliet.pgp ciphertext.pgp

# Decrypt a file verifying signatures
$ sq decrypt --recipient-key juliet.pgp --signer-cert romeo.pgp ciphertext.pgp

# Decrypt a file using a password
$ sq decrypt ciphertext.pgp
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("signatures")
                         .short("n").long("signatures").value_name("N")
                         .default_value("0")
                         .help("Sets the threshold of valid signatures to N")
                         .long_help(
                             "Sets the threshold of valid signatures to N. \
                              If this threshold is not reached, the message \
                              will not be considered verified."))
                    .arg(Arg::with_name("sender-cert-file")
                         .long("signer-cert").value_name("CERT")
                         .multiple(true).number_of_values(1)
                         .help("Verifies signatures with CERT"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("recipient-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Decrypts with KEY"))
                    .arg(Arg::with_name("dump-session-key")
                         .long("dump-session-key")
                         .help("Prints the session key to stderr"))
                    .arg(Arg::with_name("dump")
                         .long("dump")
                         .help("Prints a packet dump to stderr"))
                    .arg(Arg::with_name("hex")
                         .short("x").long("hex")
                         .help("Prints a hexdump (implies --dump)"))
        )

        .subcommand(SubCommand::with_name("encrypt")
                    .display_order(100)
                    .about("Encrypts a message")
                    .long_about(
"Encrypts a message

Encrypts a message for any number of recipients and with any number of
passwords, optionally signing the message in the process.

The converse operation is \"sq decrypt\".
")
                    .after_help(
"EXAMPLES:

# Encrypt a file using a certificate
$ sq encrypt --recipient-cert romeo.pgp message.txt

# Encrypt a file creating a signature in the process
$ sq encrypt --recipient-cert romeo.pgp --signer-key juliet.pgp message.txt

# Encrypt a file using a password
$ sq encrypt --symmetric message.txt
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("binary")
                         .short("B").long("binary")
                         .help("Emits binary data"))
                    .arg(Arg::with_name("recipients-cert-file")
                         .long("recipient-cert").value_name("CERT-RING")
                         .multiple(true).number_of_values(1)
                         .help("Encrypts for all recipients in CERT-RING"))
                    .arg(Arg::with_name("signer-key-file")
                         .long("signer-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Signs the message with KEY"))
                    .arg(Arg::with_name("symmetric")
                         .short("s").long("symmetric")
                         .multiple(true)
                         .help("Adds a password to encrypt with")
                         .long_help("Adds a password to encrypt with.  \
                                     The message can be decrypted with \
                                     either one of the recipient's keys, \
                                     or any password."))
                    .arg(Arg::with_name("mode")
                         .long("mode").value_name("MODE")
                         .possible_values(&["transport", "rest", "all"])
                         .default_value("all")
                         .help("Selects what kind of keys are considered for \
                                encryption.")
                         .long_help(
                             "Selects what kind of keys are considered for \
                                encryption.  Transport select subkeys marked \
                                as suitable for transport encryption, rest \
                                selects those for encrypting data at rest, \
                                and all selects all encryption-capable \
                                subkeys."))
                    .arg(Arg::with_name("compression")
                         .long("compression").value_name("KIND")
                         .possible_values(&["none", "pad", "zip", "zlib",
                                            "bzip2"])
                         .default_value("pad")
                         .help("Selects compression scheme to use"))
                    .arg(Arg::with_name("time")
                         .short("t").long("time").value_name("TIME")
                         .help("Chooses keys valid at the specified time and \
                                sets the signature's creation time"))
                    .arg(Arg::with_name("use-expired-subkey")
                         .long("use-expired-subkey")
                         .help("Falls back to expired encryption subkeys")
                         .long_help(
                             "If a certificate has only expired \
                              encryption-capable subkeys, falls back \
                              to using the one that expired last"))
        )

        .subcommand(SubCommand::with_name("sign")
                    .display_order(200)
                    .about("Signs messages or data files")
                    .long_about(
"Signs messages or data files

Creates signed messages or detached signatures.  Detached signatures
are often used to sign software packages.

The converse operation is \"sq verify\".
")
                    .after_help(
"EXAMPLES:

# Create a signed message
$ sq sign --signer-key juliet.pgp message.txt

# Create a detached signature
$ sq sign --detached --signer-key juliet.pgp message.txt
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("binary")
                         .short("B").long("binary")
                         .help("Emits binary data"))
                    .arg(Arg::with_name("detached")
                         .long("detached")
                         .help("Creates a detached signature"))
                    .arg(Arg::with_name("clearsign")
                         .long("cleartext-signature")
                         .conflicts_with_all(&[
                             "detached",
                             "append",
                             "notarize",
                             "binary",
                         ])
                         .help("Creates a cleartext signature"))
                    .arg(Arg::with_name("append")
                         .short("a").long("append")
                         .conflicts_with("notarize")
                         .help("Appends a signature to existing signature"))
                    .arg(Arg::with_name("notarize")
                         .short("n").long("notarize")
                         .conflicts_with("append")
                         .help("Signs a message and all existing signatures"))
                    .arg(Arg::with_name("merge")
                         .long("merge").value_name("SIGNED-MESSAGE")
                         .conflicts_with_all(&[
                             "append",
                             "detached",
                             "clearsign",
                             "notarize",
                             "secret-key-file",
                             "time",
                         ])
                         .help("Merges signatures from the input and \
                                SIGNED-MESSAGE"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("signer-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Signs using KEY"))
                    .arg(Arg::with_name("time")
                         .short("t").long("time").value_name("TIME")
                         .help("Chooses keys valid at the specified time and \
                                sets the signature's creation time"))
                    .arg(Arg::with_name("notation")
                         .value_names(&["NAME", "VALUE"])
                         .long("notation")
                         .multiple(true).number_of_values(2)
                         .help("Adds a notation to the certification.")
                         .long_help(
                             "Adds a notation to the certification.  \
                              A user-defined notation's name must be of \
                              the form \"name@a.domain.you.control.org\". \
                              If the notation's name starts with a !, \
                              then the notation is marked as being \
                              critical.  If a consumer of a signature \
                              doesn't understand a critical notation, \
                              then it will ignore the signature.  The \
                              notation is marked as being human readable.")
                         .conflicts_with("merge"))
        )

        .subcommand(SubCommand::with_name("verify")
                    .display_order(210)
                    .about("Verifies signed messages or detached signatures")
                    .long_about(
"Verifies signed messages or detached signatures

When verifying signed messages, the message is written to stdout or
the file given to --output.

When a detached message is verified, no output is produced.  Detached
signatures are often used to sign software packages.

The converse operation is \"sq sign\".
")
                    .after_help(
"EXAMPLES:

# Verify a signed message
$ sq verify --signer-cert juliet.pgp signed-message.pgp

# Verify a detached message
$ sq verify --signer-cert juliet.pgp --detached message.sig message.txt

SEE ALSO:

If you are looking for a standalone program to verify detached
signatures, consider using sequoia-sqv.
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("detached")
                         .long("detached").value_name("SIG")
                         .help("Verifies a detached signature"))
                    .arg(Arg::with_name("signatures")
                         .short("n").long("signatures").value_name("N")
                         .default_value("0")
                         .help("Sets the threshold of valid signatures to N")
                         .long_help(
                             "Sets the threshold of valid signatures to N. \
                              If this threshold is not reached, the message \
                              will not be considered verified."))
                    .arg(Arg::with_name("sender-cert-file")
                         .long("signer-cert").value_name("CERT")
                         .multiple(true).number_of_values(1)
                         .help("Verifies signatures with CERT"))
        )

        .subcommand(SubCommand::with_name("armor")
                    .display_order(500)
                    .about("Converts binary to ASCII")
                    .long_about(
"Converts binary to ASCII

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
emits armored data by default, but this subcommand can be used to
convert existing OpenPGP data to its ASCII-encoded representation.

The converse operation is \"sq dearmor\".
")
                    .after_help(
"EXAMPLES:

# Convert a binary certificate to ASCII
$ sq armor binary-juliet.pgp

# Convert a binary message to ASCII
$ sq armor binary-message.pgp
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("kind")
                         .long("label").value_name("LABEL")
                         .possible_values(&["auto", "message",
                                            "cert", "key", "sig",
                                            "file"])
                         .default_value("auto")
                         .help("Selects the kind of armor header"))
        )

        .subcommand(SubCommand::with_name("dearmor")
                    .display_order(510)
                    .about("Converts ASCII to binary")
                    .long_about(
"Converts ASCII to binary

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
transparently handles armored data, but this subcommand can be used to
explicitly convert existing ASCII-encoded OpenPGP data to its binary
representation.

The converse operation is \"sq armor\".
")
                    .after_help(
"EXAMPLES:

# Convert a ASCII certificate to binary
$ sq dearmor ascii-juliet.pgp

# Convert a ASCII message to binary
$ sq dearmor ascii-message.pgp
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
        )


        .subcommand(SubCommand::with_name("inspect")
                    .display_order(600)
                    .about("Inspects data, like file(1)")
                    .long_about(
"Inspects data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or
file(1) what kind of OpenPGP one is looking at.  This subcommand
inspects the data and provides a meaningful human-readable description
of it.
")
                    .after_help(
"EXAMPLES:

# Inspects a certificate
$ sq inspect juliet.pgp

# Inspects a certificate ring
$ sq inspect certs.pgp

# Inspects a message
$ sq inspect message.pgp

# Inspects a detached signature
$ sq inspect message.sig
")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("certifications")
                         .long("certifications")
                         .help("Prints third-party certifications"))
        )

        .subcommand(
            SubCommand::with_name("key")
                .display_order(300)
                .about("Manages keys")
                    .long_about(
"Manages keys

We use the term \"key\" to refer to OpenPGP keys that do contain
secrets.  This subcommand provides primitives to generate and
otherwise manipulate keys.

Conversely, we use the term \"certificate\", or cert for short, to refer
to OpenPGP keys that do not contain secrets.  See \"sq keyring\" for
operations on certificates.
")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .display_order(100)
                        .about("Generates a new key")
                        .long_about(
"Generates a new key

Generating a key is the prerequisite to receiving encrypted messages
and creating signatures.  There are a few parameters to this process,
but we provide reasonable defaults for most users.

When generating a key, we also generate a revocation certificate.
This can be used in case the key is superseded, lost, or compromised.
It is a good idea to keep a copy of this in a safe place.

After generating a key, use \"sq key extract-cert\" to get the
certificate corresponding to the key.  The key must be kept secure,
while the certificate should be handed out to correspondents, e.g. by
uploading it to a keyserver.
")
                        .after_help(
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp

# Generates a key protecting it with a password
$ sq key generate --userid \"<juliet@example.org>\" --with-password

# Generates a key with multiple userids
$ sq key generate --userid \"<juliet@example.org>\" --userid \"Juliet Capulet\"
")
                        .arg(Arg::with_name("userid")
                             .short("u").long("userid").value_name("EMAIL")
                             .multiple(true).number_of_values(1)
                             .help("Adds a userid to the key"))
                        .arg(Arg::with_name("cipher-suite")
                             .short("c").long("cipher-suite").value_name("CIPHER-SUITE")
                             .possible_values(&["rsa3k", "rsa4k", "cv25519"])
                             .default_value("cv25519")
                             .help("Selects the cryptographic algorithms for \
                                    the key"))
                        .arg(Arg::with_name("with-password")
                             .long("with-password")
                             .help("Protects the key with a password"))

                        .group(ArgGroup::with_name("expiration-group")
                               .args(&["expires", "expires-in"]))

                        .arg(Arg::with_name("expires")
                             .long("expires").value_name("TIME")
                             .help("Makes the key expire at TIME (as ISO 8601)")
                             .long_help(
                                 "Makes the key expire at TIME (as ISO 8601). \
                                  Use \"never\" to create keys that do not \
                                  expire."))
                        .arg(Arg::with_name("expires-in")
                             .long("expires-in").value_name("DURATION")
                             // Catch negative numbers.
                             .allow_hyphen_values(true)
                             .help("Makes the key expire after DURATION \
                                    (as N[ymwd]) [default: 3y]")
                             .long_help(
                                 "Makes the key expire after DURATION. \
                                  Either \"N[ymwd]\", for N years, months, \
                                  weeks, or days, or \"never\"."))

                        .group(ArgGroup::with_name("cap-sign")
                               .args(&["can-sign", "cannot-sign"]))
                        .arg(Arg::with_name("can-sign")
                             .long("can-sign")
                             .help("Adds a signing-capable subkey (default)"))
                        .arg(Arg::with_name("cannot-sign")
                             .long("cannot-sign")
                             .help("Adds no signing-capable subkey"))

                        .group(ArgGroup::with_name("cap-encrypt")
                               .args(&["can-encrypt", "cannot-encrypt"]))
                        .arg(Arg::with_name("can-encrypt")
                             .long("can-encrypt").value_name("PURPOSE")
                             .possible_values(&["transport", "storage",
                                                "universal"])
                             .help("Adds an encryption-capable subkey \
                                    [default: universal]")
                             .long_help(
                                 "Adds an encryption-capable subkey. \
                                  Encryption-capable subkeys can be marked as \
                                  suitable for transport encryption, storage \
                                  encryption, or both. \
                                  [default: universal]"))
                        .arg(Arg::with_name("cannot-encrypt")
                             .long("cannot-encrypt")
                             .help("Adds no encryption-capable subkey"))

                        .arg(Arg::with_name("export")
                             .short("e").long("export").value_name("OUTFILE")
                             .help("Writes the key to OUTFILE")
                             .required(true))
                        .arg(Arg::with_name("rev-cert")
                             .long("rev-cert").value_name("FILE or -")
                             .required_if("export", "-")
                             .help("Writes the revocation certificate to FILE")
                             .long_help(
                                 "Writes the revocation certificate to FILE. \
                                  mandatory if OUTFILE is \"-\". \
                                  [default: <OUTFILE>.rev]"))
                )
                .subcommand(SubCommand::with_name("extract-cert")
                            .display_order(110)
                            .about("Converts a key to a cert")
                            .long_about(
"Converts a key to a cert

After generating a key, use this command to get the certificate
corresponding to the key.  The key must be kept secure, while the
certificate should be handed out to correspondents, e.g. by uploading
it to a keyserver.
")
                            .after_help(
                                "EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
")
                            .arg(Arg::with_name("input")
                                 .value_name("FILE")
                                 .help("Reads from FILE or stdin if omitted"))
                            .arg(Arg::with_name("output")
                                 .short("o").long("output").value_name("FILE")
                                 .help("Writes to FILE or stdout if omitted"))
                            .arg(Arg::with_name("binary")
                                 .short("B").long("binary")
                                 .help("Emits binary data"))
                )
                .subcommand(
                    SubCommand::with_name("adopt")
                        .display_order(800)
                        .about("Binds keys from one certificate to another")
                        .long_about(
"
Binds keys from one certificate to another

This command allows one to transfer primary keys and subkeys into an
existing certificate.  Say you want to transition to a new
certificate, but have an authentication subkey on your current
certificate.  You want to keep the authentication subkey because it
allows access to SSH servers and updating their configuration is not
feasible.
")
                        .after_help(
"EXAMPLES:

# Adopt an subkey into the new cert
$ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF -- juliet-new.pgp
")
                        .arg(Arg::with_name("keyring")
                             .short("r").long("keyring").value_name("KEY-RING")
                             .multiple(true).number_of_values(1)
                             .help("Supplies keys for use in --key."))
                        .arg(Arg::with_name("key")
                             .short("k").long("key").value_name("KEY")
                             .multiple(true).number_of_values(1)
                             .required(true)
                             .help("Adds the key or subkey KEY to the \
                                    TARGET-KEY"))
                        .arg(Arg::with_name("allow-broken-crypto")
                             .long("allow-broken-crypto")
                             .help("Allows adopting keys from certificates \
                                    using broken cryptography"))
                        .arg(Arg::with_name("certificate")
                             .value_name("TARGET-KEY")
                             .help("Adds keys to TARGET-KEY"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                )
                .subcommand(
                    SubCommand::with_name("attest-certifications")
                        .display_order(200)
                        .about("Attests to third-party certifications")
                        .long_about(
"
Attests to third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To make the key holder the sovereign over the
information over what information is distributed with the certificate,
the key holder needs to explicitly attest to third-party
certifications.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a keyserver.
")
                        .after_help(
"EXAMPLES:

# Attest to all certifications present on the key
$ sq key attest-certifications juliet.pgp

# Retract prior attestations on the key
$ sq key attest-certifications --none juliet.pgp
")
                        .arg(Arg::with_name("none")
                             .long("none")
                             .conflicts_with("all")
                             .help("Removes all prior attestations"))
                        .arg(Arg::with_name("all")
                             .long("all")
                             .conflicts_with("none")
                             .help("Attests to all certifications [default]"))
                        .arg(Arg::with_name("key")
                             .value_name("KEY")
                             .help("Changes attestations on KEY"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                )
        )

        .subcommand(
            SubCommand::with_name("keyring")
                .display_order(310)
                .about("Manages collections of keys or certs")
                .long_about(
"Manages collections of keys or certs

Collections of keys or certficicates (also known as \"keyrings\" when
they contain secret key material, and \"certrings\" when they don't) are
any number of concatenated certificates.  This subcommand provides
tools to list, split, join, merge, and filter keyrings.

Note: In the documentation of this subcommand, we sometimes use the
terms keys and certs interchangeably.
")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("filter")
                        .display_order(600)
                        .about("Joins keys into a keyring applying a filter")
                        .long_about(
"Joins keys into a keyring applying a filter

This can be used to filter keys based on given predicates,
e.g. whether they have a user id containing an email address with a
certain domain.  Additionally, the keys can be pruned to only include
components matching the predicates.

If no filters are supplied, everything matches.

If multiple predicates are given, they are or'ed, i.e. a key matches
if any of the predicates match.  To require all predicates to match,
chain multiple invocations of this command.  See EXAMPLES for
inspiration.
")
                        .after_help(
"EXAMPLES:

# Converts a key to a cert (i.e., remove any secret key material)
$ sq keyring filter --to-cert cat juliet.pgp

# Gets the keys with a user id on example.org
$ sq keyring filter --domain example.org keys.pgp

# Gets the keys with a user id on example.org or example.net
$ sq keyring filter --domain example.org --domain example.net keys.pgp

# Gets the keys with a user id with the name Juliet
$ sq keyring filter --name Juliet keys.pgp

# Gets the keys with a user id with the name Juliet on example.org
$ sq keyring filter --domain example.org keys.pgp | \\
  sq keyring filter --name Juliet

# Gets the keys with a user id on example.org, pruning other userids
$ sq keyring filter --domain example.org --prune-certs certs.pgp
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .multiple(true)
                             .help("Reads from FILE or stdin if omitted"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("name")
                             .long("name").value_name("NAME")
                             .multiple(true).number_of_values(1)
                             .help("Matches on NAME"))
                        .arg(Arg::with_name("email")
                             .long("email").value_name("ADDRESS")
                             .multiple(true).number_of_values(1)
                             .help("Matches on email ADDRESS"))
                        .arg(Arg::with_name("domain")
                             .long("domain").value_name("FQDN")
                             .multiple(true).number_of_values(1)
                             .help("Matches on email domain FQDN"))
                        .arg(Arg::with_name("prune-certs")
                             .short("P").long("prune-certs")
                             .help("Removes certificate components not \
                                    matching the filter"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                        .arg(Arg::with_name("to-certificate")
                             .long("to-cert")
                             .help("Converts any keys in the input to \
                                    certificates.  Converting a key to a \
                                    certificate removes secret key material \
                                    from the key thereby turning it into \
                                    a certificate."))
                )
                .subcommand(
                    SubCommand::with_name("join")
                        .display_order(300)
                        .about("Joins keys or keyrings into a single keyring")
                        .long_about(
"Joins keys or keyrings into a single keyring

Unlike \"sq keyring merge\", multiple versions of the same key are not
merged together.

The converse operation is \"sq keyring split\".
")
                        .after_help(
"EXAMPLES:

# Collect certs for an email conversation
$ sq keyring join juliet.pgp romeo.pgp alice.pgp
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .multiple(true)
                             .help("Sets the input files to use"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Sets the output file to use"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Don't ASCII-armor the keyring"))
                )
                .subcommand(
                    SubCommand::with_name("merge")
                        .display_order(350)
                        .about("Merges keys or keyrings into a single keyring")
                        .long_about(
"Merges keys or keyrings into a single keyring

Unlike \"sq keyring join\", the certificates are buffered and multiple
versions of the same certificate are merged together.  Where data is
replaced (e.g., secret key material), data from the later certificate
is preferred.
")
                        .after_help(
"EXAMPLES:

# Merge certificate updates
$ sq keyring merge certs.pgp romeo-updates.pgp
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .multiple(true)
                             .help("Reads from FILE"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .about("Lists keys in a keyring")
                        .display_order(100)
                        .long_about(
"Lists keys in a keyring

Prints the fingerprint as well one userid for every certificate
encountered in the keyring.
")
                        .after_help(
"EXAMPLES:

# List all certs
$ sq keyring list certs.pgp

# List all certs with a userid on example.org
$ sq keyring filter --domain example.org certs.pgp | sq keyring list
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                )
                .subcommand(
                    SubCommand::with_name("split")
                        .display_order(200)
                        .about("Splits a keyring into individual keys")
                        .long_about(
"Splits a keyring into individual keys

Splitting up a keyring into individual keys helps with curating a
keyring.

The converse operation is \"sq keyring join\".
")
                        .after_help(
"EXAMPLES:

# Split all certs
$ sq keyring split certs.pgp

# Split all certs, merging them first to avoid duplicates
$ sq keyring merge certs.pgp | sq keyring split
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                        .arg(Arg::with_name("prefix")
                             .short("p").long("prefix").value_name("FILE")
                             .help("Writes to files with prefix FILE \
                                    [defaults to the input filename with a \
                                    dash, or \"output\" if keyring is read \
                                    from stdin]"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                )
        )

        .subcommand(SubCommand::with_name("certify")
                    .display_order(320)
                    .about("Certifies a User ID for a Certificate")
                        .long_about(
"
Certifies a User ID for a Certificate

Using a certification a keyholder may vouch for the fact that another
certificate legitimately belongs to a user id.  In the context of
emails this means that the same entity controls the key and the email
address.  These kind of certifications form the basis for the Web Of
Trust.

This command emits the certificate with the new certification.  The
updated certificate has to be distributed, preferably by sending it to
the certificate holder for attestation.  See also \"sq key
attest-certification\".
")
                        .after_help(
"EXAMPLES:

# Juliet certifies that Romeo controls romeo.pgp and romeo@example.org
$ sq certify juliet.pgp romeo.pgp \"<romeo@example.org>\"
")
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("binary")
                         .short("B").long("binary")
                         .help("Emits binary data"))
                    .arg(Arg::with_name("depth")
                         .short("d").long("depth").value_name("TRUST_DEPTH")
                         .help("Sets the trust depth")
                         .long_help(
                             "Sets the trust depth (sometimes referred to as \
                                the trust level).  0 means a normal \
                                certification of <CERTIFICATE, USERID>.  \
                                1 means CERTIFICATE is also a trusted \
                                introducer, 2 means CERTIFICATE is a \
                                meta-trusted introducer, etc.  The \
                                default is 0."))
                    .arg(Arg::with_name("amount")
                         .short("a").long("amount").value_name("TRUST_AMOUNT")
                         .help("Sets the amount of trust")
                         .long_help(
                             "Sets the amount of trust.  \
                                Values between 1 and 120 are meaningful. \
                                120 means fully trusted.  \
                                Values less than 120 indicate the degree \
                                of trust.  60 is usually used for partially \
                                trusted.  The default is 120."))
                    .arg(Arg::with_name("regex")
                         .short("r").long("regex").value_name("REGEX")
                         .multiple(true).number_of_values(1)
                         .help("Adds a regular expression to constrain \
                                what a trusted introducer can certify")
                         .long_help(
                             "Adds a regular expression to constrain \
                                what a trusted introducer can certify.  \
                                The regular expression must match \
                                the certified User ID in all intermediate \
                                introducers, and the certified certificate. \
                                Multiple regular expressions may be \
                                specified.  In that case, at least \
                                one must match."))
                    .arg(Arg::with_name("local")
                         .short("l").long("local")
                         .help("Makes the certification a local \
                                certification")
                         .long_help(
                             "Makes the certification a local \
                                certification.  Normally, local \
                                certifications are not exported."))
                    .arg(Arg::with_name("non-revocable")
                         .long("non-revocable")
                         .help("Marks the certification as being non-revocable")
                         .long_help(
                             "Marks the certification as being non-revocable. \
                                That is, you cannot later revoke this \
                                certification.  This should normally only \
                                be used with an expiration."))
                    .arg(Arg::with_name("notation")
                         .value_names(&["NAME", "VALUE"])
                         .long("notation")
                         .multiple(true).number_of_values(2)
                         .help("Adds a notation to the certification.")
                         .long_help(
                             "Adds a notation to the certification.  \
                              A user-defined notation's name must be of \
                              the form \"name@a.domain.you.control.org\". \
                              If the notation's name starts with a !, \
                              then the notation is marked as being \
                              critical.  If a consumer of a signature \
                              doesn't understand a critical notation, \
                              then it will ignore the signature.  The \
                              notation is marked as being human readable."))

                    .group(ArgGroup::with_name("expiration-group")
                           .args(&["expires", "expires-in"]))
                    .arg(Arg::with_name("expires")
                         .long("expires").value_name("TIME")
                         .help("Makes the certification expire at TIME (as ISO 8601)")
                         .long_help(
                             "Makes the certification expire at TIME (as ISO 8601). \
                              Use \"never\" to create certifications that do not \
                              expire."))
                    .arg(Arg::with_name("expires-in")
                         .long("expires-in").value_name("DURATION")
                         // Catch negative numbers.
                         .allow_hyphen_values(true)
                         .help("Makes the certification expire after DURATION \
                                (as N[ymwd]) [default: 5y]")
                         .long_help(
                             "Makes the certification expire after DURATION. \
                              Either \"N[ymwd]\", for N years, months, \
                              weeks, or days, or \"never\".  [default: 5y]"))

                    .arg(Arg::with_name("certifier")
                         .value_name("CERTIFIER-KEY")
                         .required(true)
                         .index(1)
                         .help("Creates the certificate using CERTIFIER-KEY."))
                    .arg(Arg::with_name("certificate")
                         .value_name("CERTIFICATE")
                         .required(true)
                         .index(2)
                         .help("Certifies CERTIFICATE."))
                    .arg(Arg::with_name("userid")
                         .value_name("USERID")
                         .required(true)
                         .index(3)
                         .help("Certifies USERID for CERTIFICATE."))
        )

        .subcommand(SubCommand::with_name("packet")
                    .display_order(610)
                    .about("Low-level packet manipulation")
                    .long_about(
"
Low-level packet manipulation

An OpenPGP data stream consists of packets.  These tools allow working
with packet streams.  They are mostly of interest to developers, but
\"sq packet dump\" may be helpful to a wider audience both to provide
valuable information in bug reports to OpenPGP-related software, and
as a learning tool.
")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("dump")
                                .display_order(100)
                                .about("Lists packets")
                                .long_about(
"
Lists packets

Creates a human-readable description of the packet sequence.
Additionally, it can print cryptographic artifacts, and print the raw
octet stream similar to hexdump(1), annotating specifically which
bytes are parsed into OpenPGP values.

To inspect encrypted messages, either supply the session key, or see
\"sq decrypt --dump\" or \"sq packet decrypt\".
")
                                .after_help(
"EXAMPLES:

# Prints the packets of a certificate
$ sq packet dump juliet.pgp

# Prints cryptographic artifacts of a certificate
$ sq packet dump --mpis juliet.pgp

# Prints a hexdump of a certificate
$ sq packet dump --hex juliet.pgp

# Prints the packets of an encrypted message
$ sq packet dump --session-key AAAABBBBCCCC... ciphertext.pgp
")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                                .arg(Arg::with_name("session-key")
                                     .long("session-key").value_name("SESSION-KEY")
                                     .help("Decrypts an encrypted message using \
                                            SESSION-KEY"))
                                .arg(Arg::with_name("mpis")
                                     .long("mpis")
                                     .help("Prints cryptographic artifacts"))
                                .arg(Arg::with_name("hex")
                                     .short("x").long("hex")
                                     .help("Prints a hexdump"))
                    )
                    .subcommand(SubCommand::with_name("decrypt")
                                .display_order(200)
                                .about("Unwraps an encryption container")
                                .long_about(
"
Unwraps an encryption container

Decrypts a message, dumping the content of the encryption container
without further processing.  The result is a valid OpenPGP message
that can, among other things, be inspected using \"sq packet dump\".
")
                                .after_help(
"EXAMPLES:

# Unwraps the encryption revealing the signed message
$ sq packet decrypt --recipient-key juliet.pgp ciphertext.pgp
")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Emits binary data"))
                                .arg(Arg::with_name("secret-key-file")
                                     .long("recipient-key").value_name("KEY")
                                     .multiple(true).number_of_values(1)
                                     .help("Decrypts the message with KEY"))
                                .arg(Arg::with_name("dump-session-key")
                                     .long("dump-session-key")
                                     .help("Prints the session key to stderr"))
                    )
                    .subcommand(SubCommand::with_name("split")
                                .display_order(300)
                                .about("Splits a message into packets")
                                .long_about(
"
Splits a message into packets

Splitting a packet sequence into individual packets, then recombining
them freely with \"sq packet join\" is a great way to experiment with
OpenPGP data.

The converse operation is \"sq packet join\".
")
                                .after_help(
"EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp
")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("prefix")
                                     .short("p").long("prefix").value_name("PREFIX")
                                     .help("Writes to files with PREFIX \
                                            [defaults: FILE a dash, \
                                            or \"output\" if read from stdin)"))
                    )
                    .subcommand(SubCommand::with_name("join")
                                .display_order(310)
                                .about("Joins packets split across \
                                        files")
                                .long_about(
"
Joins packets split across files

Splitting a packet sequence into individual packets, then recombining
them freely with \"sq packet join\" is a great way to experiment with
OpenPGP data.

The converse operation is \"sq packet split\".
")
                        .after_help(
"EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp

# Then join only a subset of these packets
$ sq packet join juliet.pgp-[0-3]*
")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .multiple(true)
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                                .arg(Arg::with_name("kind")
                                     .long("label").value_name("LABEL")
                                     .possible_values(&["auto", "message",
                                                        "cert", "key", "sig",
                                                        "file"])
                                     .default_value("auto")
                                     .conflicts_with("binary")
                                     .help("Selects the kind of armor header"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Emits binary data"))));

    let app = if ! feature_net {
        // Without networking support.
        app
    } else {
        // With networking support.
        app
        .subcommand(SubCommand::with_name("keyserver")
                    .display_order(410)
                    .about("Interacts with keyservers")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .arg(Arg::with_name("policy")
                         .short("p").long("policy").value_name("NETWORK-POLICY")
                         .possible_values(&["offline", "anonymized",
                                            "encrypted", "insecure"])
                         .default_value("encrypted")
                         .help("Sets the network policy to use"))
                    .arg(Arg::with_name("server")
                         .short("s").long("server").value_name("URI")
                         .help("Sets the keyserver to use"))
                    .subcommand(SubCommand::with_name("get")
                                .about("Retrieves a key")
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Emits binary data"))
                                .arg(Arg::with_name("query")
                                     .value_name("QUERY")
                                     .required(true)
                                     .help(
                                         "Retrieve certificate(s) using QUERY. \
                                          This may be a fingerprint, a KeyID, \
                                          or an email address."))
                    )
                    .subcommand(SubCommand::with_name("send")
                                .about("Sends a key")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                    )
        )

        .subcommand(SubCommand::with_name("wkd")
                    .display_order(420)
                    .about("Interacts with Web Key Directories")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .arg(Arg::with_name("policy")
                         .short("p").long("policy").value_name("NETWORK-POLICY")
                         .possible_values(&["offline", "anonymized",
                                            "encrypted", "insecure"])
                         .default_value("encrypted")
                         .help("Sets the network policy to use"))
                    .subcommand(SubCommand::with_name("url")
                                .about("Prints the Web Key Directory URL of \
                                        an email address.")
                                .arg(Arg::with_name("input")
                                    .value_name("ADDRESS")
                                    .required(true)
                                    .help("Queries for ADDRESS"))
                    )
                    .subcommand(SubCommand::with_name("get")
                                .about("Queries for certs using \
                                        Web Key Directory")
                                .arg(Arg::with_name("input")
                                    .value_name("ADDRESS")
                                    .required(true)
                                    .help("Queries a cert for ADDRESS"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Emits binary data"))
                    )
                    .subcommand(SubCommand::with_name("generate")
                                .about("Generates a Web Key Directory \
                                        for the given domain and keys.  \
                                        If the WKD exists, the new \
                                        keys will be inserted and it \
                                        is updated and existing ones \
                                        will be updated.")
                                .arg(Arg::with_name("base_directory")
                                     .value_name("WEB-ROOT")
                                     .required(true)
                                     .help("Writes the WKD to WEB-ROOT")
                                     .long_help(
                                         "Writes the WKD to WEB-ROOT. \
                                          Transfer this directory to \
                                          the webserver."))
                                .arg(Arg::with_name("domain")
                                    .value_name("FQDN")
                                    .help("Generates a WKD for FQDN")
                                    .required(true))
                                .arg(Arg::with_name("input")
                                    .value_name("CERT-RING")
                                    .help("Adds certificates from CERT-RING to \
                                           the WKD"))
                                .arg(Arg::with_name("direct_method")
                                     .short("d").long("direct-method")
                                     .help("Uses the direct method \
                                            [default: advanced method]"))
                    )
        )
    };

    let app = if ! feature_autocrypt {
        // Without Autocrypt support.
        app
    } else {
        // With Autocrypt support.
        app.subcommand(
            SubCommand::with_name("autocrypt")
                .display_order(400)
                .about("Communicates certificates using Autocrypt")
                .long_about(
"Communicates certificates using Autocrypt

Autocrypt is a standard for mail user agents to provide convenient
end-to-end encryption of emails.  This subcommand provides a limited
way to produce and consume headers that are used by Autocrypt to
communicate certificates between clients.

See https://autocrypt.org/
")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("decode")
                        .about("Reads Autocrypt-encoded certificates")
                        .long_about(
"Reads Autocrypt-encoded certificates

Given an autocrypt header (or an key-gossip header), this command
extracts the certificate encoded within it.

The converse operation is \"sq autocrypt encode-sender\".
")
                        .after_help(
"EXAMPLES:

# Extract all certificates from a mail
$ sq autocrypt decode autocrypt.eml
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Emits binary data"))
                )
                .subcommand(
                    SubCommand::with_name("encode-sender")
                        .about("Encodes a certificate into \
                                an Autocrypt header")
                        .long_about(
"Encodes a certificate into an Autocrypt header

A certificate can be encoded and included in a header of an email
message.  This command encodes the certificate, adds the senders email
address (which must match the one used in the \"From\" header), and the
senders \"prefer-encrypt\" state (see the Autocrypt spec for more
information).

The converse operation is \"sq autocrypt decode\".
")
                        .after_help(
"EXAMPLES:

# Encodes a certificate
$ sq autocrypt encode-sender juliet.pgp

# Encodes a certificate with an explicit sender address
$ sq autocrypt encode-sender --email juliet@example.org juliet.pgp

# Encodes a certificate while indicating the willingness to encrypt
$ sq autocrypt encode-sender --prefer-encrypt mutual juliet.pgp
")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Writes to FILE or stdout if omitted"))
                        .arg(Arg::with_name("address")
                             .long("email").value_name("ADDRESS")
                             .help("Sets the address \
                                    [default: primary userid]"))
                             .arg(Arg::with_name("prefer-encrypt")
                                  .long("prefer-encrypt")
                                  .possible_values(&["nopreference",
                                                     "mutual"])
                                  .default_value("nopreference")
                                  .help("Sets the prefer-encrypt \
                                         attribute"))
                )
        )
    };

    app
}
