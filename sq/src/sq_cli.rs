/// Command-line parser for sq.

use clap::{App, Arg, ArgGroup, SubCommand, AppSettings};

pub fn build() -> App<'static, 'static> {
    configure(App::new("sq"))
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
pub fn configure(app: App<'static, 'static>) -> App<'static, 'static> {
    let version = Box::leak(
        format!("{} (sequoia-openpgp {})",
                env!("CARGO_PKG_VERSION"),
                sequoia_openpgp::VERSION)
            .into_boxed_str()) as &str;

    let app = app
        .version(version)
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
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
        )

        .subcommand(SubCommand::with_name("verify")
                    .display_order(210)
                    .about("Verifies signed messages or detached signatures")
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
                    .about("Converts binary data to ASCII")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
                    .arg(Arg::with_name("kind")
                         .long("kind").value_name("KIND")
                         .possible_values(&["message", "publickey", "secretkey",
                                            "signature", "file"])
                         .default_value("file")
                         .help("Selects the kind of armor header"))
        )

        .subcommand(SubCommand::with_name("dearmor")
                    .display_order(510)
                    .about("Converts ASCII to binary")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Reads from FILE or stdin if omitted"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Writes to FILE or stdout if omitted"))
        )

        .subcommand(SubCommand::with_name("autocrypt")
                    .display_order(400)
                    .about("Communicates certificates using Autocrypt")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("decode")
                                .about("Reads Autocrypt-encoded certificates")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                    )
                    .subcommand(SubCommand::with_name("encode-sender")
                                .about("Encodes the sender's OpenPGP \
                                        Certificates into \
                                        an Autocrypt header")
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

        .subcommand(SubCommand::with_name("inspect")
                    .display_order(600)
                    .about("Inspects data, like file(1)")
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
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .display_order(100)
                        .about("Generates a new key")
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
                                  Use 'never' to create keys that do not \
                                  expire."))
                        .arg(Arg::with_name("expires-in")
                             .long("expires-in").value_name("DURATION")
                             // Catch negative numbers.
                             .allow_hyphen_values(true)
                             .help("Makes the key expire after DURATION \
                                    (as N[ymwd])")
                             .long_help(
                                 "Makes the key expire after DURATION. \
                                  Either 'N[ymwd]', for N years, months, \
                                  weeks, or days, or 'never'."))

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
                                  mandatory if OUTFILE is '-'. \
                                  [default: <OUTFILE>.rev]"))
                )
                .subcommand(
                    SubCommand::with_name("adopt")
                        .display_order(800)
                        .about("Binds keys from one certificate to another")
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
                             .required(true)
                             .help("Adds keys to TARGET-KEY"))
                )
                .subcommand(
                    SubCommand::with_name("attest-certifications")
                        .display_order(200)
                        .about("Attests third-party certifications allowing \
                                for their distribution")
                        .arg(Arg::with_name("none")
                             .long("none")
                             .conflicts_with("all")
                             .help("Removes all prior attestations"))
                        .arg(Arg::with_name("all")
                             .long("all")
                             .conflicts_with("none")
                             .help("Attests to all certifications"))
                        .arg(Arg::with_name("key")
                             .value_name("KEY")
                             .required(true)
                             .help("Changes attestations on KEY"))
                )
        )

        .subcommand(
            SubCommand::with_name("certring")
                .display_order(310)
                .about("Manages collections of certificates")
                .long_about(
                    "Manages collections of certificates \
                     (also known as 'keyrings)'.")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("filter")
                        .about("Joins certs into a certring applying a filter")
                        .after_help(
                            "If multiple predicates are given, they are \
                             or'ed, i.e. a certificate matches if any \
                             of the predicates match.  To require all \
                             predicates to match, chain multiple \
                             invocations of this command:\n\
                             \n\
                             $ cat certs.pgp | sq certring filter --domain example.org | sq certring filter --name Juliett")
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
                )
                .subcommand(
                    SubCommand::with_name("join")
                        .about("Joins certs or certrings into a single certring")
                        .long_about(
                            "Unlike 'sq certring merge', multiple versions \
                             of the same certificate are not merged \
                             together.")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .multiple(true)
                             .help("Sets the input files to use"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Sets the output file to use"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Don't ASCII-armor the certring"))
                )
                .subcommand(
                    SubCommand::with_name("merge")
                        .about("Merges certs or certrings into a single certring")
                        .long_about(
                            "Unlike 'sq certring join', the certificates \
                             are buffered and multiple versions of the same \
                             certificate are merged together.  Where data \
                             is replaced (e.g., secret key material), data \
                             from the later certificate is preferred.")
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
                        .about("Lists certs in a certring")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                )
                .subcommand(
                    SubCommand::with_name("split")
                        .about("Splits a certring into individual certs")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Reads from FILE or stdin if omitted"))
                        .arg(Arg::with_name("prefix")
                             .short("p").long("prefix").value_name("FILE")
                             .help("Writes to files with prefix FILE \
                                    [defaults to the input filename with a \
                                    dash, or 'output' if certring is read \
                                    from stdin]")))
        )

        .subcommand(SubCommand::with_name("certify")
                    .display_order(320)
                    .about("Certifies a User ID for a Certificate")
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

                    .group(ArgGroup::with_name("expiration-group")
                           .args(&["expires", "expires-in"]))
                    .arg(Arg::with_name("expires")
                         .long("expires").value_name("TIME")
                         .help("Makes the certification expire at TIME (as ISO 8601)")
                         .long_help(
                             "Makes the certification expire at TIME (as ISO 8601). \
                              Use 'never' to create certifications that do not \
                              expire."))
                    .arg(Arg::with_name("expires-in")
                         .long("expires-in").value_name("DURATION")
                         // Catch negative numbers.
                         .allow_hyphen_values(true)
                         .help("Makes the certification expire after DURATION \
                                (as N[ymwd]) [default: 5y]")
                         .long_help(
                             "Makes the certification expire after DURATION. \
                              Either 'N[ymwd]', for N years, months, \
                              weeks, or days, or 'never'.  [default: 5y]"))

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
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("dump")
                                .display_order(100)
                                .about("Lists packets")
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
                                .long_about("Decrypts a message, dumping \
                                        the content of the encryption \
                                        container without further processing")
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
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("prefix")
                                     .short("p").long("prefix").value_name("PREFIX")
                                     .help("Writes to files with PREFIX \
                                            [defaults: FILE a dash, \
                                            or 'output' if read from stdin)"))
                    )
                    .subcommand(SubCommand::with_name("join")
                                .display_order(310)
                                .about("Joins packets split across \
                                        files")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .multiple(true)
                                     .help("Reads from FILE or stdin if omitted"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Writes to FILE or stdout if omitted"))
                                .arg(Arg::with_name("kind")
                                     .long("kind").value_name("KIND")
                                     .possible_values(&["message", "publickey",
                                                        "secretkey",
                                                        "signature", "file"])
                                     .default_value("file")
                                     .conflicts_with("binary")
                                     .help("Selects the kind of armor header"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Emits binary data"))));

    let app = if ! cfg!(feature = "net") {
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

    app
}
