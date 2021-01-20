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
    let app = app
        .version(env!("CARGO_PKG_VERSION"))
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(Arg::with_name("force")
             .short("f").long("force")
             .help("Overwrite existing files"))
        .arg(Arg::with_name("known-notation")
             .long("known-notation").value_name("NOTATION")
             .multiple(true).number_of_values(1)
             .help("The notation name is considered known. \
               This is used when validating signatures. \
               Signatures that have unknown notations with the \
               critical bit set are considered invalid."))

        .subcommand(SubCommand::with_name("decrypt")
                    .display_order(110)
                    .about("Decrypts an OpenPGP message")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("signatures").value_name("N")
                         .help("The number of valid signatures required.  \
                                Default: 0")
                         .short("n").long("signatures"))
                    .arg(Arg::with_name("sender-cert-file")
                         .long("signer-cert").value_name("CERT")
                         .multiple(true).number_of_values(1)
                         .help("The sender's certificate to verify signatures \
                                with, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("recipient-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Secret key to decrypt with, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("dump-session-key")
                         .long("dump-session-key")
                         .help("Prints the session key to stderr"))
                    .arg(Arg::with_name("dump")
                         .long("dump")
                         .help("Print a packet dump to stderr"))
                    .arg(Arg::with_name("hex")
                         .short("x").long("hex")
                         .help("Print a hexdump (implies --dump)"))
        )

        .subcommand(SubCommand::with_name("encrypt")
                    .display_order(100)
                    .about("Encrypts a message")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("binary")
                         .short("B").long("binary")
                         .help("Don't ASCII-armor encode the OpenPGP data"))
                    .arg(Arg::with_name("recipients-cert-file")
                         .long("recipient-cert").value_name("CERT-RING")
                         .multiple(true).number_of_values(1)
                         .help("Recipients to encrypt for, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("signer-key-file")
                         .long("signer-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Secret key to sign with, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("symmetric")
                         .short("s").long("symmetric")
                         .multiple(true)
                         .help("Encrypt with a password \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("mode")
                         .long("mode").value_name("MODE")
                         .possible_values(&["transport", "rest", "all"])
                         .default_value("all")
                         .help("Selects what kind of keys are considered for \
                                encryption.  Transport select subkeys marked \
                                as suitable for transport encryption, rest \
                                selects those for encrypting data at rest, \
                                and all selects all encryption-capable \
                                subkeys"))
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
                         .help("If a certificate has only expired \
                                encryption-capable subkeys, fall back \
                                to using the one that expired last"))
        )

        .subcommand(SubCommand::with_name("merge-signatures")
                    .display_order(250)
                    .about("Merges two signatures")
                    .arg(Arg::with_name("input1")
                         .value_name("FILE")
                         .help("Sets the first input file to use"))
                    .arg(Arg::with_name("input2")
                         .value_name("FILE")
                         .help("Sets the second input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
        )

        .subcommand(SubCommand::with_name("sign")
                    .display_order(200)
                    .about("Signs a message")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("binary")
                         .short("B").long("binary")
                         .help("Don't ASCII-armor encode the OpenPGP data"))
                    .arg(Arg::with_name("detached")
                         .long("detached")
                         .help("Create a detached signature"))
                    .arg(Arg::with_name("append")
                         .short("a").long("append")
                         .conflicts_with("notarize")
                         .help("Append signature to existing signature"))
                    .arg(Arg::with_name("notarize")
                         .short("n").long("notarize")
                         .conflicts_with("append")
                         .help("Signs a message and all existing signatures"))
                    .arg(Arg::with_name("secret-key-file")
                         .long("signer-key").value_name("KEY")
                         .multiple(true).number_of_values(1)
                         .help("Secret key to sign with, given as a file \
                                (can be given multiple times)"))
                    .arg(Arg::with_name("time")
                         .short("t").long("time").value_name("TIME")
                         .help("Chooses keys valid at the specified time and \
                                sets the signature's creation time"))
        )

        .subcommand(SubCommand::with_name("verify")
                    .display_order(210)
                    .about("Verifies a message")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("detached")
                         .long("detached").value_name("SIG")
                         .help("Verifies a detached signature"))
                    .arg(Arg::with_name("signatures")
                         .short("n").long("signatures").value_name("N")
                         .help("The number of valid signatures required.  \
                                Default: 0"))
                    .arg(Arg::with_name("sender-cert-file")
                         .long("signer-cert").value_name("CERT")
                         .multiple(true).number_of_values(1)
                         .help("The sender's certificate to verify signatures \
                                with, given as a file \
                                (can be given multiple times)"))
        )

        .subcommand(SubCommand::with_name("armor")
                    .display_order(500)
                    .about("Applies ASCII Armor to a file")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("kind")
                         .long("kind").value_name("KIND")
                         .possible_values(&["message", "publickey", "secretkey",
                                            "signature", "file"])
                         .default_value("file")
                         .help("Selects the kind of header line to produce"))
        )

        .subcommand(SubCommand::with_name("dearmor")
                    .display_order(510)
                    .about("Removes ASCII Armor from a file")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output")
                         .short("o").long("output").value_name("FILE")
                         .help("Sets the output file to use"))
        )

        .subcommand(SubCommand::with_name("autocrypt")
                    .display_order(400)
                    .about("Autocrypt support")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("decode")
                                .about("Converts Autocrypt-encoded keys to \
                                        OpenPGP Certificates")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                    )
                    .subcommand(SubCommand::with_name("encode-sender")
                                .about("Encodes the sender's OpenPGP \
                                        Certificates into \
                                        an Autocrypt header")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("address")
                                     .long("address")
                                     .takes_value(true)
                                     .help("Select userid to use.  \
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
                    .about("Inspects a sequence of OpenPGP packets")
                    .arg(Arg::with_name("input")
                         .value_name("FILE")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("certifications")
                         .long("certifications")
                         .help("Print third-party certifications"))
        )

        .subcommand(
            SubCommand::with_name("key")
                .display_order(300)
                .about("Manipulates keys")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("Generates a new key")
                        .arg(Arg::with_name("userid")
                             .short("u").long("userid").value_name("EMAIL")
                             .multiple(true).number_of_values(1)
                             .help("Add userid to the key \
                                    (can be given multiple times)"))
                        .arg(Arg::with_name("cipher-suite")
                             .short("c").long("cipher-suite").value_name("CIPHER-SUITE")
                             .possible_values(&["rsa3k", "rsa4k", "cv25519"])
                             .default_value("cv25519")
                             .help("Cryptographic algorithms used for the key."))
                        .arg(Arg::with_name("with-password")
                             .long("with-password")
                             .help("Prompt for a password to protect the \
                                    generated key with."))

                        .group(ArgGroup::with_name("expiration-group")
                               .args(&["expires", "expires-in"]))

                        .arg(Arg::with_name("expires")
                             .long("expires").value_name("TIME")
                             .help("Absolute time When the key should expire, \
                                    or 'never'."))
                        .arg(Arg::with_name("expires-in")
                             .long("expires-in").value_name("DURATION")
                             // Catch negative numbers.
                             .allow_hyphen_values(true)
                             .help("Relative time when the key should expire.  \
                                    Either 'N[ymwd]', for N years, months, \
                                    weeks, or days, or 'never'."))

                        .group(ArgGroup::with_name("cap-sign")
                               .args(&["can-sign", "cannot-sign"]))
                        .arg(Arg::with_name("can-sign")
                             .long("can-sign")
                             .help("The key has a signing-capable subkey \
                                    (default)"))
                        .arg(Arg::with_name("cannot-sign")
                             .long("cannot-sign")
                             .help("The key will not be able to sign data"))

                        .group(ArgGroup::with_name("cap-encrypt")
                               .args(&["can-encrypt", "cannot-encrypt"]))
                        .arg(Arg::with_name("can-encrypt")
                             .long("can-encrypt").value_name("PURPOSE")
                             .possible_values(&["transport", "storage",
                                                "universal"])
                             .help("The key has an encryption-capable subkey \
                                    (default: universal)"))
                        .arg(Arg::with_name("cannot-encrypt")
                             .long("cannot-encrypt")
                             .help("The key will not be able to encrypt data"))

                        .arg(Arg::with_name("export")
                             .short("e").long("export").value_name("OUTFILE")
                             .help("Exports the key instead of saving it in \
                                    the store")
                             .required(true))
                        .arg(Arg::with_name("rev-cert")
                             .long("rev-cert").value_name("FILE or -")
                             .required_if("export", "-")
                             .help("Sets the output file for the revocation \
                                    certificate. Default is <OUTFILE>.rev, \
                                    mandatory if OUTFILE is '-'."))
                )
                .subcommand(
                    SubCommand::with_name("adopt")
                        .about("Bind keys from one certificate to another.")
                        .arg(Arg::with_name("keyring")
                             .short("r").long("keyring").value_name("KEYRING")
                             .multiple(true).number_of_values(1)
                             .help("A keyring containing the keys specified \
                                    in --key."))
                        .arg(Arg::with_name("key")
                             .short("k").long("key").value_name("KEY")
                             .multiple(true).number_of_values(1)
                             .required(true)
                             .help("Adds the specified key or subkey to the \
                                    certificate."))
                        .arg(Arg::with_name("allow-broken-crypto")
                             .long("allow-broken-crypto")
                             .help("Allows adopting keys from certificates \
                                    using broken cryptography."))
                        .arg(Arg::with_name("certificate")
                             .value_name("CERT")
                             .required(true)
                             .help("The certificate to add keys to."))
                )
                .subcommand(
                    SubCommand::with_name("attest-certifications")
                        .about("Attests third-party certifications allowing \
                                for their distribution")
                        .arg(Arg::with_name("none")
                             .long("none")
                             .conflicts_with("all")
                             .help("Remove all prior attestations"))
                        .arg(Arg::with_name("all")
                             .long("all")
                             .conflicts_with("none")
                             .help("Attest to all certifications"))
                        .arg(Arg::with_name("key")
                             .value_name("KEY")
                             .required(true)
                             .help("Change attestations on this key."))
                )
        )

        .subcommand(
            SubCommand::with_name("certring")
                .display_order(310)
                .about("Manipulates certificate rings")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("filter")
                        .about("Joins certs into a certring applying a filter")
                        .long_about(
                            "If multiple predicates are given, they are \
                             or'ed, i.e. a certificate matches if any \
                             of the predicates match.  To require all \
                             predicates to match, chain multiple \
                             invocations of this command.")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .multiple(true)
                             .help("Sets the input files to use"))
                        .arg(Arg::with_name("output")
                             .short("o").long("output").value_name("FILE")
                             .help("Sets the output file to use"))
                        .arg(Arg::with_name("name")
                             .long("name").value_name("NAME")
                             .multiple(true).number_of_values(1)
                             .help("Match on this name"))
                        .arg(Arg::with_name("email")
                             .long("email").value_name("ADDRESS")
                             .multiple(true).number_of_values(1)
                             .help("Match on this email address"))
                        .arg(Arg::with_name("domain")
                             .long("domain").value_name("FQDN")
                             .multiple(true).number_of_values(1)
                             .help("Match on this email domain name"))
                        .arg(Arg::with_name("prune-certs")
                             .short("P").long("prune-certs")
                             .help("Remove certificate components not matching \
                                    the filter"))
                        .arg(Arg::with_name("binary")
                             .short("B").long("binary")
                             .help("Don't ASCII-armor the certring"))
                )
                .subcommand(
                    SubCommand::with_name("join")
                        .about("Joins certs into a certring")
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
                    SubCommand::with_name("list")
                        .about("Lists certs in a certring")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Sets the input file to use"))
                )
                .subcommand(
                    SubCommand::with_name("split")
                        .about("Splits a certring into individual certs")
                        .arg(Arg::with_name("input")
                             .value_name("FILE")
                             .help("Sets the input file to use"))
                        .arg(Arg::with_name("prefix")
                             .short("p").long("prefix").value_name("FILE")
                             .help("Sets the prefix to use for output files \
                                    (defaults to the input filename with a \
                                    dash, or 'output' if certring is read \
                                    from stdin)")))
        )

        .subcommand(SubCommand::with_name("packet")
                    .display_order(610)
                    .about("OpenPGP Packet manipulation")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("dump")
                                .about("Lists OpenPGP packets")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("session-key")
                                     .long("session-key").value_name("SESSION-KEY")
                                     .help("Session key to decrypt encryption \
                                            containers"))
                                .arg(Arg::with_name("mpis")
                                     .long("mpis")
                                     .help("Print MPIs"))
                                .arg(Arg::with_name("hex")
                                     .short("x").long("hex")
                                     .help("Print a hexdump"))
                    )
                    .subcommand(SubCommand::with_name("decrypt")
                                .display_order(10)
                                .about("Decrypts an OpenPGP message, dumping \
                                        the content of the encryption \
                                        container without further processing")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Don't ASCII-armor encode the \
                                            OpenPGP data"))
                                .arg(Arg::with_name("secret-key-file")
                                     .long("recipient-key").value_name("KEY")
                                     .multiple(true).number_of_values(1)
                                     .help("Secret key to decrypt with, given \
                                            as a file \
                                            (can be given multiple times)"))
                                .arg(Arg::with_name("dump-session-key")
                                     .long("dump-session-key")
                                     .help("Prints the session key to stderr"))
                    )
                    .subcommand(SubCommand::with_name("split")
                                .about("Splits a message into OpenPGP packets")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("prefix")
                                     .short("p").long("prefix").value_name("FILE")
                                     .help("Sets the prefix to use for output files \
                                            (defaults to the input filename with a dash, \
                                            or 'output')"))
                    )
                    .subcommand(SubCommand::with_name("join")
                                .about("Joins OpenPGP packets split across \
                                        files")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .multiple(true)
                                     .help("Sets the input files to use"))
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("kind")
                                     .long("kind").value_name("KIND")
                                     .possible_values(&["message", "publickey",
                                                        "secretkey",
                                                        "signature", "file"])
                                     .default_value("file")
                                     .help("Selects the kind of header line to \
                                            produce"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Don't ASCII-armor encode the \
                                            OpenPGP data"))));

    let app = if ! cfg!(feature = "net") {
        // Without networking support.
        app
    } else {
        // With networking support.
        app
        .arg(Arg::with_name("policy")
             .short("p").long("policy").value_name("NETWORK-POLICY")
             .help("Sets the network policy to use"))
        .subcommand(SubCommand::with_name("keyserver")
                    .display_order(410)
                    .about("Interacts with keyservers")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .arg(Arg::with_name("server")
                         .short("s").long("server").value_name("URI")
                         .help("Sets the keyserver to use"))
                    .subcommand(SubCommand::with_name("get")
                                .about("Retrieves a key")
                                .arg(Arg::with_name("output")
                                     .short("o").long("output").value_name("FILE")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Don't ASCII-armor encode the OpenPGP data"))
                                .arg(Arg::with_name("query")
                                     .value_name("QUERY")
                                     .required(true)
                                     .help(
                                         "Fingerprint, KeyID, or email \
                                          address of the cert(s) to retrieve"
                                     ))
                    )
                    .subcommand(SubCommand::with_name("send")
                                .about("Sends a key")
                                .arg(Arg::with_name("input")
                                     .value_name("FILE")
                                     .help("Sets the input file to use"))
                    )
        )

        .subcommand(SubCommand::with_name("wkd")
                    .display_order(420)
                    .about("Interacts with Web Key Directories")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("url")
                                .about("Prints the Web Key Directory URL of \
                                        an email address.")
                                .arg(Arg::with_name("input")
                                    .value_name("EMAIL_ADDRESS")
                                    .required(true)
                                    .help("The email address from which to \
                                           obtain the WKD URI."))
                    )
                    .subcommand(SubCommand::with_name("get")
                                .about("Writes to the standard output the \
                                        Cert retrieved \
                                        from a Web Key Directory, given an \
                                        email address")
                                .arg(Arg::with_name("input")
                                    .value_name("EMAIL_ADDRESS")
                                    .required(true)
                                    .help("The email address from which to \
                                            obtain the Cert from a WKD."))
                                .arg(Arg::with_name("binary")
                                     .short("B").long("binary")
                                     .help("Don't ASCII-armor encode the OpenPGP data"))
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
                                     .help("The location to write the WKD to. \
                                            This must be the directory the \
                                            webserver is serving the \
                                            '.well-known' directory from."))
                                .arg(Arg::with_name("domain")
                                    .value_name("DOMAIN")
                                    .help("The domain for the WKD.")
                                    .required(true))
                                .arg(Arg::with_name("input")
                                    .value_name("KEYRING")
                                    .help("The keyring file with the keys to add to the WKD."))
                                .arg(Arg::with_name("direct_method")
                                     .short("d").long("direct_method")
                                     .help("Use the direct method. \
                                            [default: advanced method]"))
                    )
        )
    };

    app
}
