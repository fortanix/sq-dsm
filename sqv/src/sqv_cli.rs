/// Command-line parser for sqv.
///
/// If you change this file, please rebuild `sqv`, run `make -C tool
/// update-usage`, and commit the resulting changes to
/// `tool/src/sqv-usage.rs`.

use clap::{App, Arg, AppSettings};

// The argument parser.
pub fn build() -> App<'static, 'static> {
    App::new("sqv")
        .version("0.1.0")
        .about("sqv is a command-line OpenPGP signature verification tool.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("keyring").value_name("FILE")
             .help("A keyring.  Can be given multiple times.")
             .long("keyring")
             .required(true)
             .takes_value(true)
             .number_of_values(1)
             .multiple(true))
        .arg(Arg::with_name("signatures").value_name("N")
             .help("The number of valid signatures to return success.  Default: 1")
             .long("signatures")
             .short("n")
             .takes_value(true))
        .arg(Arg::with_name("not-before").value_name("YYYY-MM-DD")
             .help("Consider signatures created before YYYY-MM-DD as invalid.  \
                    Default: no constraint")
             .long("not-before")
             .takes_value(true))
        .arg(Arg::with_name("not-after").value_name("YYYY-MM-DD")
             .help("Consider signatures created after YYYY-MM-DD as invalid.  \
                    Default: now")
             .long("not-after")
             .takes_value(true))
        .arg(Arg::with_name("sig-file").value_name("SIG-FILE")
             .help("File containing the detached signature.")
             .required(true))
        .arg(Arg::with_name("file").value_name("FILE")
             .help("File to verify.")
             .required(true))
        .arg(Arg::with_name("trace")
             .help("Trace execution.")
             .long("trace"))
}
