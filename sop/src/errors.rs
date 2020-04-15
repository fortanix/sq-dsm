/// Errors defined by the Stateless OpenPGP Protocol.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    /// No acceptable signatures found ("sop verify").
    #[error("No acceptable signatures found")]
    NoSignature,

    /// Asymmetric algorithm unsupported ("sop encrypt").
    #[error("Asymmetric algorithm unsupported")]
    UnsupportedAsymmetricAlgo,

    /// Certificate not encryption-capable (e.g., expired, revoked,
    /// unacceptable usage flags) ("sop encrypt").
    #[error("Certificate not encryption-capable")]
    CertCannotEncrypt,

    /// Missing required argument.
    #[error("Missing required argument")]
    MissingArg,

    /// Incomplete verification instructions ("sop decrypt").
    #[error("Incomplete verification instructions")]
    IncompleteVerification,

    /// Unable to decrypt ("sop decrypt").
    #[error("Unable to decrypt")]
    CannotDecrypt,

    /// Non-"UTF-8" or otherwise unreliable password ("sop encrypt").
    #[error("Non-UTF-8 or otherwise unreliable password")]
    PasswordNotHumanReadable,

    /// Unsupported option.
    #[error("Unsupported option")]
    UnsupportedOption,

    /// Invalid data type (no secret key where "KEY" expected, etc).
    #[error("Invalid data type")]
    BadData,

    /// Non-text input where text expected.
    #[error("Non-text input where text expected")]
    ExpectedText,

    /// Output file already exists.
    #[error("Output file already exists")]
    OutputExists,

    /// Input file does not exist.
    #[error("Input file does not exist")]
    MissingInput,

    /// A "KEY" input is protected (locked) with a password, and "sop" cannot
    /// unlock it.
    #[error("A KEY input is protected with a password")]
    KeyIsProtected,

    /// Unsupported subcommand.
    #[error("Unsupported subcommand")]
    UnsupportedSubcommand,

    /// An indirect parameter is a special designator (it starts with "@") but
    /// "sop" does not know how to handle the prefix.
    #[error("An indirect parameter is a special designator with unknown prefix")]
    UnsupportedSpecialPrefix,

    /// A indirect input parameter is a special designator (it starts with
    /// "@"), and a filename matching the designator is actually present.
    #[error("A indirect input parameter is a special designator matches file")]
    AmbiguousInput,
}

impl From<Error> for i32 {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            NoSignature => 3,
            UnsupportedAsymmetricAlgo => 13,
            CertCannotEncrypt => 17,
            MissingArg => 19,
            IncompleteVerification => 23,
            CannotDecrypt => 29,
            PasswordNotHumanReadable => 31,
            UnsupportedOption => 37,
            BadData => 41,
            ExpectedText => 53,
            OutputExists => 59,
            MissingInput => 61,
            KeyIsProtected => 67,
            UnsupportedSubcommand => 69,
            UnsupportedSpecialPrefix => 71,
            AmbiguousInput => 73,
        }
    }
}

/// Prints the error and causes, if any.
pub fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}
