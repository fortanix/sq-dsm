use std::fmt;
use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, offset::Utc};
use structopt::StructOpt;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        CertParser,
    },
    crypto::{
        Password,
    },
    types::{
        SignatureType,
        DataFormat,
    },
    parse::Parse,
};

use super::{
    dates,
    Error,
    Result,
};

#[derive(StructOpt)]
#[structopt(about = "An implementation of the \
                     Stateless OpenPGP Command Line Interface \
                     using Sequoia")]
pub enum SOP {
    /// Prints version information.
    Version {
    },
    /// Generates a Secret Key.
    GenerateKey {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// UserIDs for the generated key.
        userids: Vec<String>,
    },
    /// Extracts a Certificate from a Secret Key.
    ExtractCert {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
    },
    /// Creates Detached Signatures.
    Sign {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// Sign binary data or UTF-8 text.
        #[structopt(default_value = "binary", long = "as")]
        as_: SignAs,
        /// Keys for signing.
        keys: Vec<String>,
    },
    /// Verifies Detached Signatures.
    Verify {
        /// Consider signatures before this date invalid.
        #[structopt(long, parse(try_from_str = dates::parse_bound_round_down))]
        not_before: Option<DateTime<Utc>>,
        /// Consider signatures after this date invalid.
        #[structopt(long, parse(try_from_str = dates::parse_bound_round_up))]
        not_after: Option<DateTime<Utc>>,
        /// Signatures to verify.
        signatures: String,
        /// Certs for verification.
        certs: Vec<String>,
    },
    /// Encrypts a Message.
    Encrypt {
        /// Don't ASCII-armor output.
        #[structopt(long)]
        no_armor: bool,
        /// Encrypt binary data, UTF-8 text, or MIME data.
        #[structopt(default_value = "binary", long = "as")]
        as_: EncryptAs,
        /// Encrypt with passwords.
        #[structopt(long)]
        with_password: Vec<String>,
        /// Keys for signing.
        #[structopt(long)]
        sign_with: Vec<String>,
        /// Encrypt for these certs.
        certs: Vec<String>,
    },
    /// Decrypts a Message.
    Decrypt {
        /// Write the session key here.
        #[structopt(long)]
        session_key_out: Option<String>,
        /// Try to decrypt with this session key.
        #[structopt(long)]
        with_session_key: Vec<String>,
        /// Try to decrypt with this password.
        #[structopt(long)]
        with_password: Vec<String>,
        /// Write verification result here.
        #[structopt(long)]
        verify_out: Option<String>,
        /// Certs for verification.
        #[structopt(long)]
        verify_with: Vec<String>,
        /// Consider signatures before this date invalid.
        #[structopt(long, parse(try_from_str = dates::parse_bound_round_down))]
        verify_not_before: Option<DateTime<Utc>>,
        /// Consider signatures after this date invalid.
        #[structopt(long, parse(try_from_str = dates::parse_bound_round_up))]
        verify_not_after: Option<DateTime<Utc>>,
        /// Try to decrypt with this key.
        key: Vec<String>,
    },
    /// Converts binary OpenPGP data to ASCII
    Armor {
        /// Indicates the kind of data
        #[structopt(long, default_value = "auto")]
        label: ArmorKind,
    },
    /// Converts ASCII OpenPGP data to binary
    Dearmor {
    },
    /// Unsupported subcommand.
    #[structopt(external_subcommand)]
    Unsupported(Vec<String>),
}

#[derive(Clone, Copy)]
pub enum SignAs {
    Binary,
    Text,
}

impl std::str::FromStr for SignAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "binary" => Ok(SignAs::Binary),
            "text" => Ok(SignAs::Text),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of {{binary|text}}", s)),
        }
    }
}

impl fmt::Display for SignAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignAs::Binary => f.write_str("binary"),
            SignAs::Text => f.write_str("text"),
        }
    }
}

impl From<SignAs> for SignatureType {
    fn from(a: SignAs) -> Self {
        match a {
            SignAs::Binary => SignatureType::Binary,
            SignAs::Text => SignatureType::Text,
        }
    }
}

#[derive(Clone, Copy)]
pub enum EncryptAs {
    Binary,
    Text,
    MIME,
}

impl std::str::FromStr for EncryptAs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "binary" => Ok(EncryptAs::Binary),
            "text" => Ok(EncryptAs::Text),
            "mime" => Ok(EncryptAs::MIME),
            _ => Err(anyhow::anyhow!(
                "{}, expected one of {{binary|text|mime}}", s)),
        }
    }
}

impl fmt::Display for EncryptAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptAs::Binary => f.write_str("binary"),
            EncryptAs::Text => f.write_str("text"),
            EncryptAs::MIME => f.write_str("mime"),
        }
    }
}

impl From<EncryptAs> for SignatureType {
    fn from(a: EncryptAs) -> Self {
        match a {
            EncryptAs::Binary => SignatureType::Binary,
            EncryptAs::Text => SignatureType::Text,
            // XXX: We should inspect the serialized MIME structure
            // and use Text if it is UTF-8, Binary otherwise.  But, we
            // cannot be bothered at this point.
            EncryptAs::MIME => SignatureType::Binary,
        }
    }
}

impl From<EncryptAs> for DataFormat {
    fn from(a: EncryptAs) -> Self {
        match a {
            EncryptAs::Binary => DataFormat::Binary,
            EncryptAs::Text => DataFormat::Text,
            EncryptAs::MIME => DataFormat::MIME,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ArmorKind {
    Auto,
    Sig,
    Key,
    Cert,
    Message,
}

impl std::str::FromStr for ArmorKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> openpgp::Result<Self> {
        match s {
            "auto" => Ok(ArmorKind::Auto),
            "sig" => Ok(ArmorKind::Sig),
            "key" => Ok(ArmorKind::Key),
            "cert" => Ok(ArmorKind::Cert),
            "message" => Ok(ArmorKind::Message),
            _ => Err(anyhow::anyhow!(
                "{:?}, expected one of \
                 {{auto|sig|key|cert|message}}", s)),
        }
    }
}

impl fmt::Display for ArmorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArmorKind::Auto => f.write_str("auto"),
            ArmorKind::Sig => f.write_str("sig"),
            ArmorKind::Key => f.write_str("key"),
            ArmorKind::Cert => f.write_str("cert"),
            ArmorKind::Message => f.write_str("message"),
        }
    }
}


fn is_special_designator<S: AsRef<str>>(file: S) -> bool {
    file.as_ref().starts_with("@")
}

/// Loads the given (special) file.
pub fn load_file<S: AsRef<str>>(file: S) -> Result<std::fs::File> {
    let f = file.as_ref();

    if is_special_designator(f) {
        if Path::new(f).exists() {
            return Err(anyhow::Error::from(Error::AmbiguousInput))
                .context(format!("File {:?} exists", f));
        }

        return Err(anyhow::Error::from(Error::UnsupportedSpecialPrefix));
    }

    std::fs::File::open(f).map_err(|_| Error::MissingInput)
            .context(format!("Failed to open file {:?}", f))
}

/// Creates the given (special) file.
pub fn create_file<S: AsRef<str>>(file: S) -> Result<std::fs::File> {
    let f = file.as_ref();

    if is_special_designator(f) {
        if Path::new(f).exists() {
            return Err(anyhow::Error::from(Error::AmbiguousInput))
                .context(format!("File {:?} exists", f));
        }

        return Err(anyhow::Error::from(Error::UnsupportedSpecialPrefix));
    }

    if Path::new(f).exists() {
        return Err(anyhow::Error::from(Error::OutputExists))
            .context(format!("File {:?} exists", f));
    }

    std::fs::File::create(f).map_err(|_| Error::MissingInput) // XXX
            .context(format!("Failed to create file {:?}", f))
}

/// Loads the certs given by the (special) files.
pub fn load_certs(files: Vec<String>) -> Result<Vec<Cert>> {
    let mut certs = vec![];
    for f in files {
        let r = load_file(&f)?;
        for cert in CertParser::from_reader(r).map_err(|_| Error::BadData)
            .context(format!("Failed to load CERTS from file {:?}", f))?
        {
            certs.push(
                cert.context(format!("Malformed certificate in file {:?}", f))?
            );
        }
    }
    Ok(certs)
}

/// Loads the KEY given by the (special) files.
pub fn load_keys(files: Vec<String>) -> Result<Vec<Cert>> {
    let mut keys = vec![];
    for f in files {
        let r = load_file(&f)?;
        keys.push(Cert::from_reader(r).map_err(|_| Error::BadData)
                   .context(format!("Failed to load KEY from file {:?}", f))?);
    }
    Ok(keys)
}

/// Frobnicates the strings and converts them to passwords.
pub fn frob_passwords(p: Vec<String>) -> Result<Vec<Password>> {
    // XXX: Maybe do additional checks.
    Ok(p.iter().map(|p| p.trim_end().into()).collect())
}
