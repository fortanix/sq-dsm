use anyhow::{Context, Result};

use log::info;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use structopt::StructOpt;

use sequoia_openpgp::{
    policy::{NullPolicy, StandardPolicy},
    serialize::SerializeInto,
};

use sq_sdkms::PgpAgent;

const ENV_API_KEY: &str = "SQ_SDKMS_API_KEY";
const ENV_API_ENDPOINT: &str = "SQ_SDKMS_API_ENDPOINT";
const DEFAULT_API_ENDPOINT: &str = "https://sdkms.fortanix.com";

#[derive(StructOpt)]
#[structopt(about = "OpenPGP integration for Fortanix SDKMS")]
struct Cli {
    /// .env file containing SQ_SDKMS_API_KEY, SQ_SDKMS_API_ENDPOINT
    #[structopt(long, parse(from_os_str))]
    env_file: Option<PathBuf>,
    /// Endpoint URL (overloaded by .env file)
    #[structopt(long)]
    api_endpoint: Option<String>,
    #[structopt(long, required_unless("env-file"))]
    /// The SDKMS API key
    api_key: Option<String>,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// Produces a detached signature of the given file with SDKMS
    SignDetached {
        #[structopt(flatten)]
        args: CommonArgs,
        #[structopt(parse(from_os_str))]
        file: PathBuf,
    },
    /// Decrypts the given file with SDKMS
    Decrypt {
        #[structopt(flatten)]
        args: CommonArgs,
        #[structopt(parse(from_os_str))]
        file: PathBuf,
        #[structopt(long)]
        /// If absent, Sequoia standard PGP policy applies (set if you
        /// **really** know what you are doing)
        no_policy: bool,
    },
    /// Generates a PGP key in SDKMS, and outputs the Transferable Public Key
    GenerateKey {
        #[structopt(flatten)]
        args: CommonArgs,
        #[structopt(long, short)]
        /// An RFC2822-compliant user ID (e.g., "Paul Morphy <paul@fortanix.com>")
        user_id: String,
    },
    /// Retrieves and outputs the Transferable Public Key
    Certificate {
        #[structopt(flatten)]
        args: CommonArgs,
    },
}

#[derive(StructOpt)]
struct CommonArgs {
    #[structopt(long)]
    /// Name of the SDKMS key
    key_name: String,
    #[structopt(long)]
    /// Outputs material in PGP armored format
    armor: bool,
    /// Output file
    #[structopt(long, short = "o", parse(from_os_str))]
    output_file: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::from_args();

    let (api_key, endpoint) = match cli.env_file {
        Some(file) => {
            dotenv::from_filename(file).ok();
            let api_key = env::var(ENV_API_KEY)
                .with_context(|| format!("{} variable absent", ENV_API_KEY))?;
            let endpoint = match env::var(ENV_API_ENDPOINT) {
                Ok(endpoint) => endpoint,
                _ => DEFAULT_API_ENDPOINT.to_string(),
            };

            (api_key, endpoint)
        }
        None => {
            let api_key = match cli.api_key {
                Some(api_key) => api_key,
                None => unreachable!(),
            };
            let endpoint = match cli.api_endpoint {
                Some(endpoint) => endpoint,
                None => DEFAULT_API_ENDPOINT.to_string(),
            };
            (api_key, endpoint)
        }
    };

    let (output_file, pgp_material) = match cli.cmd {
        Command::GenerateKey { args, user_id } => {
            info!("sq-sdkms generate-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::generate_key(
                &endpoint,
                &api_key,
                &args.key_name,
                &user_id,
            )?;

            let cert = match args.armor {
                true => agent.certificate.armored().to_vec(),
                false => agent.certificate.to_vec(),
            }?;

            (args.output_file, cert)
        }
        Command::Certificate { args } => {
            info!("sq-sdkms public-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::summon(&endpoint, &api_key, &args.key_name)
                .context("Could not summon the PGP agent")?;

            let cert = match args.armor {
                true => agent.certificate.armored().to_vec()?,
                false => agent.certificate.to_vec()?,
            };

            (args.output_file, cert)
        }
        Command::SignDetached { args, file } => {
            info!("sq-sdkms sign");
            not_exists(&args.output_file)?;

            let content = fs::read(file)?;
            let mut signed_message = Vec::new();

            let agent = PgpAgent::summon(&endpoint, &api_key, &args.key_name)
                .context("Could not summon the PGP agent")?;

            agent
                .sign(&mut signed_message, &content, true, args.armor)
                .context("Could not sign the file")?;

            (args.output_file, signed_message)
        }
        Command::Decrypt {
            args,
            file,
            no_policy,
        } => {
            info!("sq-sdkms decrypt");
            not_exists(&args.output_file)?;

            let ciphertext = fs::read(file)?;

            let agent = PgpAgent::summon(&endpoint, &api_key, &args.key_name)
                .context("Could not summon the PGP agent")?;

            let mut plaintext = Vec::new();

            match no_policy {
                false => {
                    agent
                        .decrypt(&mut plaintext, &ciphertext, &StandardPolicy::new())
                        .context("Could not decrypt the file")?;
                }
                true => {
                    agent
                        .decrypt(&mut plaintext, &ciphertext, &NullPolicy::new())
                        .context("Could not decrypt the file")?;
                }
            };

            (args.output_file, plaintext)
        }
    };

    match output_file {
        None => {
            std::io::stdout().write_all(&pgp_material)?;
        }
        Some(file) => {
            let mut buf = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(file)?;
            buf.write_all(&pgp_material)?;
        }
    }

    Ok(())
}

fn not_exists(path: &Option<PathBuf>) -> Result<()> {
    match path {
        None => Ok(()),
        Some(file) => {
            if Path::new(&file).exists() {
                return Err(anyhow::Error::msg("Output file exists".to_string()));
            }
            Ok(())
        }
    }
}
