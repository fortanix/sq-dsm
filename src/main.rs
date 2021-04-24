use anyhow::{Context, Result};

use log::info;

use std::{path::{Path, PathBuf}, io::{Read, Write}, fs::{OpenOptions}, env};

use structopt::StructOpt;

use sequoia_openpgp::serialize::SerializeInto;

use sq_sdkms::PgpAgent;

const ENV_API_KEY: &'static str = "SQ_SDKMS_API_KEY";
const ENV_API_ENDPOINT: &'static str = "SQ_SDKMS_API_ENDPOINT";
const DEFAULT_API_ENDPOINT: &'static str = "https://sdkms.fortanix.com";

#[derive(StructOpt)]
#[structopt(about = "OpenPGP integration for Fortanix SDKMS")]
/// TODO: Document me!
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
    /// Signs the given file with SDKMS
    Sign {
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
    },
    /// Generates a PGP key in SDKMS, and outputs the Transferable Public Key
    GenerateKey {
        #[structopt(flatten)]
        args: CommonArgs,
    },
    /// Retrieves and outputs the Transferable Public Key
    PublicKey {
        #[structopt(flatten)]
        args: CommonArgs,
    },
}

#[derive(StructOpt)]
struct CommonArgs {
    #[structopt(long)]
    /// The name of the SDKMS key
    key_name: String,
    #[structopt(long)]
    /// Outputs material in PGP armored format
    armor: bool,
    /// Output file
    #[structopt(long, short = "o", parse(from_os_str), required_unless("armor"))]
    output_file: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::from_args();

    let (api_key, api_endpoint) = match cli.env_file {
        Some(file) => {
            dotenv::from_filename(file).ok();
            let api_key = env::var(ENV_API_KEY)
                .with_context(|| format!("{} variable absent", ENV_API_KEY))?;
            let api_endpoint = match env::var(ENV_API_ENDPOINT) {
                Ok(endpoint) => endpoint,
                _ => DEFAULT_API_ENDPOINT.to_string(),
            };

            (api_key, api_endpoint)
        }
        None =>{
            let api_key = match cli.api_key {
                Some(api_key) => api_key,
                None => unreachable!(),
            };
            let api_endpoint = match cli.api_endpoint {
                Some(endpoint) => endpoint,
                None => DEFAULT_API_ENDPOINT.to_string(),
            };
            (api_key, api_endpoint)
        }
    };

    let (output_file, pgp_material) = match cli.cmd {
        Command::GenerateKey {args} => {
            info!("sq-sdkms generate-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::generate_key(
                &api_endpoint,
                &api_key,
                &args.key_name,
            )?;

            let cert = match args.armor {
                true => agent.certificate.armored().to_vec(),
                false => agent.certificate.to_vec(),
            }?;

            (args.output_file, cert)
        },
        Command::PublicKey {args} => {
            info!("sq-sdkms public-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::summon(
                &api_endpoint,
                &api_key,
                &args.key_name,
            ).context("Could not summon the PGP agent")?;

            let cert = match args.armor {
                true => agent.certificate.armored().to_vec()?,
                false => agent.certificate.to_vec()?,
            };

            (args.output_file, cert)
        }
        Command::Sign { args, file } => {
            info!("sq-sdkms sign");
            not_exists(&args.output_file)?;

            let mut input_file = OpenOptions::new().read(true).open(file)?;
            let mut content = Vec::new();
            input_file.read(&mut content)?;
            let mut signed_message = Vec::new();

            let agent = PgpAgent::summon(
                &api_endpoint,
                &api_key,
                &args.key_name,
            ).context("Could not summon the PGP agent")?;

            agent.sign(&mut signed_message, &content)
                .context("Could not sign the message")?;

            (args.output_file, signed_message)
        },
        Command::Decrypt { args, file } => {
            info!("sq-sdkms decrypt");
            not_exists(&args.output_file)?;

            let mut input_file = OpenOptions::new().read(true).open(file)?;
            let mut ciphertext = Vec::new();
            input_file.read(&mut ciphertext)?;

            let agent = PgpAgent::summon(
                &api_endpoint,
                &api_key,
                &args.key_name,
            ).context("Could not summon the PGP agent")?;

            let mut plaintext = Vec::new();
            agent.decrypt(&mut plaintext, &ciphertext)
                .context("Could not sign the message")?;

            (args.output_file, plaintext)
        }
    };

    match output_file {
        None => {
            std::io::stdout().write(&pgp_material)?;
        }
        Some(file) => {
            let mut buf = OpenOptions::new().write(true)
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
                return Err(anyhow::Error::msg("Output file exists".to_string()))
            }
            Ok(())
        },
    }
}
