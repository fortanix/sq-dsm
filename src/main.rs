use anyhow::Result;

use log::info;

use std::{path::{Path, PathBuf}, io::{Read, Write}, fs::{OpenOptions}};

use structopt::StructOpt;

use sequoia_openpgp::serialize::SerializeInto;

use sq_sdkms::PgpAgent;

const DEFAULT_API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";

#[derive(StructOpt)]
#[structopt(about = "OpenPGP integration for Fortanix SDKMS")]
/// TODO: Document me!
struct Cli {
    #[structopt(long)]
    /// (Optional) Endpoint URL
    api_endpoint: Option<String>,
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
    /// Generates a PGP key in SDKMS, and outputs the public key
    GenerateKey {
        #[structopt(flatten)]
        args: CommonArgs,
    },
    /// Retrieves and outputs the public key
    PublicKey {
        #[structopt(flatten)]
        args: CommonArgs,
    },
}

#[derive(StructOpt)]
struct CommonArgs {
    #[structopt(long)]
    /// The SDKMS API key
    api_key: String,
    #[structopt(long)]
    /// The name of the SDKMS key
    key_name: String,
    #[structopt(long)]
    /// Outputs material in PGP armored format
    armor: bool,
    /// Output file
    #[structopt(short = "o", parse(from_os_str), required_unless("armor"))]
    output_file: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cmd = Cli::from_args();

    let api_endpoint = match cmd.api_endpoint {
        Some(endpoint) => endpoint,
        None => DEFAULT_API_ENDPOINT.to_string(),
    };

    let (output_file, pgp_material) = match cmd.cmd {
        Command::GenerateKey {args} => {
            info!("sq-sdkms generate-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::generate_key(
                &api_endpoint,
                &args.api_key,
                &args.key_name,
            )?;
            let cert = match args.armor {
                true => agent.certificate.armored().to_vec()?,
                false => agent.certificate.to_vec()?,
            };

            (args.output_file, cert)
        },
        Command::PublicKey {args} => {
            info!("sq-sdkms public-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::summon(
                &api_endpoint,
                &args.api_key,
                &args.key_name,
            )?;

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
                &args.api_key,
                &args.key_name,
            )?;

            agent.sign(&mut signed_message, &content)?;

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
                &args.api_key,
                &args.key_name,
            )?;

            let mut plaintext = Vec::new();
            agent.decrypt(&mut plaintext, &ciphertext)?;

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
                return Err(anyhow::Error::msg("Output file already exists".to_string()))
            }
            Ok(())
        },
    }
}
