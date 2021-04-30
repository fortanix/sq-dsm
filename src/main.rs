use anyhow::{Context, Result};

use log::info;

use std::{
    env, fs,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use structopt::StructOpt;

use sequoia_openpgp::{
    policy::{NullPolicy, StandardPolicy},
    serialize::SerializeInto,
};

use sq_sdkms::{PgpAgent, SupportedPkAlgo};

const ENV_API_KEY: &str = "FORTANIX_API_KEY";
const ENV_API_ENDPOINT: &str = "FORTANIX_API_ENDPOINT";

#[derive(StructOpt)]
/// OpenPGP integration for Fortanix SDKMS
struct Cli {
    /// .env file containing SQ_SDKMS_API_KEY, SQ_SDKMS_API_ENDPOINT
    #[structopt(long, parse(from_os_str))]
    env_file: Option<PathBuf>,
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
        /// If absent, Sequoia standard PGP policy applies (set if you
        /// **really** know what you are doing)
        #[structopt(long)]
        no_policy: bool,
    },
    /// Generates a PGP key in SDKMS, and outputs the Transferable Public Key.
    GenerateKey {
        #[structopt(flatten)]
        args: CommonArgs,
        /// An RFC2822-compliant user ID (e.g., "Paul Morphy <paul@fortanix.com>")
        #[structopt(long, short)]
        user_id: Option<String>,
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
    if let Some(file) = cli.env_file {
        dotenv::from_filename(file).ok();
    }

    let (api_key, endpoint) = {
        let api_key =
            env::var(ENV_API_KEY).with_context(|| format!("{} env var absent", ENV_API_KEY))?;
        let endpoint = env::var(ENV_API_ENDPOINT)
            .with_context(|| format!("{} env var absent", ENV_API_ENDPOINT))?;

        (api_key, endpoint)
    };

    let (output_file, pgp_material) = match cli.cmd {
        Command::GenerateKey { args, user_id } => {
            info!("sq-sdkms generate-key");
            not_exists(&args.output_file)?;

            let algo = pk_algo_prompt()?;
            let user_id = match user_id {
                Some(user_id) => user_id,
                None => user_id_prompt()?,
            };

            let agent = PgpAgent::generate_key(
                &endpoint,
                &api_key,
                &args.key_name,
                &user_id,
                &algo,
            )?;

            let cert = if args.armor || args.output_file == None {
                agent.certificate.armored().to_vec()
            } else {
                agent.certificate.to_vec()
            }?;

            (args.output_file, cert)
        },
        Command::Certificate { args } => {
            info!("sq-sdkms public-key");
            not_exists(&args.output_file)?;

            let agent = PgpAgent::summon(&endpoint, &api_key, &args.key_name)
                .context("Could not summon the PGP agent")?;

            let cert = if args.armor {
                agent.certificate.armored().to_vec()
            } else {
                agent.certificate.to_vec()
            }?;

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

            if no_policy {
                agent
                    .decrypt(&mut plaintext, &ciphertext, &NullPolicy::new())
                    .context("Could not decrypt the file")?;
            } else {
                agent
                    .decrypt(&mut plaintext, &ciphertext, &StandardPolicy::new())
                    .context("Could not decrypt the file")?;
            }

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

fn pk_algo_prompt() -> Result<SupportedPkAlgo> {
    loop {
        println!("\nSelect public key algorithm:\n");
        println!("   (1) RSA");
        print!("\nYour choice: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        match line.trim().parse::<u32>()? {
            1 => {
                let key_size = loop {
                    println!("\nSelect RSA key size:\n");
                    println!("   (1) 2048");
                    println!("   (2) 3072");
                    println!("   (3) 4096");
                    print!("\nYour choice: ");
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    match input.trim().parse::<u32>()? {
                        1 => break 2048,
                        2 => break 3072,
                        3 => break 4096,
                        _ => println!("Invalid input"),
                    }
                };

                return Ok(SupportedPkAlgo::Rsa(key_size))
            },
            _ => println!("Invalid input"),
        }
    }
}

fn user_id_prompt() -> Result<String> {
    println!("\nTo identify your key, you need to create a user ID of the form");
    println!("\n    \"Paul Morphy (Comment) <paul@fortanix.com>\"\n");

    let user_id = loop {
        print!("Your name: ");
        std::io::stdout().flush()?;
        let name = std::io::stdin().lock().lines().next().unwrap()?;

        print!("Optional comment: ");
        std::io::stdout().flush()?;
        let comment = std::io::stdin().lock().lines().next().unwrap()?;

        print!("Your email: ");
        std::io::stdout().flush()?;
        let email = std::io::stdin().lock().lines().next().unwrap()?;

        let user_id = format!("{} ({}) <{}>", &name, &comment, &email);

        println!("\nIs the following user ID correct?");
        println!("\n    \"{}\"\n", user_id);
        print!("(y/n): ");
        std::io::stdout().flush()?;
        let choice = std::io::stdin().lock().lines().next().unwrap()?;
        if choice == "y" {
            break user_id
        }
    };

    Ok(user_id)
}
