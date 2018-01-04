/// A command-line frontend for Sequoia.

extern crate clap;

use clap::{Arg, App, SubCommand, AppSettings};
use std::fs::File;
use std::io;
use std::process::exit;

extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;

use openpgp::armor;
use openpgp::tpk::TPK;
use sequoia_core::{Context, Result, NetworkPolicy};
use sequoia_net::KeyServer;

fn open_or_stdin(f: Option<&str>) -> Box<io::Read> {
    match f {
        Some(f) => Box::new(File::open(f).unwrap()),
        None => Box::new(io::stdin()),
    }
}

fn create_or_stdout(f: Option<&str>) -> Box<io::Write> {
    match f {
        Some(f) => Box::new(File::create(f).unwrap()),
        None => Box::new(io::stdout()),
    }
}

fn real_main() -> Result<()> {
    let matches = App::new("sq")
        .version("0.1.0")
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("domain").value_name("DOMAIN")
             .long("domain")
             .short("d")
             .help("Sets the domain to use"))
        .arg(Arg::with_name("policy").value_name("NETWORK-POLICY")
             .long("policy")
             .short("p")
             .help("Sets the network policy to use"))
        .subcommand(SubCommand::with_name("enarmor")
                    .about("Applies ASCII Armor to a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dearmor")
                    .about("Removes ASCII Armor from a file")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use")))
        .subcommand(SubCommand::with_name("dump")
                    .about("Lists OpenPGP packets")
                    .arg(Arg::with_name("input").value_name("FILE")
                         .long("input")
                         .short("i")
                         .help("Sets the input file to use"))
                    .arg(Arg::with_name("output").value_name("FILE")
                         .long("output")
                         .short("o")
                         .help("Sets the output file to use"))
                    .arg(Arg::with_name("dearmor")
                         .long("dearmor")
                         .short("A")
                         .help("Remove ASCII Armor from input")))
        .subcommand(SubCommand::with_name("keyserver")
                    .about("Interacts with keyservers")
                    .arg(Arg::with_name("server").value_name("URI")
                         .long("server")
                         .short("s")
                         .help("Sets the keyserver to use"))
                    .subcommand(SubCommand::with_name("get")
                                .about("Retrieves a key")
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("armor")
                                     .long("armor")
                                     .short("A")
                                     .help("Write armored data to file"))
                                .arg(Arg::with_name("keyid").value_name("KEYID")
                                     .required(true)
                                     .help("ID of the key to retrieve")))
                    .subcommand(SubCommand::with_name("send")
                                .about("Sends a key")
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .long("input")
                                     .short("i")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("dearmor")
                                     .long("dearmor")
                                     .short("A")
                                     .help("Remove ASCII Armor from input"))))
        .get_matches();

    let policy = match matches.value_of("policy") {
        None => NetworkPolicy::Encrypted,
        Some("offline") => NetworkPolicy::Offline,
        Some("anonymized") => NetworkPolicy::Anonymized,
        Some("encrypted") => NetworkPolicy::Encrypted,
        Some("insecure") => NetworkPolicy::Insecure,
        Some(_) => {
            eprintln!("Bad network policy, must be offline, anonymized, encrypted, or insecure.");
            exit(1);
        },
    };
    let ctx = Context::configure(matches.value_of("domain").unwrap_or("org.sequoia-pgp.sq"))
        .network_policy(policy).build()?;

    match matches.subcommand() {
        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let mut filter = armor::Writer::new(&mut output, armor::Kind::File);
            io::copy(&mut input, &mut filter).unwrap();
        },
        ("dearmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let mut filter = armor::Reader::new(&mut input, armor::Kind::Any);
            io::copy(&mut filter, &mut output).unwrap();
        },
        ("dump",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"));
            let mut output = create_or_stdout(m.value_of("output"));
            let input = if m.is_present("dearmor") {
                Box::new(armor::Reader::new(&mut input, armor::Kind::Any))
            } else {
                input
            };

            // Indent packets according to their recursion level.
            let indent = "                                                  ";

            let mut ppo
                = openpgp::parse::PacketParserBuilder::from_reader(input)?
                    .finalize()?;
            while ppo.is_some() {
                let mut pp = ppo.unwrap();

                if let openpgp::Packet::Literal(_) = pp.packet {
                    // XXX: We should actually stream this.  In fact,
                    // we probably only want to print out the first
                    // line or so and then print the total number of
                    // bytes.
                    pp.buffer_unread_content()?;
                }
                writeln!(output, "{}{:?}",
                         &indent[0..pp.recursion_depth as usize], pp.packet)?;

                let (_, _, ppo_tmp, _) = pp.recurse()?;
                ppo = ppo_tmp;
            }
        },
        ("keyserver",  Some(m)) => {
            let mut ks = if let Some(uri) = m.value_of("server") {
                KeyServer::new(&ctx, &uri)
            } else {
                KeyServer::sks_pool(&ctx)
            }.expect("Malformed keyserver URI");

            match m.subcommand() {
                ("get",  Some(m)) => {
                    let keyid = m.value_of("keyid").unwrap();
                    let id = openpgp::types::KeyId::from_hex(keyid);
                    if id.is_none() {
                        eprintln!("Malformed keyid: {:?}", keyid);
                        exit(1);
                    }

                    let mut output = create_or_stdout(m.value_of("output"));
                    let mut output = if m.is_present("armor") {
                        Box::new(armor::Writer::new(&mut output, armor::Kind::PublicKey))
                    } else {
                        output
                    };

                    ks.get(&id.unwrap()).expect("An error occured")
                        .serialize(&mut output).expect("An error occured");
                },
                ("send",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"));
                    let mut input = if m.is_present("dearmor") {
                        Box::new(armor::Reader::new(&mut input, armor::Kind::Any))
                    } else {
                        input
                    };

                    let tpk = TPK::from_reader(&mut input).
                        expect("Malformed key");

                    ks.send(&tpk).expect("An error occured");
                },
                _ => {
                    eprintln!("No keyserver subcommand given.");
                    exit(1);
                },
            }
        },
        _ => {
            eprintln!("No subcommand given.");
            exit(1);
        },
    }

    return Ok(())
}

fn main() { real_main().expect("An error occured"); }
