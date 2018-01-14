/// A command-line frontend for Sequoia.

extern crate clap;
#[macro_use]
extern crate prettytable;

use clap::{Arg, App, SubCommand, AppSettings};
use prettytable::Table;
use prettytable::cell::Cell;
use prettytable::row::Row;
use std::fs::File;
use std::io;
use std::process::exit;

extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use openpgp::{armor, Fingerprint};
use openpgp::tpk::TPK;
use sequoia_core::{Context, Result, NetworkPolicy};
use sequoia_net::KeyServer;
use sequoia_store::Store;

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
        .subcommand(SubCommand::with_name("store")
                    .about("Interacts with key stores")
                    .arg(Arg::with_name("name").value_name("NAME")
                         .required(true)
                         .help("Name of the store"))
                    .subcommand(SubCommand::with_name("list")
                                .about("Lists keys in the store"))
                    .subcommand(SubCommand::with_name("add")
                                .about("Add a key identified by fingerprint")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("fingerprint").value_name("FINGERPRINT")
                                     .required(true)
                                     .help("Key to add")))
                    .subcommand(SubCommand::with_name("import")
                                .about("Imports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("input").value_name("FILE")
                                     .long("input")
                                     .short("i")
                                     .help("Sets the input file to use"))
                                .arg(Arg::with_name("dearmor")
                                     .long("dearmor")
                                     .short("A")
                                     .help("Remove ASCII Armor from input")))
                    .subcommand(SubCommand::with_name("export")
                                .about("Exports a key")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))
                                .arg(Arg::with_name("output").value_name("FILE")
                                     .long("output")
                                     .short("o")
                                     .help("Sets the output file to use"))
                                .arg(Arg::with_name("armor")
                                     .long("armor")
                                     .short("A")
                                     .help("Write armored data to file")))
                    .subcommand(SubCommand::with_name("delete")
                                .about("Deletes bindings or stores")
                                .arg(Arg::with_name("the-store")
                                     .long("the-store")
                                     .help("Delete the whole store"))
                                .arg(Arg::with_name("label")
                                     .value_name("LABEL")
                                     .help("Delete binding with this label")))
                    .subcommand(SubCommand::with_name("stats")
                                .about("Get stats for the given label")
                                .arg(Arg::with_name("label").value_name("LABEL")
                                     .required(true)
                                     .help("Label to use"))))
        .subcommand(SubCommand::with_name("list")
                    .about("Lists key stores and known keys")
                    .subcommand(SubCommand::with_name("stores")
                                .about("Lists key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("bindings")
                                .about("Lists all bindings in all key stores")
                                .arg(Arg::with_name("prefix").value_name("PREFIX")
                                     .help("List only bindings from stores with the given domain prefix")))
                    .subcommand(SubCommand::with_name("keys")
                                .about("Lists all keys in the common key pool")))
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
                    let id = openpgp::KeyID::from_hex(keyid);
                    if id.is_none() {
                        eprintln!("Malformed key ID: \"{:?}\"\n\
                                   (Note: only long Key IDs are supported.)",
                                  keyid);
                        exit(1);
                    }
                    let id = id.unwrap();

                    let mut output = create_or_stdout(m.value_of("output"));
                    let mut output = if m.is_present("armor") {
                        Box::new(armor::Writer::new(&mut output, armor::Kind::PublicKey))
                    } else {
                        output
                    };

                    ks.get(&id).expect("An error occured")
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
        ("store",  Some(m)) => {
            let store = Store::open(&ctx, m.value_of("name").unwrap())
                .expect("Failed to open store");

            match m.subcommand() {
                ("list",  Some(_)) => {
                    list_bindings(&store);
                },
                ("add",  Some(m)) => {
                    let fp = Fingerprint::from_hex(m.value_of("fingerprint").unwrap())
                        .expect("Malformed fingerprint");
                    store.add(m.value_of("label").unwrap(), &fp)
                        .expect("Failed to add key");
                },
                ("import",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"));
                    let mut input = if m.is_present("dearmor") {
                        Box::new(armor::Reader::new(&mut input, armor::Kind::Any))
                    } else {
                        input
                    };

                    let tpk = TPK::from_reader(&mut input).
                        expect("Malformed key");
                    store.import(m.value_of("label").unwrap(), &tpk)
                        .expect("Failed to import key");
                },
                ("export",  Some(m)) => {
                    let tpk = store.lookup(m.value_of("label").unwrap())
                        .expect("Failed to get the key")
                        .tpk()
                        .expect("Failed to get the key");

                    let mut output = create_or_stdout(m.value_of("output"));
                    let mut output = if m.is_present("armor") {
                        Box::new(armor::Writer::new(&mut output, armor::Kind::PublicKey))
                    } else {
                        output
                    };

                    tpk.serialize(&mut output)
                        .expect("Failed to write the key");
                },
                ("delete",  Some(m)) => {
                    if m.is_present("label") == m.is_present("the-store") {
                        eprintln!("Please specify either a label or --the-store.");
                        exit(1);
                    }

                    if m.is_present("the-store") {
                        store.delete().expect("Failed to delete the store");
                    } else {
                        let binding = store.lookup(m.value_of("label").unwrap())
                            .expect("Failed to get key");
                        binding.delete().expect("Failed to delete the binding");
                    }
                },
                ("stats",  Some(m)) => {
                    let binding = store.lookup(m.value_of("label").unwrap())
                        .expect("Failed to get key");
                    println!("Binding {:?}", binding.stats().expect("Failed to get stats"));
                    let key = binding.key().expect("Failed to get key");
                    println!("Key {:?}", key.stats().expect("Failed to get stats"));
                },
                _ => {
                    eprintln!("No store subcommand given.");
                    exit(1);
                },
            }
        },
        ("list",  Some(m)) => {
            match m.subcommand() {
                ("stores",  Some(m)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["domain", "name", "network policy", "# of entries"]);

                    for item in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))
                        .expect("Failed to iterate over stores") {
                            table.add_row(Row::new(vec![
                                Cell::new(&item.domain),
                                Cell::new(&item.name),
                                Cell::new(&format!("{:?}", item.network_policy)),
                                Cell::new(&format!("{}", item.entries))])
                            );
                        }

                    table.printstd();
                },
                ("bindings",  Some(m)) => {
                    for item in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))
                        .expect("Failed to iterate over stores") {
                            println!("Domain {:?} Name {:?}:", item.domain, item.name);
                            list_bindings(&item.store);
                        }
                },
                ("keys",  Some(_)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["fingerprint", "# of bindings"]);

                    for item in Store::list_keys(&ctx)
                        .expect("Failed to iterate over keys") {
                            table.add_row(Row::new(vec![
                                Cell::new(&item.fingerprint.to_string()),
                                Cell::new(&format!("{}", item.bindings))])
                            );
                        }

                    table.printstd();
                },
                _ => {
                    eprintln!("No list subcommand given.");
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

fn list_bindings(store: &Store) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["label", "fingerprint"]);
    for item in store.iter().expect("Failed to iterate over bindings") {
        table.add_row(Row::new(vec![
            Cell::new(&item.label),
            Cell::new(&item.fingerprint.to_string())]));
    }
    table.printstd();
}


fn main() { real_main().expect("An error occured"); }
