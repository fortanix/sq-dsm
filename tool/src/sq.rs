/// A command-line frontend for Sequoia.

extern crate clap;
extern crate failure;
#[macro_use]
extern crate prettytable;
extern crate rpassword;
extern crate time;

use failure::ResultExt;
use prettytable::Table;
use prettytable::cell::Cell;
use prettytable::row::Row;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::exit;

extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use openpgp::{armor, autocrypt, Fingerprint, TPK};
use sequoia_core::{Context, NetworkPolicy};
use sequoia_net::KeyServer;
use sequoia_store::{Store, LogIter};

mod cli;
mod commands;

fn open_or_stdin(f: Option<&str>) -> Result<Box<io::Read>, failure::Error> {
    match f {
        Some(f) => Ok(Box::new(File::open(f)
                               .context("Failed to open input file")?)),
        None => Ok(Box::new(io::stdin())),
    }
}

fn create_or_stdout(f: Option<&str>) -> Result<Box<io::Write>, failure::Error> {
    match f {
        Some(f) => Ok(Box::new(File::create(f)
                               .context("Failed to create output file")?)),
        None => Ok(Box::new(io::stdout())),
    }
}

fn real_main() -> Result<(), failure::Error> {
    let matches = cli::build().get_matches();

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
    let store_name = matches.value_of("store").unwrap_or("default");

    match matches.subcommand() {
        ("decrypt",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut input = openpgp::Reader::from_reader(input)?;
            commands::decrypt(&mut input, &mut output,
                              m.is_present("dump"), m.is_present("hex"))?;
        },
        ("encrypt",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut output = if ! m.is_present("binary") {
                Box::new(armor::Writer::new(&mut output,
                                            armor::Kind::Message,
                                            &[][..])?)
            } else {
                output
            };
            let mut store = Store::open(&ctx, store_name)
                .context("Failed to open the store")?;
            let recipients = m.values_of("recipient")
                .map(|r| r.collect())
                .unwrap_or(vec![]);
            commands::encrypt(&mut store, &mut input, &mut output,
                              m.occurrences_of("symmetric") as usize,
                              recipients)?;
        },

        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut filter = armor::Writer::new(&mut output, armor::Kind::File,
                                                &[][..])?;
            io::copy(&mut input, &mut filter)?;
        },
        ("dearmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut filter = armor::Reader::new(&mut input, armor::Kind::Any);
            io::copy(&mut filter, &mut output)?;
        },
        ("autocrypt", Some(m)) => {
            match m.subcommand() {
                ("decode",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let mut output = create_or_stdout(m.value_of("output"))?;
                    let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
                    for h in &ac.headers {
                        if let Some(ref tpk) = h.key {
                            let mut filter = armor::Writer::new(
                                &mut output, armor::Kind::PublicKey, &[][..])?;
                            tpk.serialize(&mut filter)?;
                        }
                    }
                }
                _ => {
                    eprintln!("No autocrypt subcommand given.");
                    exit(1);
                }
            }
        },

        ("dump",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut input = openpgp::Reader::from_reader(input)?;
            commands::dump(&mut input, &mut output, m.is_present("hex"))?;
        },
        ("split",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let prefix =
                // The prefix is either specified explicitly...
                m.value_of("prefix").map(|p| p.to_owned())
                .unwrap_or(
                    // ... or we derive it from the input file...
                    m.value_of("input").and_then(|i| {
                        let p = PathBuf::from(i);
                        // (but only use the filename)
                        p.file_name().map(|f| String::from(f.to_string_lossy()))
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or(String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            let mut input = openpgp::Reader::from_reader(input)?;
            commands::split(&mut input, &prefix)?;
        },
        ("keyserver",  Some(m)) => {
            let mut ks = if let Some(uri) = m.value_of("server") {
                KeyServer::new(&ctx, &uri)
            } else {
                KeyServer::sks_pool(&ctx)
            }.context("Malformed keyserver URI")?;

            match m.subcommand() {
                ("get",  Some(m)) => {
                    let keyid = m.value_of("keyid").unwrap();
                    let id = openpgp::KeyID::from_hex(keyid);
                    if id.is_none() {
                        eprintln!("Malformed key ID: {:?}\n\
                                   (Note: only long Key IDs are supported.)",
                                  keyid);
                        exit(1);
                    }
                    let id = id.unwrap();

                    let mut output = create_or_stdout(m.value_of("output"))?;
                    let mut output = if ! m.is_present("binary") {
                        Box::new(armor::Writer::new(&mut output,
                                                    armor::Kind::PublicKey,
                                                    &[][..])?)
                    } else {
                        output
                    };

                    ks.get(&id)
                        .context("Failed to retrieve key")?
                    .serialize(&mut output)
                        .context("Failed to serialize key")?;
                },
                ("send",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut input = openpgp::Reader::from_reader(input)?;

                    let tpk = TPK::from_reader(&mut input).
                        context("Malformed key")?;

                    ks.send(&tpk)
                        .context("Failed to send key to server")?;
                },
                _ => {
                    eprintln!("No keyserver subcommand given.");
                    exit(1);
                },
            }
        },
        ("store",  Some(m)) => {
            let store = Store::open(&ctx, store_name)
                .context("Failed to open the store")?;

            match m.subcommand() {
                ("list",  Some(_)) => {
                    list_bindings(&store)?;
                },
                ("add",  Some(m)) => {
                    let fp = Fingerprint::from_hex(m.value_of("fingerprint").unwrap())
                        .expect("Malformed fingerprint");
                    store.add(m.value_of("label").unwrap(), &fp)?;
                },
                ("import",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut input = openpgp::Reader::from_reader(input)?;

                    let tpk = TPK::from_reader(&mut input)?;
                    store.import(m.value_of("label").unwrap(), &tpk)?;
                },
                ("export",  Some(m)) => {
                    let tpk = store.lookup(m.value_of("label").unwrap())?.tpk()?;

                    let mut output = create_or_stdout(m.value_of("output"))?;
                    let mut output = if ! m.is_present("binary") {
                        Box::new(armor::Writer::new(&mut output,
                                                    armor::Kind::PublicKey,
                                                    &[][..])?)
                    } else {
                        output
                    };

                    tpk.serialize(&mut output)?;
                },
                ("delete",  Some(m)) => {
                    if m.is_present("label") == m.is_present("the-store") {
                        eprintln!("Please specify either a label or --the-store.");
                        exit(1);
                    }

                    if m.is_present("the-store") {
                        store.delete().context("Failed to delete the store")?;
                    } else {
                        let binding = store.lookup(m.value_of("label").unwrap())
                            .context("Failed to get key")?;
                        binding.delete().context("Failed to delete the binding")?;
                    }
                },
                ("stats",  Some(m)) => {
                    let binding = store.lookup(m.value_of("label").unwrap())?;
                    println!("Binding {:?}", binding.stats().context("Failed to get stats")?);
                    let key = binding.key().context("Failed to get key")?;
                    println!("Key {:?}", key.stats().context("Failed to get stats")?);
                },
                ("log",  Some(m)) => {
                    if m.is_present("label") {
                        let binding = store.lookup(m.value_of("label").unwrap())
                            .context("No such key")?;
                        print_log(binding.log().context("Failed to get log")?, false);
                    } else {
                        print_log(store.log().context("Failed to get log")?, true);
                    }
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
                    table.set_titles(row!["domain", "name", "network policy"]);

                    for (domain, name, network_policy, _)
                        in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            table.add_row(Row::new(vec![
                                Cell::new(&domain),
                                Cell::new(&name),
                                Cell::new(&format!("{:?}", network_policy))
                            ]));
                        }

                    table.printstd();
                },
                ("bindings",  Some(m)) => {
                    for (domain, name, _, store)
                        in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            println!("Domain {:?} Name {:?}:", domain, name);
                            list_bindings(&store)?;
                        }
                },
                ("keys",  Some(_)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["fingerprint", "updated", "status"]);

                    for (fingerprint, key) in Store::list_keys(&ctx)? {
                            let stats = key.stats()
                                .context("Failed to get key stats")?;
                            table.add_row(Row::new(vec![
                                Cell::new(&fingerprint.to_string()),
                                if let Some(ref t) = stats.updated {
                                    Cell::new(&format_time(t))
                                } else {
                                    Cell::new("")
                                },
                                Cell::new("")
                            ]));
                        }

                    table.printstd();
                },
                ("log",  Some(_)) => {
                    print_log(Store::server_log(&ctx)?, true);
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

fn list_bindings(store: &Store) -> Result<(), failure::Error> {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["label", "fingerprint"]);
    for (label, fingerprint, _) in store.iter()? {
        table.add_row(Row::new(vec![
            Cell::new(&label),
            Cell::new(&fingerprint.to_string())]));
    }
    table.printstd();
    Ok(())
}

fn print_log(iter: LogIter, with_slug: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    let mut head = row!["timestamp", "message"];
    if with_slug {
        head.insert_cell(1, Cell::new("slug"));
    }
    table.set_titles(head);

    for entry in iter {
        let mut row = row![&format_time(&entry.timestamp),
                           &entry.short()];
        if with_slug {
            row.insert_cell(1, Cell::new(&entry.slug));
        }
        table.add_row(row);
    }

    table.printstd();
}

fn format_time(t: &time::Timespec) -> String {
    time::strftime("%F %H:%M", &time::at(*t))
    .unwrap() // Only parse errors can happen.
}

fn main() {
    if let Err(e) = real_main() {
        let mut cause = e.cause();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}
