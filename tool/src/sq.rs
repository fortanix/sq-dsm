/// A command-line frontend for Sequoia.

extern crate clap;
extern crate failure;
#[macro_use]
extern crate prettytable;
extern crate rpassword;
extern crate tempfile;
extern crate time;

use failure::ResultExt;
use prettytable::{Table, Cell, Row};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::process::exit;

extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use openpgp::{armor, autocrypt, Fingerprint, TPK};
use openpgp::serialize::Serialize;
use sequoia_core::{Context, NetworkPolicy};
use sequoia_net::KeyServer;
use sequoia_store::{Store, LogIter};

mod sq_cli;
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
        Some(f) => Ok(Box::new(OpenOptions::new().write(true).create_new(true)
                               .open(f)
                               .context("Failed to create output file")?)),
        None => Ok(Box::new(io::stdout())),
    }
}

fn load_tpks<'a, I>(files: I) -> openpgp::Result<Vec<TPK>>
    where I: Iterator<Item=&'a str>
{
    let mut tpks = vec![];
    for f in files {
        tpks.push(TPK::from_reader(
            // Use an openpgp::Reader so that we accept both armored
            // and plain PGP data.
            openpgp::Reader::from_file(f)
                .context(format!("Failed to open key file {:?}", f))?)
                  .context(format!("Failed to load key from file {:?}", f))?);
    }
    Ok(tpks)
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
fn help_warning(arg: &str) {
    if arg == "help" {
        eprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

fn real_main() -> Result<(), failure::Error> {
    let matches = sq_cli::build().get_matches();

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
    let domain_name =
        matches.value_of("domain").unwrap_or("org.sequoia-pgp.sq");
    let mut builder = Context::configure(domain_name)
        .network_policy(policy);
    if let Some(dir) = matches.value_of("home") {
        builder = builder.home(dir);
    }
    let ctx = builder.build()?;
    let store_name = matches.value_of("store").unwrap_or("default");

    match matches.subcommand() {
        ("decrypt",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut input = openpgp::Reader::from_reader(input)?;
            let signatures: usize =
                m.value_of("signatures").unwrap_or("0").parse()?;
            let tpks = m.values_of("public-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let secrets = m.values_of("secret-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let mut store = Store::open(&ctx, store_name)
                .context("Failed to open the store")?;
            commands::decrypt(&ctx, &mut store,
                              &mut input, &mut output,
                              signatures, tpks, secrets,
                              m.is_present("dump"), m.is_present("hex"))?;
        },
        ("encrypt",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut output = if ! m.is_present("binary") {
                Box::new(armor::Writer::new(&mut output,
                                            armor::Kind::Message,
                                            &[])?)
            } else {
                output
            };
            let mut store = Store::open(&ctx, store_name)
                .context("Failed to open the store")?;
            let recipients = m.values_of("recipient")
                .map(|r| r.collect())
                .unwrap_or(vec![]);
            let additional_tpks = m.values_of("recipient-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let additional_secrets = m.values_of("signer-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            commands::encrypt(&mut store, &mut input, &mut output,
                              m.occurrences_of("symmetric") as usize,
                              recipients, additional_tpks, additional_secrets)?;
        },
        ("sign",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let output = m.value_of("output");
            let detached = m.is_present("detached");
            let binary = m.is_present("binary");
            let append = m.is_present("append");
            let notarize = m.is_present("notarize");
            let secrets = m.values_of("secret-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            commands::sign(&mut input, output, secrets, detached, binary,
                           append, notarize)?;
        },
        ("verify",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut input = openpgp::Reader::from_reader(input)?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let detached = m.is_present("detached");
            if detached {
                unimplemented!("Detached signature generation not implemented");
            }
            let signatures: usize =
                m.value_of("signatures").unwrap_or("0").parse()?;
            let tpks = m.values_of("public-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let mut store = Store::open(&ctx, store_name)
                .context("Failed to open the store")?;
            commands::verify(&ctx, &mut store, &mut input, &mut output,
                             signatures, tpks)?;
        },

        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut filter = armor::Writer::new(&mut output, armor::Kind::File,
                                                &[])?;
            io::copy(&mut input, &mut filter)?;
        },
        ("dearmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"))?;
            let mut filter = armor::Reader::new(&mut input, None);
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
                                &mut output, armor::Kind::PublicKey, &[])?;
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
            commands::dump(&mut input, &mut output,
                           m.is_present("mpis"), m.is_present("hex"))?;
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
                    if id.is_err() {
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
                                                    &[])?)
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
                    list_bindings(&store, domain_name, store_name)?;
                },
                ("add",  Some(m)) => {
                    let fp = Fingerprint::from_hex(m.value_of("fingerprint").unwrap())
                        .expect("Malformed fingerprint");
                    store.add(m.value_of("label").unwrap(), &fp)?;
                },
                ("import",  Some(m)) => {
                    let label = m.value_of("label").unwrap();
                    help_warning(label);
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut input = openpgp::Reader::from_reader(input)?;

                    let tpk = TPK::from_reader(&mut input)?;
                    store.import(label, &tpk)?;
                },
                ("export",  Some(m)) => {
                    let tpk = store.lookup(m.value_of("label").unwrap())?.tpk()?;

                    let mut output = create_or_stdout(m.value_of("output"))?;
                    let mut output = if ! m.is_present("binary") {
                        Box::new(armor::Writer::new(&mut output,
                                                    armor::Kind::PublicKey,
                                                    &[])?)
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
                    commands::store_print_stats(&store,
                                                m.value_of("label").unwrap())?;
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
                            list_bindings(&store, &domain, &name)?;
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
        ("keygen",  Some(m)) => {
            use openpgp::tpk::{TPKBuilder, CipherSuite};
            use openpgp::packet::signature::subpacket::KeyFlags;
            use openpgp::armor::{Writer, Kind};
            use openpgp::serialize::Serialize;
            use std::io;
            use std::fs::File;

            let mut builder = TPKBuilder::default();

            // User ID
            match m.value_of("userid") {
                Some(uid) => { builder = builder.add_userid(uid); }
                None => {
                    eprintln!("No user ID given, using direct key signature");
                }
            }

            // Cipher Suite
            match m.value_of("cipher-suite") {
                None | Some("rsa3k") => {
                    builder = builder.set_cipher_suite(CipherSuite::RSA3k);
                }
                Some("cv25519") => {
                    builder = builder.set_cipher_suite(CipherSuite::Cv25519);
                }
                Some(ref cs) => {
                    eprintln!("Unknown cipher suite '{}'", cs);
                    exit(1);
                }
            }

            // Signing Capability
            match (m.is_present("can-sign"), m.is_present("cannot-sign")) {
                (false, false) | (true, false) => {
                    builder = builder.add_signing_subkey();
                }
                (false, true) => { /* no signing subkey */ }
                (true, true) => {
                    eprintln!("Conflicting arguments --can-sign and --cannot-sign");
                    exit(1);
                }
            }

            // Encryption Capability
            match (m.value_of("can-encrypt"), m.is_present("cannot-encrypt")) {
                (Some("all"), false) | (None, false) => {
                    builder = builder.add_encryption_subkey();
                }
                (Some("rest"), false) => {
                    builder = builder.add_subkey(KeyFlags::default()
                                                 .set_encrypt_at_rest(true));
                }
                (Some("transport"), false) => {
                    builder = builder.add_subkey(KeyFlags::default()
                                                 .set_encrypt_for_transport(true));
                }
                (None, true) => { /* no encryption subkey */ }
                (Some(_), true) => {
                    eprintln!("Conflicting arguments --can-encrypt and --cannot-encrypt");
                    exit(1);
                }
                (Some(ref cap), false) => {
                    eprintln!("Unknown encryption capability '{}'", cap);
                    exit(1);
                }
            }

            // Generate the key
            let (tpk, rev) = builder.generate()?;
            let tsk = tpk.into_tsk();

            // Export
            if m.is_present("export") {
                let (key_path, rev_path) =
                    match (m.value_of("export"), m.value_of("rev-cert")) {
                        (Some("-"), Some("-")) =>
                            ("-".to_string(), "-".to_string()),
                        (Some("-"), Some(ref rp)) =>
                            ("-".to_string(), rp.to_string()),
                        (Some("-"), None) => {
                            eprintln!("Missing arguments: --rev-cert is mandatory if --export is '-'.");
                            exit(1);
                        }
                        (Some(ref kp), None) =>
                            (kp.to_string(), format!("{}.rev", kp)),
                        (Some(ref kp), Some("-")) =>
                            (kp.to_string(), "-".to_string()),
                        (Some(ref kp), Some(ref rp)) =>
                            (kp.to_string(), rp.to_string()),
                        _ => {
                            eprintln!("Conflicting arguments --rev-cert and --export");
                            exit(1);
                        }
                    };
                let mut stdout = io::stdout();

                // write out key
                if key_path == "-" {
                    let mut w = Writer::new(&mut stdout, Kind::SecretKey, &[])?;
                    tsk.serialize(&mut w)?;
                } else {
                    let mut fd = File::create(key_path)?;
                    let mut w = Writer::new(&mut fd, Kind::SecretKey, &[])?;
                    tsk.serialize(&mut w)?;
                }

                // write out rev cert
                if rev_path == "-" {
                    let mut w = Writer::new(&mut stdout, Kind::Signature, &[])?;
                    rev.serialize(&mut w)?;
                } else {
                    let mut fd = File::create(rev_path)?;
                    let mut w = Writer::new(&mut fd, Kind::Signature, &[])?;
                    rev.serialize(&mut w)?;
                }
            } else {
                eprintln!("Saving generated key to the store isn't implemented yet.");
                exit(1);
            }
        }
        _ => {
            eprintln!("No subcommand given.");
            exit(1);
        },
    }

    return Ok(())
}

fn list_bindings(store: &Store, domain: &str, name: &str) -> Result<(), failure::Error> {
    if store.iter()?.count() == 0 {
        println!("No label-key bindings in the \"{}/{}\" store.", domain, name);
        return Ok(());
    }

    println!("Domain: {:?}, store: {:?}:", domain, name);

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
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}
