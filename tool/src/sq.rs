/// A command-line frontend for Sequoia.

extern crate clap;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate prettytable;
extern crate rpassword;
extern crate tempfile;
extern crate termsize;
extern crate time;
extern crate itertools;
extern crate tokio_core;

use failure::ResultExt;
use prettytable::{Table, Cell, Row};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;

extern crate sequoia_openpgp as openpgp;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use crate::openpgp::{armor, autocrypt, Fingerprint, TPK};
use crate::openpgp::conversions::hex;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::Serialize;
use sequoia_core::{Context, NetworkPolicy};
use sequoia_net::{KeyServer, wkd};
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

fn create_or_stdout(f: Option<&str>, force: bool)
    -> Result<Box<io::Write>, failure::Error> {
    match f {
        None => Ok(Box::new(io::stdout())),
        Some(p) if p == "-" => Ok(Box::new(io::stdout())),
        Some(f) => {
            let p = Path::new(f);
            if !p.exists() || force {
                Ok(Box::new(OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .open(f)
                            .context("Failed to create output file")?))
            } else {
                Err(failure::err_msg(
                    format!("File {:?} exists, use --force to overwrite", p)))
            }
        }
    }
}

fn load_tpks<'a, I>(files: I) -> openpgp::Result<Vec<TPK>>
    where I: Iterator<Item=&'a str>
{
    let mut tpks = vec![];
    for f in files {
        tpks.push(TPK::from_file(f)
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
    let force = matches.is_present("force");
    let (realm_name, store_name) = {
        let s = matches.value_of("store").expect("has a default value");
        if let Some(i) = s.find('/') {
            (&s[..i], &s[i+1..])
        } else {
            (s, "default")
        }
    };
    let mut builder = Context::configure()
        .network_policy(policy);
    if let Some(dir) = matches.value_of("home") {
        builder = builder.home(dir);
    }
    let ctx = builder.build()?;
    let mut core = tokio_core::reactor::Core::new()?;

    match matches.subcommand() {
        ("decrypt",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let signatures: usize =
                m.value_of("signatures").unwrap_or("0").parse()?;
            let tpks = m.values_of("public-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let secrets = m.values_of("secret-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let mut store = Store::open(&ctx, realm_name, store_name)
                .context("Failed to open the store")?;
            commands::decrypt(&ctx, &mut store,
                              &mut input, &mut output,
                              signatures, tpks, secrets,
                              m.is_present("dump-session-key"),
                              m.is_present("dump"), m.is_present("hex"))?;
        },
        ("encrypt",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let mut output = if ! m.is_present("binary") {
                Box::new(armor::Writer::new(&mut output,
                                            armor::Kind::Message,
                                            &[])?)
            } else {
                output
            };
            let mut store = Store::open(&ctx, realm_name, store_name)
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
                           append, notarize, force)?;
        },
        ("verify",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let mut detached = if let Some(f) = m.value_of("detached") {
                Some(File::open(f)?)
            } else {
                None
            };
            let signatures: usize =
                m.value_of("signatures").unwrap_or("0").parse()?;
            let tpks = m.values_of("public-key-file")
                .map(load_tpks)
                .unwrap_or(Ok(vec![]))?;
            let mut store = Store::open(&ctx, realm_name, store_name)
                .context("Failed to open the store")?;
            commands::verify(&ctx, &mut store, &mut input,
                             detached.as_mut().map(|r| r as &mut io::Read),
                             &mut output, signatures, tpks)?;
        },

        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let kind = match m.value_of("kind").expect("has default value") {
                "message" => armor::Kind::Message,
                "publickey" => armor::Kind::PublicKey,
                "secretkey" => armor::Kind::SecretKey,
                "signature" => armor::Kind::Signature,
                "file" => armor::Kind::File,
                _ => unreachable!(),
            };
            let mut filter = armor::Writer::new(&mut output, kind, &[])?;
            io::copy(&mut input, &mut filter)?;
        },
        ("dearmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let mut filter = armor::Reader::new(&mut input, None);
            io::copy(&mut filter, &mut output)?;
        },
        ("autocrypt", Some(m)) => {
            match m.subcommand() {
                ("decode",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
                    for h in &ac.headers {
                        if let Some(ref tpk) = h.key {
                            let mut filter = armor::Writer::new(
                                &mut output, armor::Kind::PublicKey, &[])?;
                            tpk.serialize(&mut filter)?;
                        }
                    }
                },
                ("encode-sender",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut output = create_or_stdout(m.value_of("output"),
                                                      force)?;
                    let tpk = TPK::from_reader(input)?;
                    let addr = m.value_of("address").map(|a| a.to_string())
                        .or_else(|| {
                            if let Some(Ok(Some(a))) =
                                tpk.userids().nth(0).map(|u| u.userid().address())
                            {
                                Some(a)
                            } else {
                                None
                            }
                        });
                    let ac = autocrypt::AutocryptHeader::new_sender(
                        &tpk,
                        &addr.ok_or(failure::err_msg(
                            "No well-formed primary userid found, use \
                             --address to specify one"))?,
                        m.value_of("prefer-encrypt").expect("has default"))?;
                    write!(&mut output, "Autocrypt: ")?;
                    ac.serialize(&mut output)?;
                },
                _ => unreachable!(),
            }
        },

        ("inspect",  Some(m)) => {
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            commands::inspect(m, &mut output)?;
        },

        ("packet", Some(m)) => match m.subcommand() {
            ("dump",  Some(m)) => {
                let mut input = open_or_stdin(m.value_of("input"))?;
                let mut output = create_or_stdout(m.value_of("output"), force)?;
                let session_key: Option<openpgp::crypto::SessionKey> =
                    if let Some(sk) = m.value_of("session-key") {
                        Some(hex::decode_pretty(sk)?.into())
                    } else {
                        None
                    };
                let width = termsize::get().map(|s| s.cols as usize);
                commands::dump(&mut input, &mut output,
                               m.is_present("mpis"), m.is_present("hex"),
                               session_key.as_ref(), width)?;
            },
            ("split",  Some(m)) => {
                let mut input = open_or_stdin(m.value_of("input"))?;
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
                commands::split(&mut input, &prefix)?;
            },
            _ => unreachable!(),
        },

        ("keyserver",  Some(m)) => {
            let mut ks = if let Some(uri) = m.value_of("server") {
                KeyServer::new(&ctx, &uri)
            } else {
                KeyServer::keys_openpgp_org(&ctx)
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

                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    let mut output = if ! m.is_present("binary") {
                        Box::new(armor::Writer::new(&mut output,
                                                    armor::Kind::PublicKey,
                                                    &[])?)
                    } else {
                        output
                    };

                    core.run(ks.get(&id))
                        .context("Failed to retrieve key")?
                    .serialize(&mut output)
                        .context("Failed to serialize key")?;
                },
                ("send",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let tpk = TPK::from_reader(&mut input).
                        context("Malformed key")?;

                    core.run(ks.send(&tpk))
                        .context("Failed to send key to server")?;
                },
                _ => unreachable!(),
            }
        },
        ("store",  Some(m)) => {
            let store = Store::open(&ctx, realm_name, store_name)
                .context("Failed to open the store")?;

            match m.subcommand() {
                ("list",  Some(_)) => {
                    list_bindings(&store, realm_name, store_name)?;
                },
                ("add",  Some(m)) => {
                    let fp = Fingerprint::from_hex(m.value_of("fingerprint").unwrap())
                        .expect("Malformed fingerprint");
                    store.add(m.value_of("label").unwrap(), &fp)?;
                },
                ("import",  Some(m)) => {
                    let label = m.value_of("label").unwrap();
                    help_warning(label);
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let tpk = TPK::from_reader(&mut input)?;
                    store.import(label, &tpk)?;
                },
                ("export",  Some(m)) => {
                    let tpk = store.lookup(m.value_of("label").unwrap())?.tpk()?;
                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    if m.is_present("binary") {
                        tpk.serialize(&mut output)?;
                    } else {
                        tpk.armored().serialize(&mut output)?;
                    }
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
                _ => unreachable!(),
            }
        },
        ("list",  Some(m)) => {
            match m.subcommand() {
                ("stores",  Some(m)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["realm", "name", "network policy"]);

                    for (realm, name, network_policy, _)
                        in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            table.add_row(Row::new(vec![
                                Cell::new(&realm),
                                Cell::new(&name),
                                Cell::new(&format!("{:?}", network_policy))
                            ]));
                        }

                    table.printstd();
                },
                ("bindings",  Some(m)) => {
                    for (realm, name, _, store)
                        in Store::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            list_bindings(&store, &realm, &name)?;
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
                _ => unreachable!(),
            }
        },
        ("key", Some(m)) => match m.subcommand() {
            ("generate", Some(m)) => commands::key::generate(m, force)?,
            _ => unreachable!(),
        },
        ("wkd",  Some(m)) => {
            match m.subcommand() {
                ("url",  Some(m)) => {
                    let email_address = m.value_of("input").unwrap();
                    let wkd_url = wkd::Url::from(email_address)?;
                    // XXX: Add other subcomand to specify whether it should be
                    // created with the advanced or the direct method.
                    let url = wkd_url.to_url(None)?;
                    println!("{}", url);
                },
                ("get",  Some(m)) => {
                    let email_address = m.value_of("input").unwrap();
                    // XXX: EmailAddress could be created here to
                    // check it's a valid email address, print the error to
                    // stderr and exit.
                    // Because it might be created a WkdServer struct, not
                    // doing it for now.
                    let tpks = core.run(wkd::get(&email_address))?;
                    // ```text
                    //     The HTTP GET method MUST return the binary representation of the
                    //     OpenPGP key for the given mail address.
                    // [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service-07
                    // ```
                    // But to keep the parallelism with `store export` and `keyserver get`,
                    // The output is armored if not `--binary` option is given.
                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    let mut output = if ! m.is_present("binary") {
                        Box::new(armor::Writer::new(&mut output,
                                                    armor::Kind::PublicKey,
                                                    &[])?)
                    } else {
                        output
                    };

                    for tpk in tpks {
                        tpk.serialize(&mut output)?;
                    }
                },
                _ => unreachable!(),
            }
        },
        _ => unreachable!(),
    }

    return Ok(())
}

fn list_bindings(store: &Store, realm: &str, name: &str) -> Result<(), failure::Error> {
    if store.iter()?.count() == 0 {
        println!("No label-key bindings in the \"{}/{}\" store.", realm, name);
        return Ok(());
    }

    println!("Realm: {:?}, store: {:?}:", realm, name);

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
