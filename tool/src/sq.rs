/// A command-line frontend for Sequoia.

extern crate clap;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate prettytable;
extern crate rpassword;
extern crate tempfile;
extern crate termsize;
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
extern crate sequoia_store as store;

use crate::openpgp::{armor, autocrypt, Fingerprint, Cert};
use crate::openpgp::fmt::hex;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::Serialize;
use crate::openpgp::cert::CertParser;
use sequoia_core::{Context, NetworkPolicy};
use sequoia_net::{KeyServer, wkd};
use store::{Mapping, LogIter};

mod sq_cli;
mod commands;
use commands::dump::Convert;

fn open_or_stdin(f: Option<&str>) -> Result<Box<dyn io::Read>, failure::Error> {
    match f {
        Some(f) => Ok(Box::new(File::open(f)
                               .context("Failed to open input file")?)),
        None => Ok(Box::new(io::stdin())),
    }
}

fn create_or_stdout(f: Option<&str>, force: bool)
    -> Result<Box<dyn io::Write>, failure::Error> {
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

fn load_certs<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a str>
{
    let mut certs = vec![];
    for f in files {
        certs.push(Cert::from_file(f)
                  .context(format!("Failed to load key from file {:?}", f))?);
    }
    Ok(certs)
}

/// Serializes a keyring, adding descriptive headers if armored.
fn serialize_keyring(mut output: &mut dyn io::Write, certs: &[Cert], binary: bool)
                     -> openpgp::Result<()> {
    // Handle the easy options first.  No armor no cry:
    if binary {
        for cert in certs {
            cert.serialize(&mut output)?;
        }
        return Ok(());
    }

    // Just one Cert?  Ez:
    if certs.len() == 1 {
        return certs[0].armored().serialize(&mut output);
    }

    // Otherwise, collect the headers first:
    let mut headers = Vec::new();
    for (i, cert) in certs.iter().enumerate() {
        headers.push(format!("Key #{}", i));
        headers.append(&mut cert.armor_headers());
    }

    let headers: Vec<_> = headers.iter()
        .map(|value| ("Comment", value.as_str()))
        .collect();
    let mut output = armor::Writer::new(&mut output,
                                        armor::Kind::PublicKey,
                                        &headers)?;
    for cert in certs {
        cert.serialize(&mut output)?;
    }
    Ok(())
}

fn parse_armor_kind(kind: Option<&str>) -> armor::Kind {
    match kind.expect("has default value") {
        "message" => armor::Kind::Message,
        "publickey" => armor::Kind::PublicKey,
        "secretkey" => armor::Kind::SecretKey,
        "signature" => armor::Kind::Signature,
        "file" => armor::Kind::File,
        _ => unreachable!(),
    }
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
    let (realm_name, mapping_name) = {
        let s = matches.value_of("mapping").expect("has a default value");
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
            let certs = m.values_of("sender-cert-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let secrets = m.values_of("secret-key-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let mut mapping = Mapping::open(&ctx, realm_name, mapping_name)
                .context("Failed to open the mapping")?;
            commands::decrypt(&ctx, &mut mapping,
                              &mut input, &mut output,
                              signatures, certs, secrets,
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
            let mut mapping = Mapping::open(&ctx, realm_name, mapping_name)
                .context("Failed to open the mapping")?;
            let recipients = m.values_of("recipient")
                .map(|r| r.collect())
                .unwrap_or(vec![]);
            let additional_certs = m.values_of("recipient-key-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let additional_secrets = m.values_of("signer-key-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let mode = match m.value_of("mode").expect("has default") {
                "rest" => KeyFlags::default()
                    .set_storage_encryption(true),
                "transport" => KeyFlags::default()
                    .set_transport_encryption(true),
                "all" => KeyFlags::default()
                    .set_storage_encryption(true)
                    .set_transport_encryption(true),
                _ => unreachable!("uses possible_values"),
            };
            commands::encrypt(&mut mapping, &mut input, &mut output,
                              m.occurrences_of("symmetric") as usize,
                              recipients, additional_certs, additional_secrets,
                              mode,
                              m.value_of("compression").expect("has default"))?;
        },
        ("sign",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let output = m.value_of("output");
            let detached = m.is_present("detached");
            let binary = m.is_present("binary");
            let append = m.is_present("append");
            let notarize = m.is_present("notarize");
            let secrets = m.values_of("secret-key-file")
                .map(load_certs)
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
            let certs = m.values_of("sender-cert-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let mut mapping = Mapping::open(&ctx, realm_name, mapping_name)
                .context("Failed to open the mapping")?;
            commands::verify(&ctx, &mut mapping, &mut input,
                             detached.as_mut().map(|r| r as &mut dyn io::Read),
                             &mut output, signatures, certs)?;
        },

        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let kind = parse_armor_kind(m.value_of("kind"));
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
                        if let Some(ref cert) = h.key {
                            let mut filter = armor::Writer::new(
                                &mut output, armor::Kind::PublicKey, &[])?;
                            cert.serialize(&mut filter)?;
                        }
                    }
                },
                ("encode-sender",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut output = create_or_stdout(m.value_of("output"),
                                                      force)?;
                    let cert = Cert::from_reader(input)?;
                    let addr = m.value_of("address").map(|a| a.to_string())
                        .or_else(|| {
                            if let Some(Ok(Some(a))) =
                                cert.userids().nth(0).map(|u| u.userid().email())
                            {
                                Some(a)
                            } else {
                                None
                            }
                        });
                    let ac = autocrypt::AutocryptHeader::new_sender(
                        &cert,
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
            ("join",  Some(m)) => {
                let output = create_or_stdout(m.value_of("output"), force)?;
                let mut output = if ! m.is_present("binary") {
                    let kind = parse_armor_kind(m.value_of("kind"));
                    Box::new(armor::Writer::new(output, kind, &[])?)
                } else {
                    output
                };
                commands::join(m.values_of("input"), &mut output)?;
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
                    let cert = core.run(ks.get(&id))
                        .context("Failed to retrieve key")?;
                    if ! m.is_present("binary") {
                        cert.armored().serialize(&mut output)
                    } else {
                        cert.serialize(&mut output)
                    }.context("Failed to serialize key")?;
                },
                ("send",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let cert = Cert::from_reader(&mut input).
                        context("Malformed key")?;

                    core.run(ks.send(&cert))
                        .context("Failed to send key to server")?;
                },
                _ => unreachable!(),
            }
        },
        ("mapping",  Some(m)) => {
            let mapping = Mapping::open(&ctx, realm_name, mapping_name)
                .context("Failed to open the mapping")?;

            match m.subcommand() {
                ("list",  Some(_)) => {
                    list_bindings(&mapping, realm_name, mapping_name)?;
                },
                ("add",  Some(m)) => {
                    let fp = Fingerprint::from_hex(m.value_of("fingerprint").unwrap())
                        .expect("Malformed fingerprint");
                    mapping.add(m.value_of("label").unwrap(), &fp)?;
                },
                ("import",  Some(m)) => {
                    let label = m.value_of("label").unwrap();
                    help_warning(label);
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let cert = Cert::from_reader(&mut input)?;
                    mapping.import(label, &cert)?;
                },
                ("export",  Some(m)) => {
                    let cert = mapping.lookup(m.value_of("label").unwrap())?.cert()?;
                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    if m.is_present("binary") {
                        cert.serialize(&mut output)?;
                    } else {
                        cert.armored().serialize(&mut output)?;
                    }
                },
                ("delete",  Some(m)) => {
                    if m.is_present("label") == m.is_present("the-mapping") {
                        eprintln!("Please specify either a label or --the-mapping.");
                        exit(1);
                    }

                    if m.is_present("the-mapping") {
                        mapping.delete().context("Failed to delete the mapping")?;
                    } else {
                        let binding = mapping.lookup(m.value_of("label").unwrap())
                            .context("Failed to get key")?;
                        binding.delete().context("Failed to delete the binding")?;
                    }
                },
                ("stats",  Some(m)) => {
                    commands::mapping_print_stats(&mapping,
                                                m.value_of("label").unwrap())?;
                },
                ("log",  Some(m)) => {
                    if m.is_present("label") {
                        let binding = mapping.lookup(m.value_of("label").unwrap())
                            .context("No such key")?;
                        print_log(binding.log().context("Failed to get log")?, false);
                    } else {
                        print_log(mapping.log().context("Failed to get log")?, true);
                    }
                },
                _ => unreachable!(),
            }
        },
        ("list",  Some(m)) => {
            match m.subcommand() {
                ("mappings",  Some(m)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["realm", "name", "network policy"]);

                    for (realm, name, network_policy, _)
                        in Mapping::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            table.add_row(Row::new(vec![
                                Cell::new(&realm),
                                Cell::new(&name),
                                Cell::new(&format!("{:?}", network_policy))
                            ]));
                        }

                    table.printstd();
                },
                ("bindings",  Some(m)) => {
                    for (realm, name, _, mapping)
                        in Mapping::list(&ctx, m.value_of("prefix").unwrap_or(""))? {
                            list_bindings(&mapping, &realm, &name)?;
                        }
                },
                ("keys",  Some(_)) => {
                    let mut table = Table::new();
                    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                    table.set_titles(row!["fingerprint", "updated", "status"]);

                    for (fingerprint, key) in store::Store::list_keys(&ctx)? {
                            let stats = key.stats()
                                .context("Failed to get key stats")?;
                            table.add_row(Row::new(vec![
                                Cell::new(&fingerprint.to_string()),
                                if let Some(t) = stats.updated {
                                    Cell::new(&t.convert().to_string())
                                } else {
                                    Cell::new("")
                                },
                                Cell::new("")
                            ]));
                        }

                    table.printstd();
                },
                ("log",  Some(_)) => {
                    print_log(store::Store::server_log(&ctx)?, true);
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
                    let certs = core.run(wkd::get(&email_address))?;
                    // ```text
                    //     The HTTP GET method MUST return the binary representation of the
                    //     OpenPGP key for the given mail address.
                    // [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service-07
                    // ```
                    // But to keep the parallelism with `store export` and `keyserver get`,
                    // The output is armored if not `--binary` option is given.
                    let mut output = create_or_stdout(m.value_of("output"), force)?;
                    serialize_keyring(&mut output, &certs,
                                      m.is_present("binary"))?;
                },
                ("generate", Some(m)) => {
                    let domain = m.value_of("domain").unwrap();
                    let f = open_or_stdin(m.value_of("input"))?;
                    let base_path =
                        m.value_of("base_directory").expect("required");
                    let variant = if m.is_present("direct_method") {
                        wkd::Variant::Direct
                    } else {
                        wkd::Variant::Advanced
                    };
                    let parser = CertParser::from_reader(f)?;
                    let certs: Vec<Cert> = parser.filter_map(|cert| cert.ok())
                        .collect();
                    for cert in certs {
                        wkd::insert(&base_path, domain, variant, &cert)
                            .context(format!("Failed to generate the WKD in \
                                              {}.", base_path))?;
                    }
                },
                _ => unreachable!(),
            }
        },
        _ => unreachable!(),
    }

    return Ok(())
}

fn list_bindings(mapping: &Mapping, realm: &str, name: &str)
                 -> Result<(), failure::Error> {
    if mapping.iter()?.count() == 0 {
        println!("No label-key bindings in the \"{}/{}\" mapping.",
                 realm, name);
        return Ok(());
    }

    println!("Realm: {:?}, mapping: {:?}:", realm, name);

    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["label", "fingerprint"]);
    for (label, fingerprint, _) in mapping.iter()? {
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
        let mut row = row![&entry.timestamp.convert().to_string(),
                           &entry.short()];
        if with_slug {
            row.insert_cell(1, Cell::new(&entry.slug));
        }
        table.add_row(row);
    }

    table.printstd();
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
