/// A command-line frontend for Sequoia.

use anyhow::Context as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use chrono::{DateTime, offset::Utc};

use buffered_reader::File;
use sequoia_openpgp as openpgp;
use sequoia_net;

use openpgp::{
    Result,
    Fingerprint,
    KeyID,
    KeyHandle,
    packet::UserID,
};
use crate::openpgp::{armor, Cert};
use sequoia_autocrypt as autocrypt;
use crate::openpgp::crypto::Password;
use crate::openpgp::fmt::hex;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::packet::prelude::*;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::{Serialize, stream::{Message, Armorer}};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::StandardPolicy as P;
use sequoia_net as net;
use sequoia_net::{KeyServer, wkd};

mod sq_cli;
mod commands;

fn open_or_stdin(f: Option<&str>) -> Result<Box<dyn io::Read + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(File::open(f)
                               .context("Failed to open input file")?)),
        None => Ok(Box::new(io::stdin())),
    }
}

fn create_or_stdout(f: Option<&str>, force: bool)
    -> Result<Box<dyn io::Write + Sync + Send>> {
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
                Err(anyhow::anyhow!(
                    format!("File {:?} exists, use --force to overwrite", p)))
            }
        }
    }
}

fn create_or_stdout_pgp<'a>(f: Option<&str>, force: bool,
                            binary: bool, kind: armor::Kind)
                            -> Result<Message<'a>>
{
    let sink = create_or_stdout(f, force)?;
    let mut message = Message::new(sink);
    if ! binary {
        message = Armorer::new(message).kind(kind).build()?;
    }
    Ok(message)
}

/// Loads one TSK from every given file.
fn load_keys<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a str>
{
    let mut certs = vec![];
    for f in files {
        let cert = Cert::from_file(f)
            .context(format!("Failed to load key from file {:?}", f))?;
        if ! cert.is_tsk() {
            Err(anyhow::anyhow!(
                "Cert in file {:?} does not contain secret keys", f))?;
        }
        certs.push(cert);
    }
    Ok(certs)
}

/// Loads one or more certs from every given file.
fn load_certs<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a str>
{
    let mut certs = vec![];
    for f in files {
        for maybe_cert in CertParser::from_file(f)
            .context(format!("Failed to load certs from file {:?}", f))?
        {
            certs.push(maybe_cert.context(
                format!("A cert from file {:?} is bad", f)
            )?);
        }
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
    let mut output = armor::Writer::with_headers(&mut output,
                                                 armor::Kind::PublicKey,
                                                 headers)?;
    for cert in certs {
        cert.serialize(&mut output)?;
    }
    output.finalize()?;
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

// Decrypts a key, if possible.
//
// The passwords in `passwords` are tried first.  If the key can't be
// decrypted using those, the user is prompted.  If a valid password
// is entered, it is added to `passwords`.
fn decrypt_key<R>(key: Key<key::SecretParts, R>, passwords: &mut Vec<String>)
    -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone
{
    let key = key.parts_as_secret()?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => {
            Ok(key.clone())
        }
        SecretKeyMaterial::Encrypted(_) => {
            for p in passwords.iter() {
                if let Ok(key)
                    = key.clone().decrypt_secret(&Password::from(&p[..]))
                {
                    return Ok(key);
                }
            }

            let mut first = true;
            loop {
                // Prompt the user.
                match rpassword::read_password_from_tty(
                    Some(&format!(
                        "{}Enter password to unlock {} (blank to skip): ",
                        if first { "" } else { "Invalid password. " },
                        key.keyid().to_hex())))
                {
                    Ok(p) => {
                        first = false;
                        if p == "" {
                            // Give up.
                            break;
                        }

                        if let Ok(key) = key
                            .clone()
                            .decrypt_secret(&Password::from(&p[..]))
                        {
                            passwords.push(p);
                            return Ok(key);
                        }
                    }
                    Err(err) => {
                        eprintln!("While reading password: {}", err);
                        break;
                    }
                }
            }

            Err(anyhow::anyhow!("Key {}: Unable to decrypt secret key material",
                                key.keyid().to_hex()))
        }
    }
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
#[allow(dead_code)]
fn help_warning(arg: &str) {
    if arg == "help" {
        eprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

#[allow(dead_code)]
pub struct Config {
    force: bool,
    network_policy: net::Policy,
}

fn main() -> Result<()> {
    let policy = &mut P::new();

    let matches = sq_cli::build().get_matches();

    let known_notations: Vec<&str> = matches.values_of("known-notation")
        .unwrap_or_default()
        .collect();
    policy.good_critical_notations(&known_notations);

    let network_policy = match matches.value_of("policy") {
        None => net::Policy::Encrypted,
        Some("offline") => net::Policy::Offline,
        Some("anonymized") => net::Policy::Anonymized,
        Some("encrypted") => net::Policy::Encrypted,
        Some("insecure") => net::Policy::Insecure,
        Some(_) => {
            eprintln!("Bad network policy, must be offline, anonymized, encrypted, or insecure.");
            exit(1);
        },
    };
    let force = matches.is_present("force");

    let config = Config {
        force,
        network_policy,
    };


    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_io()
        .enable_time()
        .build()?;

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
                .map(load_keys)
                .unwrap_or(Ok(vec![]))?;
            commands::decrypt(config, policy,
                              &mut input, &mut output,
                              signatures, certs, secrets,
                              m.is_present("dump-session-key"),
                              m.is_present("dump"), m.is_present("hex"))?;
        },
        ("encrypt",  Some(m)) => {
            let recipients = m.values_of("recipients-cert-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            let mut input = open_or_stdin(m.value_of("input"))?;
            let output =
                create_or_stdout_pgp(m.value_of("output"), force,
                                     m.is_present("binary"),
                                     armor::Kind::Message)?;
            let additional_secrets = m.values_of("signer-key-file")
                .map(load_keys)
                .unwrap_or(Ok(vec![]))?;
            let mode = match m.value_of("mode").expect("has default") {
                "rest" => KeyFlags::empty()
                    .set_storage_encryption(),
                "transport" => KeyFlags::empty()
                    .set_transport_encryption(),
                "all" => KeyFlags::empty()
                    .set_storage_encryption()
                    .set_transport_encryption(),
                _ => unreachable!("uses possible_values"),
            };
            let time = if let Some(time) = m.value_of("time") {
                Some(parse_iso8601(time, chrono::NaiveTime::from_hms(0, 0, 0))
                         .context(format!("Bad value passed to --time: {:?}",
                                          time))?.into())
            } else {
                None
            };
            commands::encrypt(policy, &mut input, output,
                              m.occurrences_of("symmetric") as usize,
                              &recipients, additional_secrets,
                              mode,
                              m.value_of("compression").expect("has default"),
                              time.into(),
                              m.is_present("use-expired-subkey"),
            )?;
        },
        ("merge-signatures",  Some(m)) => {
            let mut input1 = open_or_stdin(m.value_of("input1"))?;
            let mut input2 = open_or_stdin(m.value_of("input2"))?;
            let output = m.value_of("output");
            commands::merge_signatures(&mut input1, &mut input2, output)?;
        },
        ("sign",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let output = m.value_of("output");
            let detached = m.is_present("detached");
            let binary = m.is_present("binary");
            let append = m.is_present("append");
            let notarize = m.is_present("notarize");
            let secrets = m.values_of("secret-key-file")
                .map(load_keys)
                .unwrap_or(Ok(vec![]))?;
            let time = if let Some(time) = m.value_of("time") {
                Some(parse_iso8601(time, chrono::NaiveTime::from_hms(0, 0, 0))
                         .context(format!("Bad value passed to --time: {:?}",
                                          time))?.into())
            } else {
                None
            };
            commands::sign(policy, &mut input, output, secrets, detached, binary,
                           append, notarize, time, force)?;
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
            commands::verify(config, policy, &mut input,
                             detached.as_mut().map(|r| r as &mut (dyn io::Read + Sync + Send)),
                             &mut output, signatures, certs)?;
        },

        ("enarmor",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output =
                create_or_stdout_pgp(m.value_of("output"), force,
                                     false,
                                     parse_armor_kind(m.value_of("kind")))?;
            io::copy(&mut input, &mut output)?;
            output.finalize()?;
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
                    let mut output =
                        create_or_stdout_pgp(m.value_of("output"), force,
                                             true,
                                             armor::Kind::PublicKey)?;
                    let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
                    for h in &ac.headers {
                        if let Some(ref cert) = h.key {
                            cert.serialize(&mut output)?;
                        }
                    }
                    output.finalize()?;
                },
                ("encode-sender",  Some(m)) => {
                    let input = open_or_stdin(m.value_of("input"))?;
                    let mut output = create_or_stdout(m.value_of("output"),
                                                      force)?;
                    let cert = Cert::from_reader(input)?;
                    let addr = m.value_of("address").map(|a| a.to_string())
                        .or_else(|| {
                            cert.with_policy(policy, None)
                                .and_then(|vcert| vcert.primary_userid()).ok()
                                .map(|ca| ca.userid().to_string())
                        });
                    let ac = autocrypt::AutocryptHeader::new_sender(
                        policy,
                        &cert,
                        &addr.ok_or(anyhow::anyhow!(
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
            commands::inspect(m, policy, &mut output)?;
        },

        ("certring", Some(m)) => commands::certring::dispatch(m, force)?,

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
                let width = term_size::dimensions_stdout().map(|(w, _)| w);
                commands::dump(&mut input, &mut output,
                               m.is_present("mpis"), m.is_present("hex"),
                               session_key.as_ref(), width)?;
            },

            ("decrypt",  Some(m)) => {
                let mut input = open_or_stdin(m.value_of("input"))?;
                let mut output =
                    create_or_stdout_pgp(m.value_of("output"), force,
                                         m.is_present("binary"),
                                         armor::Kind::Message)?;
                let secrets = m.values_of("secret-key-file")
                    .map(load_keys)
                    .unwrap_or(Ok(vec![]))?;
                commands::decrypt::decrypt_unwrap(
                    config, policy,
                    &mut input, &mut output,
                    secrets, m.is_present("dump-session-key"))?;
                output.finalize()?;
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
                let mut output =
                    create_or_stdout_pgp(m.value_of("output"), force,
                                         m.is_present("binary"),
                                         parse_armor_kind(m.value_of("kind")))?;
                commands::join(m.values_of("input"), &mut output)?;
                output.finalize()?;
            },
            _ => unreachable!(),
        },

        ("keyserver",  Some(m)) => {
            let mut ks = if let Some(uri) = m.value_of("server") {
                KeyServer::new(network_policy, &uri)
            } else {
                KeyServer::keys_openpgp_org(network_policy)
            }.context("Malformed keyserver URI")?;

            match m.subcommand() {
                ("get",  Some(m)) => {
                    let query = m.value_of("query").unwrap();

                    let handle: Option<KeyHandle> = {
                        let q_fp = query.parse::<Fingerprint>();
                        let q_id = query.parse::<KeyID>();
                        if let Ok(Fingerprint::V4(_)) = q_fp {
                            q_fp.ok().map(Into::into)
                        } else if let Ok(KeyID::V4(_)) = q_id {
                            q_fp.ok().map(Into::into)
                        } else {
                            None
                        }
                    };

                    if let Some(handle) = handle {
                        let cert = rt.block_on(ks.get(handle))
                            .context("Failed to retrieve cert")?;

                        let mut output =
                            create_or_stdout(m.value_of("output"), force)?;
                        if ! m.is_present("binary") {
                            cert.armored().serialize(&mut output)
                        } else {
                            cert.serialize(&mut output)
                        }.context("Failed to serialize cert")?;
                    } else if let Ok(Some(addr)) = UserID::from(query).email() {
                        let certs = rt.block_on(ks.search(addr))
                            .context("Failed to retrieve certs")?;

                        let mut output =
                            create_or_stdout_pgp(m.value_of("output"), force,
                                                 m.is_present("binary"),
                                                 armor::Kind::PublicKey)?;
                        for cert in certs {
                            cert.serialize(&mut output)
                                .context("Failed to serialize cert")?;
                        }
                        output.finalize()?;
                    } else {
                        Err(anyhow::anyhow!(
                            "Query must be a fingerprint, a keyid, \
                             or an email address: {:?}", query))?;
                    }
                },
                ("send",  Some(m)) => {
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let cert = Cert::from_reader(&mut input).
                        context("Malformed key")?;

                    rt.block_on(ks.send(&cert))
                        .context("Failed to send key to server")?;
                },
                _ => unreachable!(),
            }
        },
        ("key", Some(m)) => match m.subcommand() {
            ("generate", Some(m)) => commands::key::generate(m, force)?,
            ("adopt", Some(m)) => commands::key::adopt(m, policy)?,
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
                    let certs = rt.block_on(wkd::get(&email_address))?;
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

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms(0, 0, 0);
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}
