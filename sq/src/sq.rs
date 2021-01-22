/// A command-line frontend for Sequoia.

use anyhow::Context as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use chrono::{DateTime, offset::Utc};
use itertools::Itertools;

use buffered_reader::{BufferedReader, Dup, File, Generic, Limitor};
use sequoia_openpgp as openpgp;

use openpgp::{
    Result,
};
use crate::openpgp::{armor, Cert};
use sequoia_autocrypt as autocrypt;
use crate::openpgp::crypto::Password;
use crate::openpgp::fmt::hex;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::packet::prelude::*;
use crate::openpgp::parse::{Parse, PacketParser, PacketParserResult};
use crate::openpgp::serialize::{Serialize, stream::{Message, Armorer}};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::StandardPolicy as P;

mod sq_cli;
mod commands;

fn open_or_stdin(f: Option<&str>)
                 -> Result<Box<dyn BufferedReader<()>>> {
    match f {
        Some(f) => Ok(Box::new(File::open(f)
                               .context("Failed to open input file")?)),
        None => Ok(Box::new(Generic::new(io::stdin(), None))),
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

const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;

fn parse_duration(expiry: &str) -> Result<Duration> {
    let mut expiry = expiry.chars().peekable();

    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let digits = expiry.by_ref()
        .peeking_take_while(|c| {
            *c == '+' || *c == '-' || c.is_digit(10)
        }).collect::<String>();
    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let suffix = expiry.next();
    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let junk = expiry.collect::<String>();

    if digits == "" {
        return Err(anyhow::anyhow!(
            "--expiry: missing count \
             (try: '2y' for 2 years)"));
    }

    let count = match digits.parse::<i32>() {
        Ok(count) if count < 0 =>
            return Err(anyhow::anyhow!(
                "--expiry: Expiration can't be in the past")),
        Ok(count) => count as u64,
        Err(err) =>
            return Err(err).context("--expiry: count is out of range"),
    };

    let factor = match suffix {
        Some('y') | Some('Y') => SECONDS_IN_YEAR,
        Some('m') | Some('M') => SECONDS_IN_YEAR / 12,
        Some('w') | Some('W') => 7 * SECONDS_IN_DAY,
        Some('d') | Some('D') => SECONDS_IN_DAY,
        None =>
            return Err(anyhow::anyhow!(
                "--expiry: missing suffix \
                 (try: '{}y', '{}m', '{}w' or '{}d' instead)",
                digits, digits, digits, digits)),
        Some(suffix) =>
            return Err(anyhow::anyhow!(
                "--expiry: invalid suffix '{}' \
                 (try: '{}y', '{}m', '{}w' or '{}d' instead)",
                suffix, digits, digits, digits, digits)),
    };

    if junk != "" {
        return Err(anyhow::anyhow!(
            "--expiry: contains trailing junk ('{:?}') \
             (try: '{}{}')",
            junk, count, factor));
    }

    Ok(Duration::new(count * factor, 0))
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
#[allow(dead_code)]
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

fn parse_armor_kind(kind: Option<&str>) -> Option<armor::Kind> {
    match kind.expect("has default value") {
        "auto" =>    None,
        "message" => Some(armor::Kind::Message),
        "cert" =>    Some(armor::Kind::PublicKey),
        "key" =>     Some(armor::Kind::SecretKey),
        "sig" =>     Some(armor::Kind::Signature),
        "file" =>    Some(armor::Kind::File),
        _ => unreachable!(),
    }
}

/// How much data to look at when detecting armor kinds.
const ARMOR_DETECTION_LIMIT: u64 = 1 << 24;

/// Peeks at the first packet to guess the type.
///
/// Returns the given reader unchanged.  If the detection fails,
/// armor::Kind::File is returned as safe default.
fn detect_armor_kind(input: Box<dyn BufferedReader<()>>)
                     -> (Box<dyn BufferedReader<()>>, armor::Kind) {
    let mut dup = Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT).as_boxed();
    let kind = 'detection: loop {
        if let Ok(ppr) = PacketParser::from_reader(&mut dup) {
            if let PacketParserResult::Some(pp) = ppr {
                let (packet, _) = match pp.next() {
                    Ok(v) => v,
                    Err(_) => break 'detection armor::Kind::File,
                };

                break 'detection match packet {
                    Packet::Signature(_) => armor::Kind::Signature,
                    Packet::SecretKey(_) => armor::Kind::SecretKey,
                    Packet::PublicKey(_) => armor::Kind::PublicKey,
                    Packet::PKESK(_) | Packet::SKESK(_) =>
                        armor::Kind::Message,
                    _ => armor::Kind::File,
                };
            }
        }
        break 'detection armor::Kind::File;
    };
    (dup.into_inner().unwrap().into_inner().unwrap(), kind)
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
}

fn main() -> Result<()> {
    if term_size::dimensions_stdout().is_none() {
        eprintln!("\nWARNING: sq does not have a stable CLI interface.  \
                   Use with caution in scripts.\n");
    }

    let policy = &mut P::new();

    // XXX: Compat with sequoia-openpgp 1.0.0:
    use openpgp::packet::signature::subpacket::SubpacketTag;
    policy.accept_critical_subpacket(SubpacketTag::TrustSignature);
    policy.accept_critical_subpacket(SubpacketTag::RegularExpression);

    let matches = sq_cli::build().get_matches();

    let known_notations: Vec<&str> = matches.values_of("known-notation")
        .unwrap_or_default()
        .collect();
    policy.good_critical_notations(&known_notations);

    let force = matches.is_present("force");

    let config = Config {
        force,
    };

    match matches.subcommand() {
        ("decrypt",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let mut output = create_or_stdout(m.value_of("output"), force)?;
            let signatures: usize =
                m.value_of("signatures").expect("has a default").parse()?;
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
            if let Some(merge) = m.value_of("merge") {
                let output = create_or_stdout_pgp(output, force, binary,
                                                  armor::Kind::Message)?;
                let mut input2 = open_or_stdin(Some(merge))?;
                commands::merge_signatures(&mut input, &mut input2, output)?;
            } else {
                commands::sign(policy, &mut input, output, secrets, detached,
                               binary, append, notarize, time, force)?;
            }
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
                m.value_of("signatures").expect("has a default").parse()?;
            let certs = m.values_of("sender-cert-file")
                .map(load_certs)
                .unwrap_or(Ok(vec![]))?;
            commands::verify(config, policy, &mut input,
                             detached.as_mut().map(|r| r as &mut (dyn io::Read + Sync + Send)),
                             &mut output, signatures, certs)?;
        },

        ("armor",  Some(m)) => {
            let input = open_or_stdin(m.value_of("input"))?;
            let mut want_kind = parse_armor_kind(m.value_of("kind"));

            // Peek at the data.  If it looks like it is armored
            // data, avoid armoring it again.
            let mut dup = Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT);
            let (already_armored, have_kind) = {
                let mut reader =
                    armor::Reader::new(&mut dup,
                                       armor::ReaderMode::Tolerant(None));
                (reader.data(8).is_ok(), reader.kind())
            };
            let mut input =
                dup.as_boxed().into_inner().unwrap().into_inner().unwrap();

            if already_armored
                && (want_kind.is_none() || want_kind == have_kind)
            {
                // It is already armored and has the correct kind.
                let mut output =
                    create_or_stdout(m.value_of("output"), force)?;
                io::copy(&mut input, &mut output)?;
                return Ok(());
            }

            if want_kind.is_none() {
                let (tmp, kind) = detect_armor_kind(input);
                input = tmp;
                want_kind = Some(kind);
            }

            // At this point, want_kind is determined.
            let want_kind = want_kind.expect("given or detected");

            let mut output =
                create_or_stdout_pgp(m.value_of("output"), force,
                                     false, want_kind)?;

            if already_armored {
                // Dearmor and copy to change the type.
                let mut reader =
                    armor::Reader::new(input,
                                       armor::ReaderMode::Tolerant(None));
                io::copy(&mut reader, &mut output)?;
            } else {
                io::copy(&mut input, &mut output)?;
            }
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
                                             m.is_present("binary"),
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
            ("join",  Some(m)) => commands::join(config, m)?,
            _ => unreachable!(),
        },

        #[cfg(feature = "net")]
        ("keyserver",  Some(m)) =>
            commands::net::dispatch_keyserver(config, m)?,

        ("key", Some(m)) => match m.subcommand() {
            ("generate", Some(m)) => commands::key::generate(m, force)?,
            ("adopt", Some(m)) => commands::key::adopt(config, m, policy)?,
            ("attest-certifications", Some(m)) =>
                commands::key::attest_certifications(config, m, policy)?,
            _ => unreachable!(),
        },

        #[cfg(feature = "net")]
        ("wkd",  Some(m)) => commands::net::dispatch_wkd(config, m)?,

        ("certify",  Some(m)) => {
            commands::certify::certify(config, policy, m)?;
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
