use std::{
    collections::HashMap,
    collections::hash_map::Entry,
    fs::File,
    io,
    path::PathBuf,
};
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    packet::{
        UserID,
        UserAttribute,
        Key,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
    open_or_stdin,
};

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("filter",  Some(m)) => {
            let any_uid_predicates =
                m.is_present("name")
                || m.is_present("email")
                || m.is_present("domain");
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                if let Some(names) = m.values_of("name") {
                    for name in names {
                        keep |= uid
                            .name().unwrap_or(None)
                            .map(|n| n == name)
                            .unwrap_or(false);
                    }
                }

                if let Some(emails) = m.values_of("email") {
                    for email in emails {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| n == email)
                            .unwrap_or(false);
                    }
                }

                if let Some(domains) = m.values_of("domain") {
                    for domain in domains {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| n.ends_with(&format!("@{}", domain)))
                            .unwrap_or(false);
                    }
                }

                keep
            };

            let any_ua_predicates = false;
            let ua_predicate = |_ua: &UserAttribute| false;

            let any_key_predicates = false;
            let key_predicate = |_key: &Key<_, _>| false;

            let filter_fn = |c: Cert| -> Option<Cert> {
                if ! (c.userids().any(|c| uid_predicate(&c))
                      || c.user_attributes().any(|c| ua_predicate(&c))
                      || c.keys().subkeys().any(|c| key_predicate(&c))) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if m.is_present("prune-certs") {
                    let c = c
                        .retain_userids(|c| {
                            ! any_uid_predicates || uid_predicate(&c)
                        })
                        .retain_user_attributes(|c| {
                            ! any_ua_predicates || ua_predicate(&c)
                        })
                        .retain_subkeys(|c| {
                            ! any_key_predicates || key_predicate(&c)
                        });
                    if c.userids().count() == 0
                        && c.user_attributes().count() == 0
                        && c.keys().subkeys().count() == 0
                    {
                        // We stripped all components, omit this cert.
                        None
                    } else {
                        Some(c)
                    }
                } else {
                    Some(c)
                }
            };

            let to_certificate = m.is_present("to-certificate");

            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            filter(m.values_of("input"), &mut output, filter_fn,
                   to_certificate)?;
            output.finalize()
        },
        ("join",  Some(m)) => {
            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            filter(m.values_of("input"), &mut output, |c| Some(c), false)?;
            output.finalize()
        },
        ("merge",  Some(m)) => {
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            merge(m.values_of("input"), &mut output)?;
            output.finalize()
        },
        ("list",  Some(m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            list(&mut input)
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
            split(&mut input, &prefix, m.is_present("binary"))
        },

        _ => unreachable!(),
    }
}

/// Joins certificates and keyrings into a keyring, applying a filter.
fn filter<F>(inputs: Option<clap::Values>, output: &mut dyn io::Write,
             mut filter: F, to_certificate: bool)
             -> Result<()>
    where F: FnMut(Cert) -> Option<Cert>,
{
    if let Some(inputs) = inputs {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                if let Some(cert) = filter(cert) {
                    if to_certificate {
                        cert.serialize(output)?;
                    } else {
                        cert.as_tsk().serialize(output)?;
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            if let Some(cert) = filter(cert) {
                if to_certificate {
                    cert.serialize(output)?;
                } else {
                    cert.as_tsk().serialize(output)?;
                }
            }
        }
    }
    Ok(())
}

/// Lists certs in a keyring.
fn list(input: &mut (dyn io::Read + Sync + Send))
        -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in keyring")?;
        print!("{}. {:X}", i, cert.fingerprint());
        // Try to be more helpful by including the first userid in the
        // listing.
        if let Some(email) = cert.userids().nth(0)
            .and_then(|uid| uid.email().unwrap_or(None))
        {
            print!(" {}", email);
        }
        println!();
    }
    Ok(())
}

/// Splits a keyring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str, binary: bool)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in keyring")?;
        let filename = format!(
            "{}{}-{:X}",
            prefix,
            i,
            cert.fingerprint());

        // Try to be more helpful by including the first userid in the
        // filename.
        let mut sink = if let Some(f) = cert.userids().nth(0)
            .and_then(|uid| uid.email().unwrap_or(None))
            .and_then(to_filename_fragment)
        {
            let filename_email = format!("{}-{}", filename, f);
            if let Ok(s) = File::create(filename_email) {
                s
            } else {
                // Degrade gracefully in case our sanitization
                // produced an invalid filename on this system.
                File::create(&filename)
                    .context(format!("Writing cert to {:?} failed", filename))?
            }
        } else {
            File::create(&filename)
                .context(format!("Writing cert to {:?} failed", filename))?
        };

        if binary {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            use sequoia_openpgp::serialize::stream::{Message, Armorer};
            let message = Message::new(sink);
            let mut message = Armorer::new(message)
            // XXX: should detect kind, see above
                .kind(sequoia_openpgp::armor::Kind::PublicKey)
                .build()?;
            cert.as_tsk().serialize(&mut message)?;
            message.finalize()?;
        }
    }
    Ok(())
}

/// Merge multiple keyrings.
fn merge(inputs: Option<clap::Values>, output: &mut dyn io::Write)
             -> Result<()>
{
    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();

    if let Some(inputs) = inputs {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                match certs.entry(cert.fingerprint()) {
                    e @ Entry::Vacant(_) => {
                        e.or_insert(Some(cert));
                    }
                    Entry::Occupied(mut e) => {
                        let e = e.get_mut();
                        let curr = e.take().unwrap();
                        *e = Some(curr.merge_public_and_secret(cert)
                            .expect("Same certificate"));
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            match certs.entry(cert.fingerprint()) {
                e @ Entry::Vacant(_) => {
                    e.or_insert(Some(cert));
                }
                Entry::Occupied(mut e) => {
                    let e = e.get_mut();
                    let curr = e.take().unwrap();
                    *e = Some(curr.merge_public_and_secret(cert)
                              .expect("Same certificate"));
                }
            }
        }
    }

    for (_, cert) in certs.iter_mut() {
        cert.take().unwrap().as_tsk().serialize(output)?;
    }

    Ok(())
}

/// Sanitizes a string to a safe filename fragment.
fn to_filename_fragment<S: AsRef<str>>(s: S) -> Option<String> {
    let mut r = String::with_capacity(s.as_ref().len());

    s.as_ref().chars().filter_map(|c| match c {
        '/' | ':' | '\\' => None,
        c if c.is_ascii_whitespace() => None,
        c if c.is_ascii() => Some(c),
        _ => None,
    }).for_each(|c| r.push(c));

    if r.len() > 0 {
        Some(r)
    } else {
        None
    }
}
