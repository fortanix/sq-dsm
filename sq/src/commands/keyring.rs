use std::{
    collections::HashMap,
    collections::hash_map::Entry,
    fs::File,
    io,
    path::PathBuf,
};
use anyhow::Context;

use sequoia_openpgp as openpgp;

use openpgp_dsm as dsm;
use clap::ArgMatches;

use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    Packet,
    packet::{
        UserID,
        UserAttribute,
        Key,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    commands::key::_unlock,
    Config,
    open_or_stdin,
};

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("filter",  Some(m)) => {
            let any_uid_predicates =
                m.is_present("userid")
                || m.is_present("name")
                || m.is_present("email")
                || m.is_present("domain");
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                if let Some(userids) = m.values_of("userid") {
                    for userid in userids {
                        keep |= uid.value() == userid.as_bytes();
                    }
                }

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
                if ! (any_uid_predicates
                      || any_ua_predicates
                      || any_key_predicates) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if ! (c.userids().any(|c| uid_predicate(&c))
                             || c.user_attributes().any(|c| ua_predicate(&c))
                             || c.keys().subkeys().any(|c| key_predicate(&c))) {
                    None
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
            filter(m.values_of("input"), &mut output, Some, false)?;
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
            list(config, &mut input, m.is_present("all-userids"))
        },
        ("dsm-import",  Some(m)) => {
            dsm_import(config, m)
        },
        ("extract",  Some(m)) => {
            let mut output = if m.is_present("include-private") {
                config.create_or_stdout_pgp(m.value_of("output"), m.is_present("binary"), armor::Kind::SecretKey)?
            }else {
                config.create_or_stdout_pgp(m.value_of("output"), m.is_present("binary"), armor::Kind::PublicKey)?
            };
            extract_dsm( m, &mut output)?;
            output.finalize()
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
                        .unwrap_or_else(|| String::from("output"))
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

/// Import keyring into DSM.
fn dsm_import(config: Config, m: &ArgMatches) -> Result<()> {
    let dsm_secret = dsm::Auth::from_options_or_env(
        m.value_of("api-key"),
        m.value_of("client-cert"),
        m.value_of("app-uuid"),
        m.value_of("pkcs12-passphrase"),
    )?;
    let dsm_auth = dsm::Credentials::new(dsm_secret)?;

    let input = open_or_stdin(m.value_of("input"))?;

    // for import all keys of keyring to specific group apart from default group
    let group_id = m.value_of("dsm-group-id");

    // Parse keyring into certificates and upload as seperate keys into DSM
    for cert in CertParser::from_reader(input)? {
        let cert = cert.context("Malformed certificate in keyring")?;

        // decrypt if secrets in keyring were protected with password
        let key = if cert.is_tsk() { _unlock(cert)? } else { cert };

        let valid_key = key.with_policy(&config.policy, None)?;
        match m.value_of("keyring-name") {
            Some(keyring_name) => 
                dsm::import_key_to_dsm(
                    valid_key, &keyring_name, group_id, dsm_auth.clone(), m.is_present("dsm-exportable"), None, true
                )?,
            None => unreachable!("keyring name is compulsory")
        }
    }
    println!("OK");
    Ok(())
}

/// Creates keyring from DSM keys.
fn extract_dsm(m: &ArgMatches, output: &mut dyn io::Write) -> Result<()> {
    let dsm_secret = dsm::Auth::from_options_or_env(
        m.value_of("api-key"),
        m.value_of("client-cert"),
        m.value_of("app-uuid"),
        m.value_of("pkcs12-passphrase"),
    )?;

    let dsm_auth = dsm::Credentials::new(dsm_secret)?;
    let include_private  = m.is_present("include-private");

    // password to encrypt the secret materials in keyring
    let mut password = None;
    if include_private {
        let prompt_0 =
            rpassword::read_password_from_tty(Some("New password: "))
            .context("Error reading password")?;
        let prompt_1 =
            rpassword::read_password_from_tty(Some("Repeat new password: "))
            .context("Error reading password")?;

        if prompt_0 != prompt_1 {
            return Err(anyhow::anyhow!("Passwords do not match"));
        }
        
        password = if prompt_0.is_empty() {
            // Empty password means no password.
            None
        } else {
            Some(prompt_0.into())
        };
    }

    match m.values_of("dsm-key-id") {
        Some(values) => {
            for key_id in values {
                if include_private {
                    let mut key = dsm::extract_tsk_from_dsm("", dsm_auth.clone(), Some(key_id))?;
                    
                    // Encrypt secret all keymaterial in keyring with given password
                    if let Some(ref new) = password {
                        let mut encrypted: Vec<Packet> = vec![
                            key.primary_key().key().clone().parts_into_secret()?
                                .encrypt_secret(&new)?.into()
                        ];
                        for ka in key.keys().subkeys().unencrypted_secret() {
                            encrypted.push(
                                ka.key().clone().parts_into_secret()?
                                    .encrypt_secret(&new)?.into());
                        }
                        key = key.insert_packets(encrypted)?;
                    }

                    key.as_tsk().serialize(output)?;
                } else {
                    let cert = dsm::extract_cert("", dsm_auth.clone(), Some(key_id))?;
                    cert.serialize(output)?;
                }
            }
        }
        None => {
            eprintln!("No key-id values provided to create keyring.");
            std::process::exit(1); // Exit with error code
        }
    };
    
    Ok(())
}

/// Lists certs in a keyring.
fn list(config: Config,
        input: &mut (dyn io::Read + Sync + Send),
        list_all_uids: bool)
        -> Result<()>
{
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in keyring")?;
        let line = format!("{}. {:X}", i, cert.fingerprint());
        let indent = line.chars().map(|_| ' ').collect::<String>();
        print!("{}", line);

        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(&config.policy, None) {
            if let Ok(primary) = vcert.primary_userid() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            let null = openpgp::policy::NullPolicy::new();
            if let Ok(vcert) = cert.with_policy(&null, None) {
                if let Ok(primary) = vcert.primary_userid() {
                    println!(" {}", String::from_utf8_lossy(primary.value()));
                    primary_uid = Some(primary.value().to_vec());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        if primary_uid.is_none() {
            // No dice.
            println!();
        }

        if list_all_uids {
            // List all user ids independently of their validity.
            for u in cert.userids() {
                if primary_uid.as_ref()
                    .map(|p| &p[..] == u.value()).unwrap_or(false)
                {
                    // Skip the user id we already printed.
                    continue;
                }

                println!("{} {}", indent,
                         String::from_utf8_lossy(u.value()));
            }
        }
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
        let mut sink = if let Some(f) = cert.userids().next()
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

    let mut fingerprints: Vec<Fingerprint> = certs.keys().cloned().collect();
    fingerprints.sort();

    for fpr in fingerprints.iter() {
        if let Some(Some(cert)) = certs.get(fpr) {
            cert.as_tsk().serialize(output)?;
        }
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

    if !r.is_empty() {
        Some(r)
    } else {
        None
    }
}
