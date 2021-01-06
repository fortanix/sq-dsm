use std::{
    fs::File,
    io,
    path::PathBuf,
};
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::CertParser,
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    open_or_stdin,
    create_or_stdout_pgp,
};

pub fn dispatch(m: &clap::ArgMatches, force: bool) -> Result<()> {
    match m.subcommand() {
        ("join",  Some(m)) => {
            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output = create_or_stdout_pgp(m.value_of("output"),
                                                  force,
                                                  m.is_present("binary"),
                                                  armor::Kind::PublicKey)?;
            join(m.values_of("input"), &mut output)?;
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
                        .unwrap_or(String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            split(&mut input, &prefix)
        },

        _ => unreachable!(),
    }
}

/// Joins cert(ring)s into a certring.
fn join(inputs: Option<clap::Values>, output: &mut dyn io::Write)
        -> Result<()> {
    if let Some(inputs) = inputs {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in certring {:?}", name))?;
                cert.serialize(output)?;
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in certring")?;
            cert.serialize(output)?;
        }
    }
    Ok(())
}

/// Splits a certring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in certring")?;
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

        cert.armored().serialize(&mut sink)?;
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
