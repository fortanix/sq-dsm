use anyhow::Context as _;
use clap::ArgMatches;
use itertools::Itertools;
use std::time::{SystemTime, Duration};

use crate::openpgp::Result;
use crate::openpgp::Packet;
use crate::openpgp::cert::prelude::*;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::armor::{Writer, Kind};
use crate::openpgp::serialize::Serialize;

use crate::create_or_stdout;

const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;

pub fn generate(m: &ArgMatches, force: bool) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    match m.values_of("userid") {
        Some(uids) => for uid in uids {
            builder = builder.add_userid(uid);
        },
        None => {
            eprintln!("No user ID given, using direct key signature");
        }
    }

    // Expiration.
    match (m.value_of("expires"), m.value_of("expires-in")) {
        (None, None) => // Default expiration.
            builder = builder.set_validity_period(
                Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),
        (Some(t), None) if t == "never" =>
            builder = builder.set_validity_period(None),
        (Some(t), None) => {
            let now = builder.creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(
                crate::parse_iso8601(t, chrono::NaiveTime::from_hms(0, 0, 0))?);
            let validity = expiration.duration_since(now)?;
            builder = builder.set_creation_time(now)
                .set_validity_period(validity);
        },
        (None, Some(d)) if d == "never" =>
            builder = builder.set_validity_period(None),
        (None, Some(d)) => {
            let d = parse_duration(d)?;
            builder = builder.set_validity_period(Some(d));
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    // Cipher Suite
    match m.value_of("cipher-suite") {
        Some("rsa3k") => {
            builder = builder.set_cipher_suite(CipherSuite::RSA3k);
        }
        Some("rsa4k") => {
            builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        }
        Some("cv25519") => {
            builder = builder.set_cipher_suite(CipherSuite::Cv25519);
        }
        Some(ref cs) => {
            return Err(anyhow::anyhow!("Unknown cipher suite '{}'", cs));
        }
        None => panic!("argument has a default value"),
    }

    // Signing Capability
    match (m.is_present("can-sign"), m.is_present("cannot-sign")) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-sign and --cannot-sign"));
        }
    }

    // Encryption Capability
    match (m.value_of("can-encrypt"), m.is_present("cannot-encrypt")) {
        (Some("universal"), false) | (None, false) => {
            builder = builder.add_subkey(KeyFlags::default()
                                         .set_transport_encryption()
                                         .set_storage_encryption(),
                                         None,
                                         None);
        }
        (Some("storage"), false) => {
            builder = builder.add_storage_encryption_subkey();
        }
        (Some("transport"), false) => {
            builder = builder.add_transport_encryption_subkey();
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"));
        }
        (Some(ref cap), false) => {
            return Err(
                anyhow::anyhow!("Unknown encryption capability '{}'", cap));
        }
    }

    if m.is_present("with-password") {
        let p0 = rpassword::read_password_from_tty(Some(
            "Enter password to protect the key: "))?.into();
        let p1 = rpassword::read_password_from_tty(Some(
            "Repeat the password once more: "))?.into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match."));
        }
    }

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    if m.is_present("export") {
        let (key_path, rev_path) =
            match (m.value_of("export"), m.value_of("rev-cert")) {
                (Some("-"), Some("-")) =>
                    ("-".to_string(), "-".to_string()),
                (Some("-"), Some(ref rp)) =>
                    ("-".to_string(), rp.to_string()),
                (Some("-"), None) =>
                    return Err(
                        anyhow::anyhow!("Missing arguments: --rev-cert is mandatory \
                                     if --export is '-'.")),
                (Some(ref kp), None) =>
                    (kp.to_string(), format!("{}.rev", kp)),
                (Some(ref kp), Some("-")) =>
                    (kp.to_string(), "-".to_string()),
                (Some(ref kp), Some(ref rp)) =>
                    (kp.to_string(), rp.to_string()),
                _ =>
                    return Err(
                        anyhow::anyhow!("Conflicting arguments --rev-cert and \
                                     --export")),
            };

        let headers = cert.armor_headers();

        // write out key
        {
            let headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let w = create_or_stdout(Some(&key_path), force)?;
            let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
            cert.as_tsk().serialize(&mut w)?;
            w.finalize()?;
        }

        // write out rev cert
        {
            let mut headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();
            headers.insert(0, ("Comment", "Revocation certificate for"));

            let w = create_or_stdout(Some(&rev_path), force)?;
            let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
            Packet::Signature(rev).serialize(&mut w)?;
            w.finalize()?;
        }
    } else {
        return Err(
            anyhow::anyhow!("Saving generated key to the store isn't implemented \
                         yet."));
    }

    Ok(())
}

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
