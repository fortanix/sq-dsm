use failure;
use clap::ArgMatches;

use openpgp::tpk::{TPKBuilder, CipherSuite};
use openpgp::packet::KeyFlags;
use openpgp::armor::{Writer, Kind};
use openpgp::serialize::Serialize;

use ::create_or_stdout;

pub fn generate(m: &ArgMatches, force: bool) -> failure::Fallible<()> {
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
            return Err(format_err!("Unknown cipher suite '{}'", cs));
        }
    }

    // Signing Capability
    match (m.is_present("can-sign"), m.is_present("cannot-sign")) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(
                format_err!("Conflicting arguments --can-sign and --cannot-sign"));
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
            return Err(
                format_err!("Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"));
        }
        (Some(ref cap), false) => {
            return Err(
                format_err!("Unknown encryption capability '{}'", cap));
        }
    }

    if m.is_present("with-password") {
        let p0 = rpassword::prompt_password_stderr(
            "Enter password to protect the key: ")?.into();
        let p1 = rpassword::prompt_password_stderr(
            "Repeat the password once more: ")?.into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(failure::err_msg("Passwords do not match."));
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
                (Some("-"), None) =>
                    return Err(
                        format_err!("Missing arguments: --rev-cert is mandatory \
                                     if --export is '-'.")),
                (Some(ref kp), None) =>
                    (kp.to_string(), format!("{}.rev", kp)),
                (Some(ref kp), Some("-")) =>
                    (kp.to_string(), "-".to_string()),
                (Some(ref kp), Some(ref rp)) =>
                    (kp.to_string(), rp.to_string()),
                _ =>
                    return Err(
                        format_err!("Conflicting arguments --rev-cert and \
                                     --export")),
            };

        // write out key
        {
            let w = create_or_stdout(Some(&key_path), force)?;
            let mut w = Writer::new(w, Kind::SecretKey, &[])?;
            tsk.serialize(&mut w)?;
        }

        // write out rev cert
        {
            let w = create_or_stdout(Some(&rev_path), force)?;
            let mut w = Writer::new(w, Kind::Signature, &[])?;
            rev.serialize(&mut w)?;
        }
    } else {
        return Err(
            format_err!("Saving generated key to the store isn't implemented \
                         yet."));
    }

    Ok(())
}
