/// A simple signature verification program.
///
/// See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872271 for
/// the motivation.

use chrono::{DateTime, offset::Utc};
extern crate clap;
extern crate failure;
use failure::ResultExt;

extern crate sequoia_openpgp as openpgp;

use std::process::exit;
use std::fs::File;
use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use std::rc::Rc;

use crate::openpgp::{
    Cert, Packet, packet::Signature, KeyHandle, KeyID, RevocationStatus,
};
use crate::openpgp::types::HashAlgorithm;
use crate::openpgp::crypto::hash::Hash;
use crate::openpgp::parse::{Parse, PacketParserResult, PacketParser};
use crate::openpgp::cert::CertParser;

mod sqv_cli;

fn real_main() -> Result<(), failure::Error> {
    let matches = sqv_cli::build().get_matches();

    let trace = matches.is_present("trace");

    let good_threshold
        = if let Some(good_threshold) = matches.value_of("signatures") {
            match good_threshold.parse::<usize>() {
                Ok(good_threshold) => good_threshold,
                Err(err) => {
                    eprintln!("Value passed to --signatures must be numeric: \
                               {} (got: {:?}).",
                              err, good_threshold);
                    exit(2);
                },
            }
        } else {
            1
        };
    if good_threshold < 1 {
        eprintln!("Value passed to --signatures must be >= 1 (got: {:?}).",
                  good_threshold);
        exit(2);
    }

    let not_before: Option<std::time::SystemTime> =
        if let Some(t) = matches.value_of("not-before") {
            Some(parse_iso8601(t, chrono::NaiveTime::from_hms(0, 0, 0))
                 .context(format!("Bad value passed to --not-before: {:?}", t))?
                 .into())
        } else {
            None
        };
    let not_after: std::time::SystemTime =
        if let Some(t) = matches.value_of("not-after") {
            Some(parse_iso8601(t, chrono::NaiveTime::from_hms(23, 59, 59))
                 .context(format!("Bad value passed to --not-after: {:?}", t))?
                 .into())
        } else {
            None
        }.unwrap_or_else(|| std::time::SystemTime::now());

    // First, we collect the signatures and the alleged issuers.
    // Then, we scan the keyrings exactly once to find the associated
    // Certs.

    let sig_file = matches.value_of_os("sig-file")
        .expect("'sig-file' is required");

    let mut ppr = PacketParser::from_file(sig_file)?;

    let mut sigs_seen = HashSet::new();
    let mut sigs: Vec<(Signature, KeyID)> = Vec::new();

    // sig_i is count of all Signature packets that we've seen.  This
    // may be more than sigs.len() if we can't handle some of the
    // sigs.
    let mut sig_i = 0;

    while let PacketParserResult::Some(pp) = ppr {
        let (packet, ppr_tmp) = pp.recurse().unwrap();
        ppr = ppr_tmp;

        match packet {
            Packet::Signature(sig) => {
                // To check for duplicates, we normalize the
                // signature, and put it into the hashset of seen
                // signatures.
                let mut sig_normalized = sig.clone();
                sig_normalized.unhashed_area_mut().clear();
                if sigs_seen.replace(sig_normalized).is_some() {
                    eprintln!("Ignoring duplicate signature.");
                    continue;
                }

                sig_i += 1;
                if let Some(fp) = sig.issuer_fingerprint() {
                    if trace {
                        eprintln!("Will check signature allegedly issued by {}.",
                                  fp);
                    }

                    // XXX: We use a KeyID even though we have a
                    // fingerprint!
                    sigs.push((sig.clone(), fp.into()));
                } else if let Some(keyid) = sig.issuer() {
                    if trace {
                        eprintln!("Will check signature allegedly issued by {}.",
                                  keyid);
                    }

                    sigs.push((sig.clone(), keyid.clone()));
                } else {
                    eprintln!("Signature #{} does not contain information \
                               about the issuer.  Unable to validate.",
                              sig_i);
                }
            },
            Packet::CompressedData(_) => {
                // Skip it.
            },
            Packet::Marker(_) => (), // Marker packets must be ignored.
            packet => {
                eprintln!("OpenPGP message is not a detached signature.  \
                           Encountered unexpected packet: {:?} packet.",
                          packet.tag());
                exit(2);
            }
        }
    }

    if sigs.len() == 0 {
        eprintln!("{:?} does not contain an OpenPGP signature.", sig_file);
        exit(2);
    }


    // Hash the content.

    let file = matches.value_of_os("file").expect("'file' is required");
    let hash_algos : Vec<HashAlgorithm>
        = sigs.iter().map(|&(ref sig, _)| sig.hash_algo()).collect();
    let hashes: HashMap<_, _> =
        openpgp::crypto::hash_reader(File::open(file)?, &hash_algos[..])?
        .into_iter().map(|ctx| (ctx.algo(), ctx)).collect();

    fn cert_has_key(cert: &Cert, keyid: &KeyID) -> bool {
        // Even if a key is revoked or expired, we can still use it to
        // verify a message.
        cert.keys().any(|key| *keyid == key.keyid())
    }

    // Find the certs.
    let mut certs: HashMap<KeyHandle, Rc<RefCell<Cert>>> = HashMap::new();
    for filename in matches.values_of_os("keyring")
        .expect("No keyring specified.")
    {
        // Load the keyring.
        for cert in CertParser::from_file(filename)?
            .unvalidated_cert_filter(|cert, _| {
                for &(_, ref issuer) in &sigs {
                    if cert_has_key(cert, issuer) {
                        return true;
                    }
                }
                false
            })
            .map(|certr| {
                match certr {
                    Ok(cert) => cert,
                    Err(err) => {
                        eprintln!("Error reading keyring {:?}: {}",
                                  filename, err);
                        exit(2);
                    }
                }
            })
        {
            for (_, issuer) in sigs.iter() {
                if cert_has_key(&cert, issuer) {
                    let fp: KeyHandle = cert.fingerprint().into();
                    let id = KeyHandle::KeyID(fp.clone().into());

                    let cert = if let Some(known) = certs.get(&fp) {
                        if trace {
                            eprintln!("Found key {} again.  Merging.",
                                      fp);
                        }

                        // XXX: Use RefCell::replace_with once stabilized.
                        let k = known.borrow().clone();
                        known.replace(k.merge(cert)?);

                        known.clone()
                    } else {
                        if trace {
                            eprintln!("Found key {}.", issuer);
                        }

                        Rc::new(RefCell::new(cert))
                    };

                    certs.insert(fp, cert.clone());
                    certs.insert(id, cert.clone());
                    for c in cert.borrow().subkeys() {
                        let fp: KeyHandle = c.key().fingerprint().into();
                        let id = KeyHandle::KeyID(fp.clone().into());
                        certs.insert(fp, cert.clone());
                        certs.insert(id, cert.clone());
                    }
                    break;
                }
            }
        }
    }

    // Verify the signatures.
    let mut sigs_seen_from_cert = HashSet::new();
    let mut good = 0;
    'sig_loop: for (sig, issuer) in sigs.into_iter() {
        if trace {
            eprintln!("Checking signature allegedly issued by {}.", issuer);
        }

        if let Some(cert) = certs.get(&issuer.clone().into()) {
            let cert = cert.borrow();
            // Find the right key.
            for ka in cert.keys().policy(None) {
                // Use the current binding signature.
                let binding = match ka.binding_signature(None) {
                    Some(b) => b,
                    None => continue,
                };
                let key = ka.key();

                if issuer == key.keyid() {
                    if !binding.key_flags().for_signing() {
                        eprintln!("Cannot check signature, key has no signing \
                                   capability");
                        continue 'sig_loop;
                    }

                    let mut hash = match hashes.get(&sig.hash_algo()) {
                        Some(h) => h.clone(),
                        None => {
                            eprintln!("Cannot check signature, hash algorithm \
                                       {} not supported.", sig.hash_algo());
                            continue 'sig_loop;
                        },
                    };
                    sig.hash(&mut hash);

                    let mut digest = vec![0u8; hash.digest_size()];
                    hash.digest(&mut digest);
                    match sig.verify_digest(key, &digest[..]) {
                        Ok(true) => {
                            if let Some(t) = sig.signature_creation_time() {
                                if let Some(not_before) = not_before {
                                    if t < not_before {
                                        eprintln!(
                                            "Signature by {} was created before \
                                             the --not-before date.",
                                            issuer);
                                        break;
                                    }
                                }

                                if t > not_after {
                                    eprintln!(
                                        "Signature by {} was created after \
                                         the --not-after date.",
                                        issuer);
                                    break;
                                }

                                // check key was valid at sig creation time
                                let binding = cert
                                    .subkeys()
                                    .find(|s| {
                                        s.key().fingerprint() == key.fingerprint()
                                    });
                                if let Some(binding) = binding {
                                    if binding.revoked(t) != RevocationStatus::NotAsFarAsWeKnow {
                                        eprintln!(
                                            "Key was revoked when the signature \
                                             was created.");
                                        break;
                                    }

                                    if binding.binding_signature(t).is_none() {
                                        eprintln!(
                                            "Key was not live when the \
                                             signature was created.");
                                        break;
                                    }
                                }

                                if cert.revoked(t)
                                    != RevocationStatus::NotAsFarAsWeKnow
                                {
                                    eprintln!(
                                        "Primary key was revoked when the \
                                         signature was created.");
                                    break;
                                }
                            } else {
                                eprintln!(
                                    "Signature by {} does not contain \
                                     information about the creation time.",
                                    issuer);
                                break;
                            }

                            if trace {
                                eprintln!("Signature by {} is good.", issuer);
                            }

                            if sigs_seen_from_cert.replace(cert.fingerprint())
                                .is_some()
                            {
                                eprintln!(
                                    "Ignoring additional good signature by {}.",
                                    issuer);
                                continue;
                            }

                            println!("{}", cert.primary().fingerprint());
                            good += 1;
                        },
                        Ok(false) => {
                            if trace {
                                eprintln!("Signature by {} is bad.", issuer);
                            }
                        },
                        Err(err) => {
                            if trace {
                                eprintln!("Verifying signature: {}.", err);
                            }
                        },
                    }

                    break;
                }
            }
        } else {
            eprintln!("Can't verify signature by {}, missing key.",
                      issuer);
        }
    }

    if trace {
        eprintln!("{} of {} signatures are valid (threshold is: {}).",
                  good, sig_i, good_threshold);
    }

    exit(if good >= good_threshold { 0 } else { 1 });
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

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> failure::Fallible<DateTime<Utc>>
{
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
    Err(failure::format_err!("Malformed ISO8601 timestamp: {}", s))
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
