/// A simple signature verification program.
///
/// See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872271 for
/// the motivation.

extern crate clap;
extern crate failure;
use failure::ResultExt;
extern crate time;

extern crate sequoia_openpgp as openpgp;

use std::process::exit;
use std::fs::File;
use std::collections::{HashMap, HashSet};

use openpgp::{TPK, Packet, packet::Signature, KeyID};
use openpgp::constants::HashAlgorithm;
use openpgp::parse::{Parse, PacketParserResult, PacketParser};
use openpgp::tpk::TPKParser;

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

    let not_before = if let Some(t) = matches.value_of("not-before") {
        Some(time::strptime(t, "%Y-%m-%d")
             .context(format!("Bad value passed to --not-before: {:?}", t))?)
    } else {
        None
    };
    let not_after = if let Some(t) = matches.value_of("not-after") {
        Some(time::strptime(t, "%Y-%m-%d")
             .context(format!("Bad value passed to --not-after: {:?}", t))?)
    } else {
        None
    }.unwrap_or_else(|| time::now_utc());

    // First, we collect the signatures and the alleged issuers.
    // Then, we scan the keyrings exactly once to find the associated
    // TPKs.

    // .unwrap() is safe, because "sig-file" is required.
    let sig_file = matches.value_of_os("sig-file").unwrap();

    let mut ppr = PacketParser::from_file(sig_file)?;

    let mut sigs_seen = HashSet::new();
    let mut sigs : Vec<(Signature, KeyID, Option<TPK>)> = Vec::new();

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
                    sigs.push((sig, fp.to_keyid(), None));
                } else if let Some(keyid) = sig.issuer() {
                    if trace {
                        eprintln!("Will check signature allegedly issued by {}.",
                                  keyid);
                    }

                    sigs.push((sig, keyid, None));
                } else {
                    eprintln!("Signature #{} does not contain information \
                               about the issuer.  Unable to validate.",
                              sig_i);
                }
            },
            Packet::CompressedData(_) => {
                // Skip it.
            },
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

    // .unwrap() is safe, because "file" is required.
    let file = matches.value_of_os("file").unwrap();
    let hash_algos : Vec<HashAlgorithm>
        = sigs.iter().map(|&(ref sig, _, _)| sig.hash_algo()).collect();
    let hashes: HashMap<_, _> =
        openpgp::crypto::hash_file(File::open(file)?, &hash_algos[..])?
        .into_iter().collect();

    fn tpk_has_key(tpk: &TPK, keyid: &KeyID) -> bool {
        if *keyid == tpk.primary().keyid() {
            return true;
        }
        for binding in tpk.subkeys() {
            if *keyid == binding.subkey().keyid() {
                return true;
            }
        }
        false
    }

    // Find the keys.
    for filename in matches.values_of_os("keyring")
        .expect("No keyring specified.")
    {
        // Load the keyring.
        let tpks : Vec<TPK> = TPKParser::from_file(filename)?
            .unvalidated_tpk_filter(|tpk, _| {
                for &(_, ref issuer, _) in &sigs {
                    if tpk_has_key(tpk, issuer) {
                        return true;
                    }
                }
                false
            })
            .map(|tpkr| {
                match tpkr {
                    Ok(tpk) => tpk,
                    Err(err) => {
                        eprintln!("Error reading keyring {:?}: {}",
                                  filename, err);
                        exit(2);
                    }
                }
            })
            .collect();

        for tpk in tpks {
            for &mut (_, ref issuer, ref mut issuer_tpko) in sigs.iter_mut() {
                if tpk_has_key(&tpk, issuer) {
                    if let Some(issuer_tpk) = issuer_tpko.take() {
                        if trace {
                            eprintln!("Found key {} again.  Merging.",
                                      issuer);
                        }

                        *issuer_tpko
                            = issuer_tpk.merge(tpk.clone()).ok();
                    } else {
                        if trace {
                            eprintln!("Found key {}.", issuer);
                        }

                        *issuer_tpko = Some(tpk.clone());
                    }
                }
            }
        }
    }

    // Verify the signatures.
    let mut sigs_seen_from_tpk = HashSet::new();
    let mut good = 0;
    'sig_loop: for (mut sig, issuer, tpko) in sigs.into_iter() {
        if trace {
            eprintln!("Checking signature allegedly issued by {}.", issuer);
        }

        if let Some(ref tpk) = tpko {
            // Find the right key.
            for (_, key) in tpk.keys() {
                if issuer == key.keyid() {
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
                    let hash_algo = sig.hash_algo();
                    sig.set_computed_hash(Some((hash_algo, digest)));

                    match sig.verify(key) {
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

                            if sigs_seen_from_tpk.replace(tpk.fingerprint())
                                .is_some()
                            {
                                eprintln!(
                                    "Ignoring additional good signature by {}.",
                                    issuer);
                                continue;
                            }

                            println!("{}", tpk.primary().fingerprint());
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
