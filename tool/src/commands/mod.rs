use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use time;
use rpassword;
use tempfile::NamedTempFile;

extern crate openpgp;
use openpgp::armor;
use openpgp::constants::DataFormat;
use openpgp::{Packet, TPK, KeyID, Error, Result};
use openpgp::packet::Signature;
use openpgp::parse::PacketParserResult;
use openpgp::parse::stream::{
    Verifier, VerificationResult, VerificationHelper,
};
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{
    wrap, Signer, LiteralWriter, Encryptor, EncryptionMode,
};
extern crate sequoia_store as store;

use super::create_or_stdout;

mod decrypt;
pub use self::decrypt::decrypt;
mod dump;
pub use self::dump::dump;

const TIMEFMT: &'static str = "%Y-%m-%dT%H:%M";

fn tm2str(t: &time::Tm) -> String {
    time::strftime(TIMEFMT, t).expect("TIMEFMT is correct")
}

pub fn encrypt(store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               npasswords: usize, recipients: Vec<&str>,
               mut tpks: Vec<openpgp::TPK>)
               -> Result<()> {
    for r in recipients {
        tpks.push(store.lookup(r).context("No such key found")?.tpk()?);
    }
    let mut passwords = Vec::with_capacity(npasswords);
    for n in 0..npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::prompt_password_stderr(
            if npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            })?);
    }

    // Build a vector of references to hand to Encryptor.
    let recipients: Vec<&openpgp::TPK> = tpks.iter().collect();
    let passwords_: Vec<&[u8]> =
        passwords.iter().map(|p| p.as_bytes()).collect();

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::new(wrap(output),
                                   &passwords_,
                                   &recipients,
                                   EncryptionMode::AtRest)
        .context("Failed to create encryptor")?;
    let mut literal_writer = LiteralWriter::new(encryptor, DataFormat::Binary,
                                                None, None)
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    Ok(())
}

pub fn sign(input: &mut io::Read, output_path: Option<&str>,
            secrets: Vec<openpgp::TPK>, detached: bool, binary: bool,
            append: bool, notarize: bool)
            -> Result<()> {
    match (detached, append|notarize) {
        (_, false) | (true, true) =>
            sign_data(input, output_path, secrets, detached, binary, append),
        (false, true) =>
            sign_message(input, output_path, secrets, binary, notarize),
    }
}

fn sign_data(input: &mut io::Read, output_path: Option<&str>,
             secrets: Vec<openpgp::TPK>, detached: bool, binary: bool,
             append: bool)
             -> Result<()> {
    let (mut output, prepend_sigs, tmp_path):
    (Box<io::Write>, Vec<Signature>, Option<PathBuf>) =
        if detached && append && output_path.is_some() {
            // First, read the existing signatures.
            let mut sigs = Vec::new();
            let reader = openpgp::Reader::from_file(output_path.unwrap())?;
            let mut ppr
                = openpgp::parse::PacketParser::from_reader(reader)?;

            while let PacketParserResult::Some(mut pp) = ppr {
                let ((packet, _), (ppr_tmp, _)) = pp.recurse()?;
                ppr = ppr_tmp;

                match packet {
                    Packet::Signature(sig) => sigs.push(sig),
                    p => return Err(
                        failure::err_msg(
                            format!("{} in detached signature", p.tag()))
                            .context("Invalid detached signature").into()),
                }
            }

            // Then, create a temporary file to write to.  If we are
            // successful with adding our signature(s), we rename the
            // file replacing the old one.
            let tmp_file = NamedTempFile::new_in(
                PathBuf::from(output_path.unwrap()).parent()
                    .unwrap_or(&PathBuf::from(".")))?;
            let tmp_path = tmp_file.path().into();
            (Box::new(tmp_file), sigs, Some(tmp_path))
        } else {
            (create_or_stdout(output_path)?, Vec::new(), None)
        };

    let mut output = if ! binary {
        Box::new(armor::Writer::new(&mut output,
                                    if detached {
                                        armor::Kind::Signature
                                    } else {
                                        armor::Kind::Message
                                    },
                                    &[][..])?)
    } else {
        output
    };

    // When extending a detached signature, prepend any existing
    // signatures first.
    for sig in prepend_sigs {
        sig.serialize(&mut output)?;
    }

    let sink = wrap(output);
    // Build a vector of references to hand to Signer.
    let keys: Vec<&openpgp::TPK> = secrets.iter().collect();
    let signer = if detached {
        Signer::detached(sink, &keys)
    } else {
        Signer::new(sink, &keys)
    }.context("Failed to create signer")?;

    let mut writer = if detached {
        // Detached signatures do not need a literal data packet, just
        // hash the data as is.
        signer
    } else {
        // We want to wrap the data in a literal data packet.
        LiteralWriter::new(signer, DataFormat::Binary, None, None)
            .context("Failed to create literal writer")?
    };

    // Finally, copy stdin to our writer stack to sign the data.
    io::copy(input, &mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;

    if let Some(path) = tmp_path {
        // Atomically replace the old file.
        fs::rename(path,
                   output_path.expect("must be Some if tmp_path is Some"))?;
    }
    Ok(())
}

fn sign_message(input: &mut io::Read, output_path: Option<&str>,
                secrets: Vec<openpgp::TPK>, binary: bool, notarize: bool)
             -> Result<()> {
    let mut output = create_or_stdout(output_path)?;
    let output = if ! binary {
        Box::new(armor::Writer::new(&mut output,
                                    armor::Kind::Message,
                                    &[][..])?)
    } else {
        output
    };

    let mut sink = wrap(output);
    // Build a vector of references to hand to Signer.
    let keys: Vec<&openpgp::TPK> = secrets.iter().collect();

    // Create a parser for the message to be notarized.
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(
            openpgp::Reader::from_reader(input)
                .context("Failed to build reader")?)
        .context("Failed to build parser")?;

    // Once we see a signature, we can no longer strip compression.
    let mut seen_signature = false;
    #[derive(PartialEq, Eq, Debug)]
    enum State {
        InFirstSigGroup,
        AfterFirstSigGroup,
        Signing {
            // Counts how many signatures are being notarized.  If
            // this drops to zero, we pop the signer from the stack.
            signature_count: isize,
        },
        Done,
    };
    let mut state =
        if ! notarize {
            State::InFirstSigGroup
        } else {
            // Pretend we have passed the first signature group so
            // that we put our signature first.
            State::AfterFirstSigGroup
        };

    while let PacketParserResult::Some(mut pp) = ppr {
        if ! pp.possible_message() {
            return Err(Error::MalformedMessage(
                "Malformed OpenPGP message".into()).into());
        }

        match pp.packet {
            Packet::PKESK(_) | Packet::SKESK(_) =>
                return Err(failure::err_msg(
                    "Signing encrypted data is not implemented")),

            Packet::Literal(_) =>
                if let State::InFirstSigGroup = state {
                    // Cope with messages that have no signatures, or
                    // with a ops packet without the last flag.
                    state = State::AfterFirstSigGroup;
                },

            // To implement this, we'd need to stream the
            // compressed data packet inclusive framing, but
            // currently the partial body filter transparently
            // removes the framing.
            //
            // If you do implement this, there is a half-disabled test
            // in tests/sq-sign.rs.
            Packet::CompressedData(_) if seen_signature =>
                return Err(failure::err_msg(
                    "Signing a compress-then-sign message is not implemented")),

            _ => (),
        }

        match state {
            State::AfterFirstSigGroup => {
                // After the first signature group, we push the signer
                // onto the writer stack.
                sink = Signer::new(sink, &keys)
                    .context("Failed to create signer")?;
                state = State::Signing { signature_count: 0, };
            },

            State::Signing { signature_count } if signature_count == 0 => {
                // All signatures that are being notarized are
                // written, pop the signer from the writer stack.
                sink = sink.finalize_one()
                    .context("Failed to sign data")?
                    .unwrap();
                state = State::Done;
            },

            _ => (),
        }

        if let Packet::Literal(_) = pp.packet {
            let l = if let Packet::Literal(l) = pp.packet.clone() {
                l
            } else {
                unreachable!()
            };
            // Create a literal writer to wrap the data in a literal
            // message packet.
            let mut literal =
                LiteralWriter::new(sink, l.format(), l.filename(),
                                   l.date().map(|d| *d))
                .context("Failed to create literal writer")?;

            // Finally, just copy all the data.
            io::copy(&mut pp, &mut literal)
                .context("Failed to sign data")?;

            // Pop the literal writer.
            sink = literal.finalize_one()
                .context("Failed to sign data")?
                .unwrap();
        }

        let ((packet, _), (ppr_tmp, _)) = if seen_signature {
            // Once we see a signature, we can no longer strip
            // compression.
            pp.next()
        } else {
            pp.recurse()
        }.context("Parsing failed")?;
        ppr = ppr_tmp;

        match packet {
            Packet::OnePassSig(mut ops) => {
                let was_last = ops.last();
                match state {
                    State::InFirstSigGroup => {
                        // We want to append our signature here, hence
                        // we set last to false.
                        ops.set_last(false);

                        if was_last {
                            // The signature group ends here.
                            state = State::AfterFirstSigGroup;
                        }
                    },

                    State::Signing { ref mut signature_count } =>
                        *signature_count += 1,

                    _ => (),
                }

                ops.serialize(&mut sink)?;
                seen_signature = true;
            },

            Packet::Signature(ref sig) => {
                sig.serialize(&mut sink)
                    .context("Failed to serialize")?;
                if let State::Signing { ref mut signature_count } = state {
                    *signature_count -= 1;
                }
            },
            _ => (),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        if ! eof.is_message() {
            return Err(Error::MalformedMessage(
                "Malformed OpenPGP message".into()).into());
        }
    } else {
        unreachable!()
    }

    match state {
        State::Signing { signature_count } => {
            assert_eq!(signature_count, 0);
            sink.finalize_one()
                .context("Failed to sign data")?
                .unwrap();
        },
        State::Done => (),
        _ => panic!("Unexpected state: {:?}", state),
    }

    Ok(())
}

struct VHelper<'a> {
    store: &'a mut store::Store,
    signatures: usize,
    tpks: Option<Vec<TPK>>,
    labels: HashMap<KeyID, String>,
    good: usize,
    unknown: usize,
    bad: usize,
}

impl<'a> VHelper<'a> {
    fn new(store: &'a mut store::Store, signatures: usize, tpks: Vec<TPK>)
           -> Self {
        VHelper {
            store: store,
            signatures: signatures,
            tpks: Some(tpks),
            labels: HashMap::new(),
            good: 0,
            unknown: 0,
            bad: 0,
        }
    }

    fn print_status(&self) {
        eprintln!("{} good signatures, {} bad signatures, {} not checked.",
                  self.good, self.bad, self.unknown);
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        let mut tpks = self.tpks.take().unwrap();
        let seen: HashSet<_> = tpks.iter()
            .flat_map(|tpk| {
                tpk.keys().map(|(_, key)| key.fingerprint().to_keyid())
            }).collect();

        // Try to get missing TPKs from the store.
        for id in ids.iter().filter(|i| !seen.contains(i)) {
            let _ =
                self.store.lookup_by_subkeyid(id)
                .and_then(|binding| {
                    self.labels.insert(id.clone(), binding.label()?);
                    binding.tpk()
                })
                .and_then(|tpk| {
                    tpks.push(tpk);
                    Ok(())
                });
        }
        Ok(tpks)
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
        use self::VerificationResult::*;
        for (i, results) in sigs.into_iter().enumerate() {
            let what = if i == 0 {
                "signature".into()
            } else {
                format!("level {} notarization", i)
            };

            for result in results {
                match result {
                    GoodChecksum(sig) => {
                        let issuer = sig.get_issuer().unwrap();
                        let issuer_str = format!("{}", issuer);
                        eprintln!("Good {} from {}", what,
                                  self.labels.get(&issuer).unwrap_or(
                                      &issuer_str));
                        self.good += 1;
                    },
                    MissingKey(sig) => {
                        eprintln!("No key to check {} from {}", what,
                                  sig.get_issuer().unwrap());
                        self.unknown += 1;
                    },
                    BadChecksum(sig) => {
                        if let Some(issuer) = sig.get_issuer() {
                            let issuer_str = format!("{}", issuer);
                            eprintln!("Bad {} from {}", what,
                                      self.labels.get(&issuer).unwrap_or(
                                          &issuer_str));
                        } else {
                            eprintln!("Bad {} without issuer information",
                                      what);
                        }
                        self.bad += 1;
                    },
                }
            }
        }

        if self.good >= self.signatures && self.bad == 0 {
            Ok(())
        } else {
            self.print_status();
            Err(failure::err_msg("Verification failed"))
        }
    }
}

pub fn verify(store: &mut store::Store,
              input: &mut io::Read, output: &mut io::Write,
              signatures: usize, tpks: Vec<TPK>)
              -> Result<()> {
    let helper = VHelper::new(store, signatures, tpks);
    let mut verifier = Verifier::from_reader(input, helper)?;

    io::copy(&mut verifier, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            e.into()
        })?;

    verifier.into_helper().print_status();
    Ok(())
}

pub fn split(input: &mut io::Read, prefix: &str)
             -> Result<()> {
    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).finalize()?;

    // This encodes our position in the tree.
    let mut pos = vec![0];

    while let PacketParserResult::Some(pp) = ppr {
        if let Some(ref map) = pp.map {
            let filename = format!(
                "{}{}--{:?}", prefix,
                pos.iter().map(|n| format!("{}", n))
                    .collect::<Vec<String>>().join("-"),
                pp.packet.tag());
            let mut sink = File::create(filename)
                .context("Failed to create output file")?;

            // Write all the bytes.
            for (_, buf) in map.iter() {
                sink.write_all(buf)?;
            }
        }

        let ((_, old_depth), (ppr_, new_depth)) = pp.recurse()?;
        ppr = ppr_;

        // Update pos.
        match old_depth.cmp(&new_depth) {
            Ordering::Less =>
                pos.push(0),
            Ordering::Equal =>
                *pos.last_mut().unwrap() += 1,
            Ordering::Greater => {
                pos.pop();
            },
        }
    }
    Ok(())
}

pub fn store_print_stats(store: &store::Store, label: &str) -> Result<()> {
    fn print_stamps(st: &store::Stamps) -> Result<()> {
        println!("{} messages using this key", st.count);
        if let Some(t) = st.first {
            println!("    First: {}", tm2str(&time::at(t)));
        }
        if let Some(t) = st.last {
            println!("    Last: {}", tm2str(&time::at(t)));
        }
        Ok(())
    }

    fn print_stats(st: &store::Stats) -> Result<()> {
        if let Some(t) = st.created {
            println!("  Created: {}", tm2str(&time::at(t)));
        }
        if let Some(t) = st.updated {
            println!("  Updated: {}", tm2str(&time::at(t)));
        }
        print!("  Encrypted ");
        print_stamps(&st.encryption)?;
        print!("  Verified ");
        print_stamps(&st.verification)?;
        Ok(())
    }

    let binding = store.lookup(label)?;
    println!("Binding {:?}", label);
    print_stats(&binding.stats().context("Failed to get stats")?)?;
    let key = binding.key().context("Failed to get key")?;
    println!("Key");
    print_stats(&key.stats().context("Failed to get stats")?)?;
    Ok(())
}
