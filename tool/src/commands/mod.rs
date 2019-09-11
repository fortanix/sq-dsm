use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use time;
use rpassword;

extern crate sequoia_openpgp as openpgp;
use sequoia_core::Context;
use crate::openpgp::constants::{
    CompressionAlgorithm,
};
use crate::openpgp::crypto;
use crate::openpgp::{TPK, KeyID, Result};
use crate::openpgp::packet::prelude::*;
use crate::openpgp::parse::{
    Parse,
    PacketParserResult,
};
use crate::openpgp::parse::stream::{
    Verifier, DetachedVerifier, VerificationResult, VerificationHelper,
    MessageStructure, MessageLayer,
};
use crate::openpgp::serialize::stream::{
    Message, Signer, LiteralWriter, Encryptor, Recipient,
    Compressor,
};
use crate::openpgp::serialize::padding::{
    Padder,
    padme,
};
extern crate sequoia_store as store;

mod decrypt;
pub use self::decrypt::decrypt;
mod sign;
pub use self::sign::sign;
mod dump;
pub use self::dump::dump;
mod inspect;
pub use self::inspect::inspect;
pub mod key;

const TIMEFMT: &'static str = "%Y-%m-%dT%H:%M";

fn tm2str(t: &time::Tm) -> String {
    time::strftime(TIMEFMT, t).expect("TIMEFMT is correct")
}

/// Returns suitable signing keys from a given list of TPKs.
fn get_signing_keys(tpks: &[openpgp::TPK])
    -> Result<Vec<crypto::KeyPair<
           openpgp::packet::key::UnspecifiedRole>>>
{
    let mut keys = Vec::new();
    'next_tpk: for tsk in tpks {
        for key in tsk.keys_valid()
            .signing_capable()
            .map(|k| k.2)
        {
            if let Some(secret) = key.secret() {
                let unencrypted = match secret {
                    SecretKeyMaterial::Encrypted(ref e) => {
                        let password = rpassword::read_password_from_tty(Some(
                            &format!("Please enter password to decrypt {}/{}: ",
                                     tsk, key))).unwrap();
                        e.decrypt(key.pk_algo(), &password.into())
                            .expect("decryption failed")
                    },
                    SecretKeyMaterial::Unencrypted(ref u) => u.clone(),
                };

                keys.push(crypto::KeyPair::new(key.clone(), unencrypted)
                          .unwrap());
                break 'next_tpk;
            }
        }

        return Err(failure::err_msg(
            format!("Found no suitable signing key on {}", tsk)));
    }

    Ok(keys)
}

pub fn encrypt(store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               npasswords: usize, recipients: Vec<&str>,
               mut tpks: Vec<openpgp::TPK>, signers: Vec<openpgp::TPK>,
               mode: openpgp::constants::KeyFlags,
               compression: &str)
               -> Result<()> {
    for r in recipients {
        tpks.push(store.lookup(r).context("No such key found")?.tpk()?);
    }
    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(npasswords);
    for n in 0..npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::read_password_from_tty(Some(
            if npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            }))?.into());
    }

    let mut signers = get_signing_keys(&signers)?;

    // Build a vector of references to hand to Signer.
    let recipients: Vec<&openpgp::TPK> = tpks.iter().collect();

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for tpk in tpks.iter() {
        let mut count = 0;
        for (_, _, key) in tpk.keys_valid().key_flags(mode.clone()) {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            return Err(failure::format_err!(
                "Key {} has no suitable encryption key", tpk));
        }
    }

    // Stream an OpenPGP message.
    let message = Message::new(output);

    // We want to encrypt a literal data packet.
    let mut sink = Encryptor::new(message,
                                  passwords,
                                  recipient_subkeys,
                                  None, None)
        .context("Failed to create encryptor")?;

    match compression {
        "none" => (),
        "pad" => sink = Padder::new(sink, padme)?,
        "zip" =>
            sink = Compressor::new(sink, CompressionAlgorithm::Zip, None)?,
        "zlib" =>
            sink = Compressor::new(sink, CompressionAlgorithm::Zlib, None)?,
        "bzip2" =>
            sink = Compressor::new(sink, CompressionAlgorithm::BZip2, None)?,
        _ => unreachable!("all possible choices are handled")
    }

    // Optionally sign message.
    if ! signers.is_empty() {
        sink = Signer::with_intended_recipients(
            sink,
            signers.iter_mut().map(|s| -> &mut dyn crypto::Signer<_> { s })
                .collect(),
            &recipients,
            None)?;
    }

    let mut literal_writer = LiteralWriter::new(sink, None, None, None)
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(())
}

struct VHelper<'a> {
    ctx: &'a Context,
    store: &'a mut store::Store,
    signatures: usize,
    tpks: Option<Vec<TPK>>,
    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
}

impl<'a> VHelper<'a> {
    fn new(ctx: &'a Context, store: &'a mut store::Store, signatures: usize,
           tpks: Vec<TPK>)
           -> Self {
        VHelper {
            ctx: ctx,
            store: store,
            signatures: signatures,
            tpks: Some(tpks),
            labels: HashMap::new(),
            trusted: HashSet::new(),
            good_signatures: 0,
            good_checksums: 0,
            unknown_checksums: 0,
            bad_signatures: 0,
            bad_checksums: 0,
        }
    }

    fn print_status(&self) {
        fn p(dirty: &mut bool, what: &str, quantity: usize) {
            if quantity > 0 {
                eprint!("{}{} {}{}",
                        if *dirty { ", " } else { "" },
                        quantity, what,
                        if quantity == 1 { "" } else { "s" });
                *dirty = true;
            }
        }

        let mut dirty = false;
        p(&mut dirty, "good signature", self.good_signatures);
        p(&mut dirty, "good checksum", self.good_checksums);
        p(&mut dirty, "unknown checksum", self.unknown_checksums);
        p(&mut dirty, "bad signature", self.bad_signatures);
        p(&mut dirty, "bad checksum", self.bad_checksums);
        if dirty {
            eprintln!(".");
        }
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) {
        use self::VerificationResult::*;
        for result in results {
            let (issuer, level) = match result {
                GoodChecksum(ref sig, ..) => (sig.get_issuer(), sig.level()),
                MissingKey(ref sig) => (sig.get_issuer(), sig.level()),
                BadChecksum(ref sig) => (sig.get_issuer(), sig.level()),
            };

            let trusted = issuer.as_ref().map(|i| {
                self.trusted.contains(&i)
            }).unwrap_or(false);
            let what = match (level == 0, trusted) {
                (true,  true)  => "signature".into(),
                (false, true)  => format!("level {} notarization", level),
                (true,  false) => "checksum".into(),
                (false, false) =>
                    format!("level {} notarizing checksum", level),
            };

            match result {
                GoodChecksum(..) => {
                    let issuer = issuer
                        .expect("good checksum has an issuer");
                    let issuer_str = format!("{}", issuer);
                    eprintln!("Good {} from {}", what,
                              self.labels.get(&issuer).unwrap_or(
                                  &issuer_str));
                    if trusted {
                        self.good_signatures += 1;
                    } else {
                        self.good_checksums += 1;
                    }
                },
                MissingKey(_) => {
                    let issuer = issuer
                        .expect("missing key checksum has an issuer");
                    eprintln!("No key to check {} from {}", what, issuer);
                    self.unknown_checksums += 1;
                },
                BadChecksum(_) => {
                    if let Some(issuer) = issuer {
                        let issuer_str = format!("{}", issuer);
                        eprintln!("Bad {} from {}", what,
                                  self.labels.get(&issuer).unwrap_or(
                                      &issuer_str));
                    } else {
                        eprintln!("Bad {} without issuer information",
                                  what);
                    }
                    if trusted {
                        self.bad_signatures += 1;
                    } else {
                        self.bad_checksums += 1;
                    }
                },
            }
        }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        let mut tpks = self.tpks.take().unwrap();
        let seen: HashSet<_> = tpks.iter()
            .flat_map(|tpk| {
                // Even if a key is revoked or expired, we can still
                // use it to verify a message.
                tpk.keys_all().map(|(_, _, key)| key.fingerprint().to_keyid())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen.clone();

        // Try to get missing TPKs from the store.
        for id in ids.iter().filter(|i| !seen.contains(i)) {
            let _ =
                self.store.lookup_by_subkeyid(id)
                .and_then(|binding| {
                    self.labels.insert(id.clone(), binding.label()?);

                    // Keys from our store are trusted.
                    self.trusted.insert(id.clone());

                    binding.tpk()
                })
                .and_then(|tpk| {
                    tpks.push(tpk);
                    Ok(())
                });
        }

        // Update seen.
        let seen = self.trusted.clone();

        // Try to get missing TPKs from the pool.
        for id in ids.iter().filter(|i| !seen.contains(i)) {
            let _ =
                store::Pool::lookup_by_subkeyid(self.ctx, id)
                .and_then(|key| {
                    // Keys from the pool are NOT trusted.
                    key.tpk()
                })
                .and_then(|tpk| {
                    tpks.push(tpk);
                    Ok(())
                });
        }
        Ok(tpks)
    }

    fn check(&mut self, structure: &MessageStructure) -> Result<()> {
        for layer in structure.iter() {
            match layer {
                MessageLayer::Compression { algo } =>
                    eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } =>
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    },
                MessageLayer::SignatureGroup { ref results } =>
                    self.print_sigs(results),
            }
        }

        if self.good_signatures >= self.signatures
            && self.bad_signatures + self.bad_checksums == 0 {
            Ok(())
        } else {
            self.print_status();
            Err(failure::err_msg("Verification failed"))
        }
    }
}

pub fn verify(ctx: &Context, store: &mut store::Store,
              input: &mut io::Read,
              detached: Option<&mut io::Read>,
              output: &mut io::Write,
              signatures: usize, tpks: Vec<TPK>)
              -> Result<()> {
    let helper = VHelper::new(ctx, store, signatures, tpks);
    let mut verifier = if let Some(dsig) = detached {
        DetachedVerifier::from_reader(dsig, input, helper, None)?
    } else {
        Verifier::from_reader(input, helper, None)?
    };

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
        if let Some(ref map) = pp.map() {
            let filename = format!(
                "{}{}--{:?}", prefix,
                pos.iter().map(|n| format!("{}", n))
                    .collect::<Vec<String>>().join("-"),
                pp.packet.tag());
            let mut sink = File::create(filename)
                .context("Failed to create output file")?;

            // Write all the bytes.
            for field in map.iter() {
                sink.write_all(field.data())?;
            }
        }

        ppr = pp.recurse()?.1;
        let old_depth = ppr.last_recursion_depth();
        let new_depth = ppr.recursion_depth();

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

/// Joins the given files.
pub fn join(inputs: Option<clap::Values>, output: &mut io::Write)
            -> Result<()> {
    /// Writes a bit-accurate copy of all top-level packets in PPR to
    /// OUTPUT.
    fn copy(mut ppr: PacketParserResult, output: &mut io::Write)
            -> Result<()> {
        while let PacketParserResult::Some(pp) = ppr {
            // We (ab)use the mapping feature to create byte-accurate
            // copies.
            for field in pp.map().expect("must be mapped").iter() {
                output.write_all(field.data())?;
            }

            ppr = pp.next()?.1;
        }
        Ok(())
    }

    if let Some(inputs) = inputs {
        for name in inputs {
            let ppr =
                openpgp::parse::PacketParserBuilder::from_file(name)?
                .map(true).finalize()?;
            copy(ppr, output)?;
        }
    } else {
        let ppr =
            openpgp::parse::PacketParserBuilder::from_reader(io::stdin())?
            .map(true).finalize()?;
        copy(ppr, output)?;
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
