use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use rpassword;

extern crate sequoia_openpgp as openpgp;
use sequoia_core::Context;
use crate::openpgp::types::{
    CompressionAlgorithm,
};
use crate::openpgp::crypto;
use crate::openpgp::{Cert, KeyID, Result};
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

pub mod decrypt;
pub use self::decrypt::decrypt;
mod sign;
pub use self::sign::sign;
pub mod dump;
use dump::Convert;
pub use self::dump::dump;
mod inspect;
pub use self::inspect::inspect;
pub mod key;

/// Returns suitable signing keys from a given list of Certs.
fn get_signing_keys(certs: &[openpgp::Cert])
    -> Result<Vec<crypto::KeyPair>>
{
    let mut keys = Vec::new();
    'next_cert: for tsk in certs {
        for key in tsk.keys().policy(None).alive().revoked(false)
            .for_signing()
            .map(|ka| ka.key())
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
                break 'next_cert;
            }
        }

        return Err(failure::err_msg(
            format!("Found no suitable signing key on {}", tsk)));
    }

    Ok(keys)
}

pub fn encrypt(mapping: &mut store::Mapping,
               input: &mut dyn io::Read, output: &mut dyn io::Write,
               npasswords: usize, recipients: Vec<&str>,
               mut certs: Vec<openpgp::Cert>, signers: Vec<openpgp::Cert>,
               mode: openpgp::types::KeyFlags,
               compression: &str)
               -> Result<()> {
    for r in recipients {
        certs.push(mapping.lookup(r).context("No such key found")?.cert()?);
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

    if certs.len() + passwords.len() == 0 {
        return Err(failure::format_err!(
            "Neither recipient nor password given"));
    }

    let mut signers = get_signing_keys(&signers)?;

    // Build a vector of references to hand to Signer.
    let recipients: Vec<&openpgp::Cert> = certs.iter().collect();

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for cert in certs.iter() {
        let mut count = 0;
        for key in cert.keys().policy(None).alive().revoked(false)
            .key_flags(&mode).map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            return Err(failure::format_err!(
                "Key {} has no suitable encryption key", cert));
        }
    }

    // Stream an OpenPGP message.
    let message = Message::new(output);

    // We want to encrypt a literal data packet.
    let mut encryptor = if let Some(p) = passwords.pop() {
        Encryptor::with_password(message, p)
    } else {
        Encryptor::for_recipient(message, recipient_subkeys.pop().unwrap())
    };
    for p in passwords {
        encryptor = encryptor.add_password(p);
    }
    for r in recipient_subkeys {
        encryptor = encryptor.add_recipient(r);
    }

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match compression {
        "none" => (),
        "pad" => sink = Padder::new(sink, padme)?,
        "zip" => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
        "zlib" => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
        "bzip2" => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
        _ => unreachable!("all possible choices are handled")
    }

    // Optionally sign message.
    if ! signers.is_empty() {
        let mut signer = Signer::new(sink, signers.pop().unwrap());
        for s in signers {
            signer = signer.add_signer(s);
        }
        for r in recipients {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let mut literal_writer = LiteralWriter::new(sink).build()
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
    mapping: &'a mut store::Mapping,
    signatures: usize,
    certs: Option<Vec<Cert>>,
    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
    broken_signatures: usize,
}

impl<'a> VHelper<'a> {
    fn new(ctx: &'a Context, mapping: &'a mut store::Mapping, signatures: usize,
           certs: Vec<Cert>)
           -> Self {
        VHelper {
            ctx: ctx,
            mapping: mapping,
            signatures: signatures,
            certs: Some(certs),
            labels: HashMap::new(),
            trusted: HashSet::new(),
            good_signatures: 0,
            good_checksums: 0,
            unknown_checksums: 0,
            bad_signatures: 0,
            bad_checksums: 0,
            broken_signatures: 0,
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
        p(&mut dirty, "broken signatures", self.broken_signatures);
        if dirty {
            eprintln!(".");
        }
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) {
        use self::VerificationResult::*;
        for result in results {
            if let Error { sig, error } = result {
                let issuer = sig.get_issuers().iter().nth(0)
                    .expect("key has an issuer")
                    .to_string();
                let what = match sig.level() {
                    0 => "checksum".into(),
                    n => format!("level {} notarizing checksum", n),
                };
                eprintln!("Error verifying {} from {}: {}",
                          what, issuer, error);
                self.broken_signatures += 1;
                continue;
            }
            if let MissingKey { sig } = result {
                let issuer = sig.get_issuers().iter().nth(0)
                    .expect("missing key checksum has an issuer")
                    .to_string();
                let what = match sig.level() {
                    0 => "checksum".into(),
                    n => format!("level {} notarizing checksum", n),
                };
                eprintln!("No key to check {} from {}", what, issuer);
                self.unknown_checksums += 1;
                continue;
            }

            let (issuer, level) = match result {
                GoodChecksum { sig, ka, .. } =>
                    (ka.key().keyid(), sig.level()),
                NotAlive { sig, .. } =>
                    (sig.get_issuers().get(0)
                         .map(|i| i.into())
                         .unwrap_or(KeyID::wildcard()),
                     sig.level()),
                MissingKey { .. } => unreachable!("handled above"),
                Error { .. } => unreachable!("handled above"),
            };

            let trusted = self.trusted.contains(&issuer);
            let what = match (level == 0, trusted) {
                (true,  true)  => "signature".into(),
                (false, true)  => format!("level {} notarization", level),
                (true,  false) => "checksum".into(),
                (false, false) =>
                    format!("level {} notarizing checksum", level),
            };

            let issuer_str = issuer.to_string();
            let label = self.labels.get(&issuer).unwrap_or(&issuer_str);
            match result {
                GoodChecksum { .. } => {
                    eprintln!("Good {} from {}", what, label);
                    if trusted {
                        self.good_signatures += 1;
                    } else {
                        self.good_checksums += 1;
                    }
                },
                NotAlive { .. } => {
                    eprintln!("Good checksum, but not alive: {} from {}",
                              what, label);
                    if trusted {
                        self.bad_signatures += 1;
                    } else {
                        self.bad_checksums += 1;
                    }
                },
                MissingKey { .. } => unreachable!("handled above"),
                Error { .. } => unreachable!("handled above"),
            }
        }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_public_keys(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = self.certs.take().unwrap();
        // Get all keys.  Even if a key is revoked or expired, we can
        // still use it to verify a message.
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|key| key.fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen.clone();

        // Try to get missing Certs from the mapping.
        for id in ids.iter().map(|i| KeyID::from(i.clone()))
            .filter(|i| !seen.contains(i))
        {
            let _ =
                self.mapping.lookup_by_subkeyid(&id)
                .and_then(|binding| {
                    self.labels.insert(id.clone(), binding.label()?);

                    // Keys from our mapping are trusted.
                    self.trusted.insert(id.clone());

                    binding.cert()
                })
                .and_then(|cert| {
                    certs.push(cert);
                    Ok(())
                });
        }

        // Update seen.
        let seen = self.trusted.clone();

        // Try to get missing Certs from the pool.
        for id in ids.iter().map(|i| KeyID::from(i.clone()))
            .filter(|i| !seen.contains(i))
        {
            let _ =
                store::Store::lookup_by_subkeyid(self.ctx, &id)
                .and_then(|key| {
                    // Keys from the pool are NOT trusted.
                    key.cert()
                })
                .and_then(|cert| {
                    certs.push(cert);
                    Ok(())
                });
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
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

pub fn verify(ctx: &Context, mapping: &mut store::Mapping,
              input: &mut dyn io::Read,
              detached: Option<&mut dyn io::Read>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let helper = VHelper::new(ctx, mapping, signatures, certs);
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

pub fn split(input: &mut dyn io::Read, prefix: &str)
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
                "{}{}--{}{:?}", prefix,
                pos.iter().map(|n| format!("{}", n))
                    .collect::<Vec<String>>().join("-"),
                pp.packet.kind().map(|_| "").unwrap_or("Unknown-"),
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
pub fn join(inputs: Option<clap::Values>, output: &mut dyn io::Write)
            -> Result<()> {
    /// Writes a bit-accurate copy of all top-level packets in PPR to
    /// OUTPUT.
    fn copy(mut ppr: PacketParserResult, output: &mut dyn io::Write)
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

pub fn mapping_print_stats(mapping: &store::Mapping, label: &str) -> Result<()> {
    fn print_stamps(st: &store::Stamps) -> Result<()> {
        println!("{} messages using this key", st.count);
        if let Some(t) = st.first {
            println!("    First: {}", t.convert());
        }
        if let Some(t) = st.last {
            println!("    Last: {}", t.convert());
        }
        Ok(())
    }

    fn print_stats(st: &store::Stats) -> Result<()> {
        if let Some(t) = st.created {
            println!("  Created: {}", t.convert());
        }
        if let Some(t) = st.updated {
            println!("  Updated: {}", t.convert());
        }
        print!("  Encrypted ");
        print_stamps(&st.encryption)?;
        print!("  Verified ");
        print_stamps(&st.verification)?;
        Ok(())
    }

    let binding = mapping.lookup(label)?;
    println!("Binding {:?}", label);
    print_stats(&binding.stats().context("Failed to get stats")?)?;
    let key = binding.key().context("Failed to get key")?;
    println!("Key");
    print_stats(&key.stats().context("Failed to get stats")?)?;
    Ok(())
}
