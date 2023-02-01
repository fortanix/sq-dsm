use anyhow::Context as _;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::time::SystemTime;

use sequoia_net::pks;
use sequoia_openpgp as openpgp;
use crate::openpgp::{
    armor,
};
use crate::openpgp::types::{
    CompressionAlgorithm,
};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::crypto;
use crate::openpgp::{Cert, KeyID, Result};
use crate::openpgp::packet::prelude::*;
use crate::openpgp::parse::{
    Parse,
    PacketParserResult,
};
use crate::openpgp::parse::stream::*;
use crate::openpgp::serialize::stream::{
    Message, Signer, LiteralWriter, Encryptor, Recipient,
    Compressor,
    padding::Padder,
};
use crate::openpgp::policy::Policy;
use openpgp_dsm::DsmAgent;

use crate::{
    Config,
    parse_armor_kind,
};

use crate::secrets::{PreSecret, Secret};

#[cfg(feature = "autocrypt")]
pub mod autocrypt;
pub mod decrypt;
pub use self::decrypt::decrypt;
pub mod sign;
pub use self::sign::sign;
pub mod dump;
pub use self::dump::dump;
mod inspect;
pub use self::inspect::inspect;
pub mod key;
pub mod merge_signatures;
pub use self::merge_signatures::merge_signatures;
pub mod keyring;
#[cfg(feature = "net")]
pub mod net;
pub mod certify;

/// Returns suitable signing keys from a given list of Certs.
#[allow(clippy::never_loop)]
fn get_signing_keys(presecrets: &[PreSecret], p: &dyn Policy,
                    private_key_store: Option<&str>,
                    timestamp: Option<SystemTime>)
    -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>>
{
    let mut keys: Vec<Box<dyn crypto::Signer + Send + Sync>> = Vec::new();
    'next_cert: for presecret in presecrets {
        match presecret {
            PreSecret::Dsm(credentials, name) => {
                keys.push(Box::new(Secret::Dsm(DsmAgent::new_signer(credentials.clone(), name)?)));
            }
            PreSecret::InMemory(tsk) => {
                for key in tsk.keys().with_policy(p, timestamp).alive().revoked(false)
                    .for_signing()
                        .supported()
                        .map(|ka| ka.key())
                        {
                            if let Some(secret) = key.optional_secret() {
                                let unencrypted = match secret {
                                    SecretKeyMaterial::Encrypted(ref e) => {
                                        let password = rpassword::read_password_from_tty(Some(
                                                &format!("Please enter password to decrypt {}/{}: ",
                                                    tsk, key)))
                                            .context("Reading password from tty")?;
                                        e.decrypt(key.pk_algo(), &password.into())
                                            .expect("decryption failed")
                                    },
                                    SecretKeyMaterial::Unencrypted(ref u) => u.clone(),
                                };

                                keys.push(Box::new(Secret::InMemory(
                                        crypto::KeyPair::new(key.clone(), unencrypted)
                                            .unwrap())));
                                            break 'next_cert;
                            } else if let Some(private_key_store) = private_key_store {
                                let password = rpassword::read_password_from_tty(
                                    Some(&format!("Please enter password to key {}/{}: ", tsk, key))).unwrap().into();
                                match pks::unlock_signer(private_key_store, key.clone(), &password) {
                                    Ok(signer) => {
                                        keys.push(signer);
                                        break 'next_cert;
                                    },
                                    Err(error) => eprintln!("Could not unlock signer: {:?}", error),
                                }
                            }
                            return Err(anyhow::anyhow!(
                                    format!("Found no suitable signing key on {}", tsk)));
                        }
            }
        }
    }

    Ok(keys)
}

pub struct EncryptOpts<'a> {
    pub policy: &'a dyn Policy,
    pub private_key_store: Option<&'a str>,
    pub input: &'a mut dyn io::Read,
    pub message: Message<'a>,
    pub npasswords: usize,
    pub recipients: &'a [openpgp::Cert],
    pub signers: Vec<PreSecret>,
    pub mode: openpgp::types::KeyFlags,
    pub compression: &'a str,
    pub time: Option<SystemTime>,
    pub use_expired_subkey: bool,
}

pub fn encrypt(opts: EncryptOpts) -> Result<()> {
    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(opts.npasswords);
    for n in 0..opts.npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::read_password_from_tty(Some(
            if opts.npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            }))?.into());
    }

    if opts.recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mut signers = get_signing_keys(&opts.signers, opts.policy,
				       opts.private_key_store, opts.time)?;

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for cert in opts.recipients.iter() {
        let mut count = 0;
        for key in cert.keys().with_policy(opts.policy, None).alive().revoked(false)
            .key_flags(&opts.mode).supported().map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            let mut expired_keys = Vec::new();
            for ka in cert.keys().with_policy(opts.policy, None).revoked(false)
                .key_flags(&opts.mode).supported()
            {
                let key = ka.key();
                expired_keys.push(
                    (ka.binding_signature().key_expiration_time(key)
                         .expect("Key must have an expiration time"),
                     key));
            }
            expired_keys.sort_by_key(|(expiration_time, _)| *expiration_time);

            if let Some((expiration_time, key)) = expired_keys.last() {
                if opts.use_expired_subkey {
                    recipient_subkeys.push((*key).into());
                } else {
                    use chrono::{DateTime, offset::Utc};
                    return Err(anyhow::anyhow!(
                        "The last suitable encryption key of cert {} expired \
                         on {}\n\
                         Hint: Use --use-expired-subkey to use it anyway.",
                        cert,
                        DateTime::<Utc>::from(*expiration_time)));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Cert {} has no suitable encryption key", cert));
            }
        }
    }

    // We want to encrypt a literal data packet.
    let encryptor =
        Encryptor::for_recipients(opts.message, recipient_subkeys)
        .add_passwords(passwords);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match opts.compression {
        "none" => (),
        "pad" => sink = Padder::new(sink).build()?,
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
            if let Some(time) = opts.time {
                signer = signer.creation_time(time);
            }
        }
        for r in opts.recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let mut literal_writer = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(opts.input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(())
}

struct VHelper<'a> {
    #[allow(dead_code)]
    config: Config<'a>,
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
    fn new(config: &Config<'a>, signatures: usize,
           certs: Vec<Cert>)
           -> Self {
        VHelper {
            config: config.clone(),
            signatures,
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
        use crate::print_error_chain;
        use self::VerificationError::*;
        for result in results {
            let (issuer, level) = match result {
                Ok(GoodChecksum { sig, ka, .. }) =>
                    (ka.key().keyid(), sig.level()),
                Err(MalformedSignature { error, .. }) => {
                    eprintln!("Malformed signature:");
                    print_error_chain(error);
                    self.broken_signatures += 1;
                    continue;
                },
                Err(MissingKey { sig, .. }) => {
                    let issuer = sig.get_issuers().get(0)
                        .expect("missing key checksum has an issuer")
                        .to_string();
                    let what = match sig.level() {
                        0 => "checksum".into(),
                        n => format!("level {} notarizing checksum", n),
                    };
                    eprintln!("No key to check {} from {}", what, issuer);
                    self.unknown_checksums += 1;
                    continue;
                },
                Err(UnboundKey { cert, error, .. }) => {
                    eprintln!("Signing key on {} is not bound:",
                              cert.fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadKey { ka, error, .. }) => {
                    eprintln!("Signing key on {} is bad:",
                              ka.cert().fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadSignature { sig, ka, error }) => {
                    let issuer = ka.fingerprint().to_string();
                    let what = match sig.level() {
                        0 => "checksum".into(),
                        n => format!("level {} notarizing checksum", n),
                    };
                    eprintln!("Error verifying {} from {}:",
                              what, issuer);
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                }
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
            eprintln!("Good {} from {}", what, label);
            if trusted {
                self.good_signatures += 1;
            } else {
                self.good_checksums += 1;
            }
        }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let certs = self.certs.take().unwrap();
        // Get all keys.
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen;

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
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
            Err(anyhow::anyhow!("Verification failed"))
        }
    }
}

pub fn verify(config: Config,
              input: &mut (dyn io::Read + Sync + Send),
              detached: Option<&mut (dyn io::Read + Sync + Send)>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let helper = VHelper::new(&config, signatures, certs);
    let helper = if let Some(dsig) = detached {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(&config.policy, None, helper)?;
        v.verify_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(&config.policy, None, helper)?;
        io::copy(&mut v, output)?;
        v.into_helper()
    };

    helper.print_status();
    Ok(())
}

pub fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str)
             -> Result<()> {
    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).build()?;

    // This encodes our position in the tree.
    let mut pos = vec![0];

    while let PacketParserResult::Some(pp) = ppr {
        if let Some(map) = pp.map() {
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
                sink.write_all(field.as_bytes())?;
            }
        }

        let old_depth = Some(pp.recursion_depth());
        ppr = pp.recurse()?.1;
        let new_depth = ppr.as_ref().map(|pp| pp.recursion_depth()).ok();

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
pub fn join(config: Config, m: &clap::ArgMatches)
            -> Result<()> {
    // Either we know what kind of armor we want to produce, or we
    // need to detect it using the first packet we see.
    let kind = parse_armor_kind(m.value_of("kind"));
    let output = m.value_of("output");
    let mut sink =
        if m.is_present("binary") {
            // No need for any auto-detection.
            Some(config.create_or_stdout_pgp(output,
                                             true, // Binary.
                                             armor::Kind::File)?)
        } else if let Some(kind) = kind {
            Some(config.create_or_stdout_pgp(output,
                                             false, // Armored.
                                             kind)?)
        } else {
            None // Defer.
        };

    /// Writes a bit-accurate copy of all top-level packets in PPR to
    /// OUTPUT.
    fn copy(config: &Config,
            mut ppr: PacketParserResult,
            output: Option<&str>,
            sink: &mut Option<Message>)
            -> Result<()> {
        while let PacketParserResult::Some(pp) = ppr {
            if sink.is_none() {
                // Autodetect using the first packet.
                let kind = match pp.packet {
                    Packet::Signature(_) => armor::Kind::Signature,
                    Packet::SecretKey(_) => armor::Kind::SecretKey,
                    Packet::PublicKey(_) => armor::Kind::PublicKey,
                    Packet::PKESK(_) | Packet::SKESK(_) =>
                        armor::Kind::Message,
                    _ => armor::Kind::File,
                };

                *sink = Some(config.create_or_stdout_pgp(output,
                                                         false, // Armored.
                                                         kind)?);
            }

            // We (ab)use the mapping feature to create byte-accurate
            // copies.
            for field in pp.map().expect("must be mapped").iter() {
                sink.as_mut().expect("initialized at this point")
                    .write_all(field.as_bytes())?;
            }

            ppr = pp.next()?.1;
        }
        Ok(())
    }

    if let Some(inputs) = m.values_of("input") {
        for name in inputs {
            let ppr =
                openpgp::parse::PacketParserBuilder::from_file(name)?
                .map(true).build()?;
            copy(&config, ppr, output, &mut sink)?;
        }
    } else {
        let ppr =
            openpgp::parse::PacketParserBuilder::from_reader(io::stdin())?
            .map(true).build()?;
        copy(&config, ppr, output, &mut sink)?;
    }

    sink.unwrap().finalize()?;
    Ok(())
}
