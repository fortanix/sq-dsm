//! An implementation of the Stateless OpenPGP Command Line Interface
//! using Sequoia.
//!
//! This implements a subset of the [Stateless OpenPGP Command Line
//! Interface] using the Sequoia OpenPGP implementation.
//!
//!   [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{self, Read, Write};

use anyhow::Context;
use structopt::StructOpt;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    Cert,
    Fingerprint,
    KeyID,
    KeyHandle,
    Packet,
};
use openpgp::crypto::{self, Password, SessionKey};
use openpgp::fmt::hex;
use openpgp::types::*;
use openpgp::packet::{key, signature, Key, PKESK, SKESK};
use openpgp::parse::{Parse, PacketParser, PacketParserResult, stream::*};
use openpgp::policy::Policy;
use openpgp::cert::prelude::*;
use openpgp::serialize::{
    Serialize,
    stream::*,
    stream::padding::{Padder, padme},
};
use openpgp::policy::StandardPolicy;

mod errors;
use errors::{Error, print_error_chain};
type Result<T> = anyhow::Result<T>;

mod cli;
use cli::{
    SOP, SignAs, EncryptAs, ArmorKind,
    load_file, create_file, load_certs, frob_passwords,
};
mod dates;

fn main() {
    use std::process::exit;

    match real_main() {
        Ok(()) => (),
        Err(e) => {
            print_error_chain(&e);
            if let Ok(e) = e.downcast::<Error>() {
                exit(e.into())
            }
            exit(1);
        },
    }
}

fn real_main() -> Result<()> {
    let p = &StandardPolicy::default();

    match SOP::from_args() {
        SOP::Version {} => {
            println!("Sequoia-SOP {}", openpgp::VERSION);
        },

        SOP::GenerateKey { no_armor, mut userids, } => {
            userids.reverse();
            let mut builder = CertBuilder::general_purpose(None, userids.pop());
            for u in userids {
                builder = builder.add_userid(u);
            }
            let (cert, _) = builder.generate()?;

            let mut sink = stdout(no_armor, armor::Kind::SecretKey)?;
            cert.as_tsk().serialize(&mut sink)?;
            sink.finalize()?;
        },

        SOP::ExtractCert { no_armor, } => {
            let cert = Cert::from_reader(&mut io::stdin())?;
            let mut sink = stdout(no_armor, armor::Kind::SecretKey)?;
            cert.serialize(&mut sink)?;
            sink.finalize()?;
        },

        SOP::Sign { no_armor, as_, keys, } => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            if let SignAs::Text = as_ {
                if let Err(e) = std::str::from_utf8(&data) {
                    return Err(anyhow::Error::from(Error::ExpectedText))
                        .context(e.to_string());
                }
            }

            let tsks = load_certs(keys)?;
            if tsks.is_empty() {
                return Err(anyhow::Error::from(Error::MissingArg))
                    .context("Expected at least one certificate");
            }
            let mut signers = Vec::new();
            let mut hash_algos = vec![
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA224,
                HashAlgorithm::RipeMD,
                HashAlgorithm::SHA1,
                HashAlgorithm::MD5,
            ];
            for tsk in tsks {
                let tsk = tsk.with_policy(p, None).map_err(|e| {
                    anyhow::Error::from(Error::CertCannotEncrypt) // XXX
                        .context(format!("Key {} not valid: {}", tsk, e))
                })?;
                if let Some(p) = tsk.preferred_hash_algorithms() {
                    hash_algos.retain(|a| p.contains(a));
                }

                let mut one = false;
                for key in tsk.keys()
                    .secret()
                    .alive()
                    .revoked(false)
                    .for_signing()
                    .map(|ka| ka.key())
                {
                    if key.secret().is_encrypted() {
                        return Err(Error::KeyIsProtected.into());
                    }
                    signers.push(key.clone().into_keypair()
                                 .expect("not encrypted"));
                    one = true;
                    // Exactly one signature per supplied key.
                    break;
                }

                if ! one {
                    return Err(anyhow::Error::from(Error::CertCannotEncrypt))
                        .context(format!("Cert {} not capable of signing",
                                         tsk));
                }
            }

            let message = stdout(no_armor, armor::Kind::Signature)?;
            let mut signer = Signer::with_template(
                message, signers.pop().expect("at least one"),
                signature::SignatureBuilder::new(as_.into()))
                .hash_algo(hash_algos.get(0).cloned().unwrap_or_default())?
                .detached();
            for s in signers {
                signer = signer.add_signer(s);
            }
            let mut message = signer.build()?;
            message.write_all(&data)?;
            message.finalize()?;
        },

        SOP::Verify { not_before, not_after, signatures, certs, } => {
            let certs = load_certs(certs)?;
            let signatures = load_file(signatures)?;
            let helper = VHelper::new(io::stdout(),
                                      1,
                                      not_before.map(|d| d.into()),
                                      not_after.map(|d| d.into()),
                                      certs);
            let mut v =
                DetachedVerifierBuilder::from_reader(signatures)?
                .with_policy(p, None, helper)?;
            v.verify_reader(io::stdin())?;
        },

        SOP::Encrypt { no_armor, as_, with_password, sign_with, certs, } =>
        {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            if let EncryptAs::Text = as_ {
                if let Err(e) = std::str::from_utf8(&data) {
                    return Err(anyhow::Error::from(Error::ExpectedText))
                        .context(e.to_string());
                }
            }

            let passwords = frob_passwords(with_password)?;

            let tsks = load_certs(sign_with)?;
            let mut signers = Vec::new();
            for tsk in tsks {
                let mut one = false;
                for key in tsk.keys().with_policy(p, None)
                    .secret()
                    .alive()
                    .revoked(false)
                    .for_signing()
                    .map(|ka| ka.key())
                {
                    if key.secret().is_encrypted() {
                        return Err(Error::KeyIsProtected.into());
                    }
                    signers.push(key.clone().into_keypair()
                                 .expect("not encrypted"));
                    one = true;
                    // Exactly one signature per supplied key.
                    break;
                }

                if ! one {
                    return Err(anyhow::Error::from(Error::CertCannotEncrypt)) // XXX
                        .context(format!("Cert {} not capable of signing",
                                         tsk));
                }
            }

            let certs = load_certs(certs)?;

            if certs.is_empty() && passwords.is_empty() {
                return Err(anyhow::Error::from(Error::MissingArg))
                        .context("Neither passwords or certs given");
            }

            // Compute recipients and algorithms.
            let mut recipients: Vec<Recipient> = Vec::new();
            // Somewhat arbitrary order of preference.
            let mut hash_algos = vec![
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA224,
                HashAlgorithm::RipeMD,
                HashAlgorithm::SHA1,
                HashAlgorithm::MD5,
            ];
            let mut symmetric_algos = vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES192,
                SymmetricAlgorithm::AES128,
                SymmetricAlgorithm::Camellia256,
                SymmetricAlgorithm::Camellia192,
                SymmetricAlgorithm::Camellia128,
                SymmetricAlgorithm::Blowfish,
                SymmetricAlgorithm::Twofish,
                SymmetricAlgorithm::CAST5,
                SymmetricAlgorithm::IDEA,
                SymmetricAlgorithm::TripleDES,
            ];
            let mut aead_algos = vec![
                AEADAlgorithm::EAX,
                AEADAlgorithm::OCB,
            ];
            for cert in certs.iter() {
                let cert = cert.with_policy(p, None).map_err(|e| {
                    anyhow::Error::from(Error::CertCannotEncrypt)
                        .context(format!("Cert {} not valid: {}", cert, e))
                })?;

                // If the recipients has preferences, compute the
                // intersection with our list.
                if let Some(p) = cert.preferred_hash_algorithms() {
                    hash_algos.retain(|a| p.contains(a));
                }
                if let Some(p) = cert.preferred_symmetric_algorithms() {
                    symmetric_algos.retain(|a| p.contains(a));
                }
                if let Some(p) = cert.preferred_aead_algorithms() {
                    aead_algos.retain(|a| p.contains(a));
                }

                // If the cert doesn't advertise support for AEAD,
                // disable it.
                if ! cert.features().map(|f| f.supports_aead()).unwrap_or(false)
                {
                    aead_algos.clear();
                }

                let mut one = false;
                for key in cert.keys()
                    .alive()
                    .revoked(false)
                    .for_storage_encryption()
                    .for_transport_encryption()
                    .map(|ka| ka.key())
                {
                    recipients.push(key.into());
                    one = true;
                }
                if ! one {
                    return Err(anyhow::Error::from(Error::CertCannotEncrypt))
                        .context(format!("Cert {} not capable of encryption",
                                         cert));
                }
            }

            let message = stdout(no_armor, armor::Kind::Message)?;

            // Encrypt the message.
            let mut encryptor =
                Encryptor::for_recipients(message, recipients)
                .add_passwords(passwords)
                .symmetric_algo(
                    symmetric_algos.get(0).cloned().unwrap_or_default());
            if let Some(&a) = aead_algos.get(0) {
                encryptor = encryptor.aead_algo(a);
            }
            let message = encryptor.build()
                .context("Failed to create encryptor")?;

            // Pad the message.
            let mut message = Padder::new(message, padme)?;

            // Maybe sign the message.
            if let Some(s) = signers.pop() {
                let mut signer = Signer::with_template(
                    message, s, signature::SignatureBuilder::new(as_.into()))
                    .hash_algo(hash_algos.get(0).cloned()
                               .unwrap_or_default())?;
                for s in signers {
                    signer = signer.add_signer(s);
                }
                for r in certs.iter() {
                    signer = signer.add_intended_recipient(r);
                }
                message = signer.build()?;
            }

            // Literal wrapping.
            let mut message = LiteralWriter::new(message)
                .format(as_.into())
                .build()?;
            message.write_all(&data)?;
            message.finalize()?;
        },

        SOP::Decrypt {
            session_key_out,
            with_session_key,
            with_password,
            verify_out,
            verify_with,
            verify_not_before,
            verify_not_after,
            key,
        } => {
            let session_key_out: Box<dyn io::Write> =
                if let Some(f) = session_key_out {
                    Box::new(create_file(f)?)
                } else {
                    Box::new(io::sink())
                };

            let mut session_keys: Vec<SessionKey> = Vec::new();
            for sk in with_session_key {
                // The SOP format is:
                //
                //   <decimal-cipher-octet> ":" <session-key>
                //
                // For robustness, and because we can, we just care
                // about the session key.

                // Strip anything before the colon, ignore whitespace.
                session_keys.push(
                    hex::decode_pretty(sk.rsplit(':').nth(0).unwrap())
                        .context("Failed to parse session key")?.into());
            }

            let passwords = frob_passwords(with_password)?;

            if verify_out.is_none() != verify_with.is_empty() {
                return Err(anyhow::Error::from(Error::IncompleteVerification))
                    .context("--verify-out and --verify-with \
                              must both be given");
            }

            let verify_out: Box<dyn io::Write> =
                if let Some(f) = verify_out {
                    Box::new(create_file(f)?)
                } else {
                    Box::new(io::sink())
                };

            let verify_with = load_certs(verify_with)?;
            let keys = load_certs(key)?;

            let vhelper = VHelper::new(verify_out,
                                       if verify_with.is_empty() {
                                           0
                                       } else {
                                           1
                                       },
                                       verify_not_before.map(|d| d.into()),
                                       verify_not_after.map(|d| d.into()),
                                       verify_with);
            let helper = Helper::new(p, vhelper, session_keys, passwords, keys,
                                     session_key_out);
            let mut v =DecryptorBuilder::from_reader(io::stdin())?
                .with_policy(p, None, helper)?;
            io::copy(&mut v, &mut io::stdout())?;
        },

        SOP::Armor { label, } => {
            // We make no effort to verify the packet structure.
            let mut ppr = PacketParser::from_reader(io::stdin())?;
            let mut sink = match label {
                ArmorKind::Auto => None,
                ArmorKind::Sig =>
                    Some(stdout(false, armor::Kind::Signature)?),
                ArmorKind::Key =>
                    Some(stdout(false, armor::Kind::SecretKey)?),
                ArmorKind::Cert =>
                    Some(stdout(false, armor::Kind::PublicKey)?),
                ArmorKind::Message =>
                    Some(stdout(false, armor::Kind::Message)?),
            };

            while let PacketParserResult::Some(pp) = ppr {
                let (packet, tmp) = pp.next()?;
                ppr = tmp;

                if sink.is_none() {
                    // Autodetect using the first packet.
                    sink = match packet {
                        Packet::Signature(_) =>
                            Some(stdout(false, armor::Kind::Signature)?),
                        Packet::SecretKey(_) =>
                            Some(stdout(false, armor::Kind::SecretKey)?),
                        Packet::PublicKey(_) =>
                            Some(stdout(false, armor::Kind::PublicKey)?),
                        Packet::PKESK(_) | Packet::SKESK(_) =>
                            Some(stdout(false, armor::Kind::Message)?),
                        _ => return Err(anyhow::Error::from(Error::BadData))
                            .context(format!("Unexpected first packet: {}",
                                             packet.tag())),
                    };
                }
                packet.serialize(sink.as_mut().expect("valid at this point"))?;
            }

            sink.expect("valid at this point").finalize()?;
        },

        SOP::Dearmor {} => {
            // We make no effort to verify the packet structure.
            let mut ppr = PacketParser::from_reader(io::stdin())?;
            let mut sink = io::stdout();
            while let PacketParserResult::Some(pp) = ppr {
                let (packet, tmp) = pp.next()?;
                ppr = tmp;
                packet.serialize(&mut sink)?;
            }
        },

        SOP::Unsupported(args) => {
            return Err(anyhow::Error::from(Error::UnsupportedSubcommand))
                .context(format!("Subcommand {} is not supported", args[0]));
        },
    }
    Ok(())
}

fn stdout<'a>(binary: bool, kind: armor::Kind) -> Result<Message<'a>> {
    let mut message = Message::new(io::stdout());
    if ! binary {
        message = Armorer::new(message).kind(kind).build()?;
    }
    Ok(message)
}

struct VHelper<'a> {
    verify_out: Box<dyn io::Write + 'a>,
    not_before: Option<std::time::SystemTime>,
    not_after: Option<std::time::SystemTime>,

    good: usize,
    total: usize,
    threshold: usize,

    keyring: Vec<Cert>,
}

impl<'a> std::fmt::Debug for VHelper<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("VHelper")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("good", &self.good)
            .field("total", &self.total)
            .field("threshold", &self.threshold)
            .field("keyring", &self.keyring)
            .finish()
    }
}

impl<'a> VHelper<'a> {
    fn new<W>(verify_out: W,
              threshold: usize,
              not_before: Option<std::time::SystemTime>,
              not_after: Option<std::time::SystemTime>,
              keyring: Vec<Cert>) -> Self
        where W: io::Write + 'a
    {
        VHelper {
            verify_out: Box::new(verify_out),
            not_before,
            not_after,
            good: 0,
            total: 0,
            threshold,
            keyring,
        }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, _: &[crate::KeyHandle])
                 -> openpgp::Result<Vec<Cert>> {
        Ok(std::mem::replace(&mut self.keyring, Default::default()))
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        use self::VerificationError::*;

        let mut signers = Vec::with_capacity(2);
        let mut verification_err = None;

        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } =>
                    for result in results {
                        self.total += 1;
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                let t = match sig.signature_creation_time() {
                                    Some(t) => t,
                                    None => {
                                        eprintln!("Malformed signature:");
                                        print_error_chain(&anyhow::anyhow!(
                                            "no signature creation time"));
                                        continue;
                                    },
                                };

                                if let Some(not_before) = self.not_before {
                                    if t < not_before {
                                        eprintln!(
                                            "Signature by {:X} was created before \
                                             the --not-before date.",
                                            ka.key().fingerprint());
                                        continue;
                                    }
                                }

                                if let Some(not_after) = self.not_after {
                                    if t > not_after {
                                        eprintln!(
                                            "Signature by {:X} was created after \
                                             the --not-after date.",
                                            ka.key().fingerprint());
                                        continue;
                                    }
                                }

                                signers.push((t, ka.fingerprint(), ka.cert().fingerprint()));
                            },
                            Err(MalformedSignature { error, .. }) => {
                                eprintln!("Signature is malformed:");
                                print_error_chain(&error);
                            },
                            Err(MissingKey { sig, .. }) => {
                                let issuers = sig.get_issuers();
                                eprintln!("Missing key {:X}, which is needed to \
                                           verify signature.",
                                          issuers.first().unwrap());
                            },
                            Err(UnboundKey { cert, error, .. }) => {
                                eprintln!("Signing key on {:X} is not bound:",
                                          cert.fingerprint());
                                print_error_chain(&error);
                            },
                            Err(BadKey { ka, error, .. }) => {
                                eprintln!("Signing key on {:X} is bad:",
                                          ka.cert().fingerprint());
                                print_error_chain(&error);
                            },
                            Err(BadSignature { error, .. }) => {
                                eprintln!("Verifying signature:");
                                print_error_chain(&error);
                                if verification_err.is_none() {
                                    verification_err = Some(error)
                                }
                            },
                        }
                    }
                MessageLayer::Compression { .. } => (),
                MessageLayer::Encryption { .. } => (),
            }
        }

        // Dedup the keys so that it is not possible to exceed the
        // threshold by duplicating signatures or by using the same
        // key.
        signers.sort();
        signers.dedup();

        self.good = signers.len();
        for (t, key, cert) in signers {
            writeln!(self.verify_out, "{} {:X} {:X}",
                     Timestamp::try_from(t).expect("representable"), key, cert)?;
        }

        if self.good >= self.threshold {
            Ok(())
        } else {
            Err(Error::NoSignature.into())
        }
    }
}

struct Helper<'a> {
    vhelper: VHelper<'a>,
    session_keys: Vec<SessionKey>,
    passwords: Vec<Password>,
    secret_keys:
        HashMap<KeyID, Key<key::SecretParts, key::UnspecifiedRole>>,
    identities: HashMap<KeyID, Fingerprint>,
    dump_session_key_out: Box<dyn io::Write + 'a>,
}

impl<'a> Helper<'a> {
    fn new<W>(policy: &'a dyn Policy,
              vhelper: VHelper<'a>,
              session_keys: Vec<SessionKey>,
              passwords: Vec<Password>,
              secrets: Vec<Cert>,
              dump_session_key_out: W) -> Self
        where W: io::Write + 'a
    {
        let mut secret_keys = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        for tsk in secrets {
            for ka in tsk.keys().secret()
                .with_policy(policy, None)
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                secret_keys.insert(id.clone(), ka.key().clone().into());
                identities.insert(id.clone(), tsk.fingerprint());
            }
        }

        Helper {
            vhelper,
            session_keys,
            passwords,
            secret_keys,
            identities,
            dump_session_key_out: Box::new(dump_session_key_out),
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      algo: Option<SymmetricAlgorithm>,
                      keypair: &mut dyn crypto::Decryptor,
                      decrypt: &mut D)
                      -> Option<(SymmetricAlgorithm,
                                 SessionKey,
                                 Option<Fingerprint>)>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        let keyid = keypair.public().fingerprint().into();
        let (algo, sk) = pkesk.decrypt(keypair, algo)
            .and_then(|(algo, sk)| {
                decrypt(algo, &sk).ok()?; Some((algo, sk))
            })?;

        Some((algo, sk, self.identities.get(&keyid).map(|fp| fp.clone())))
    }

    /// Dumps the session key.
    fn dump_session_key(&mut self, algo: SymmetricAlgorithm, sk: &SessionKey)
                        -> Result<()> {
        write!(&mut self.dump_session_key_out, "{}:{}",
               u8::from(algo), hex::encode(sk))?;
        Ok(())
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        // First, try all supplied session keys.
        while let Some(sk) = self.session_keys.pop() {
            for algo in (1..20u8).map(|n| SymmetricAlgorithm::from(n))
                .filter(|a| a.key_size().map(|size| size == sk.len())
                        .unwrap_or(false))
            {
                if decrypt(algo, &sk).is_ok() {
                    self.dump_session_key(algo, &sk)?;
                    return Ok(None);
                }
            }
        }

        // Second, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get(&keyid) {
                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for key in self.secret_keys.values() {
                if ! key.secret().is_encrypted() {
                    if let Some((algo, sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.dump_session_key(algo, &sk)?;
                        return Ok(fp);
                    }
                }
            }
        }

        if skesks.is_empty() {
            return
                Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.
        for password in self.passwords.iter() {
            for skesk in skesks {
                if let Ok((algo, sk)) = skesk.decrypt(password)
                    .and_then(|(algo, sk)| {
                        decrypt(algo, &sk)?;
                        Ok((algo, sk))
                    })
                {
                    self.dump_session_key(algo, &sk)?;
                    return Ok(None);
                }
            }
        }

        Err(Error::CannotDecrypt.into())
    }
}
