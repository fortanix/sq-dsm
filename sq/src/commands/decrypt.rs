use anyhow::Context as _;
use std::collections::HashMap;
use std::io;
use rpassword;

use sequoia_openpgp as openpgp;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::fmt::hex;
use crate::openpgp::crypto::{self, SessionKey};
use crate::openpgp::{Fingerprint, Cert, KeyID, Result};
use crate::openpgp::packet;
use crate::openpgp::packet::prelude::*;
use crate::openpgp::parse::{
    Parse,
    PacketParser,
    PacketParserResult,
};
use crate::openpgp::parse::stream::{
    VerificationHelper, DecryptionHelper, DecryptorBuilder, MessageStructure,
};

use crate::{
    Config,
    commands::{
        dump::PacketDumper,
        VHelper,
    },
};

struct Helper<'a> {
    vhelper: VHelper<'a>,
    secret_keys:
        HashMap<KeyID, Key<key::SecretParts, key::UnspecifiedRole>>,
    key_identities: HashMap<KeyID, Fingerprint>,
    key_hints: HashMap<KeyID, String>,
    dump_session_key: bool,
    dumper: Option<PacketDumper>,
}

impl<'a> Helper<'a> {
    fn new(config: &Config<'a>,
           signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
           dump_session_key: bool, dump: bool)
           -> Self
    {
        let mut keys = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        for tsk in secrets {
            let hint = match tsk.with_policy(&config.policy, None)
                .and_then(|valid_cert| valid_cert.primary_userid()).ok()
            {
                Some(uid) => format!("{} ({})", uid.userid(),
                                     KeyID::from(tsk.fingerprint())),
                None => format!("{}", KeyID::from(tsk.fingerprint())),
            };

            for ka in tsk.keys()
            // XXX: Should use the message's creation time that we do not know.
                .with_policy(&config.policy, None)
                .for_transport_encryption().for_storage_encryption()
                .secret()
            {
                let id: KeyID = ka.key().fingerprint().into();
                keys.insert(id.clone(), ka.key().clone().into());
                identities.insert(id.clone(), tsk.fingerprint());
                hints.insert(id, hint.clone());
            }
        }

        Helper {
            vhelper: VHelper::new(config, signatures, certs),
            secret_keys: keys,
            key_identities: identities,
            key_hints: hints,
            dump_session_key: dump_session_key,
            dumper: if dump {
                let width = term_size::dimensions_stdout().map(|(w, _)| w)
                    .unwrap_or(80);
                Some(PacketDumper::new(width, false))
            } else {
                None
            },
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      sym_algo: Option<SymmetricAlgorithm>,
                      keypair: &mut dyn crypto::Decryptor,
                      decrypt: &mut D)
                      -> Option<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let keyid = keypair.public().fingerprint().into();
        match pkesk.decrypt(keypair, sym_algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some(sk) } else { None }
            })
        {
            Some(sk) => {
                if self.dump_session_key {
                    eprintln!("Session key: {}", hex::encode(&sk));
                }
                Some(self.key_identities.get(&keyid).map(|fp| fp.clone()))
            },
            None => None,
        }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        if let Some(dumper) = self.dumper.as_mut() {
            dumper.packet(&mut io::stderr(),
                          pp.recursion_depth() as usize,
                          pp.header().clone(), pp.packet.clone(),
                          pp.map().map(|m| m.clone()), None)?;
        }
        Ok(())
    }

    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        // First, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get(&keyid) {
                if ! key.secret().is_encrypted() {
                    if let Some(fp) = key.clone().into_keypair().ok()
                        .and_then(|mut k|
                                  self.try_decrypt(pkesk, sym_algo, &mut k, &mut decrypt))
                    {
                        return Ok(fp);
                    }
                }
            }
        }

        // Second, we try those keys that are encrypted.
        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get_mut(&keyid) {
                let mut keypair = loop {
                    if ! key.secret().is_encrypted() {
                        break key.clone().into_keypair().unwrap();
                    }

                    let p = rpassword::read_password_from_tty(Some(
                        &format!(
                            "Enter password to decrypt key {}: ",
                            self.key_hints.get(&keyid).unwrap())))?.into();

                    let algo = key.pk_algo();
                    if let Some(()) =
                        key.secret_mut().decrypt_in_place(algo, &p).ok() {
                        break key.clone().into_keypair().unwrap()
                    } else {
                        eprintln!("Bad password.");
                    }
                };

                if let Some(fp) =
                    self.try_decrypt(pkesk, sym_algo, &mut keypair,
                                     &mut decrypt)
                {
                    return Ok(fp);
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for key in self.secret_keys.values() {
                if ! key.secret().is_encrypted() {
                    if let Some(fp) = key.clone().into_keypair().ok()
                        .and_then(|mut k|
                                  self.try_decrypt(pkesk, sym_algo, &mut k, &mut decrypt))
                    {
                        return Ok(fp);
                    }
                }
            }
        }

        // Fourth, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that are encrypted.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            // To appease the borrow checker, iterate over the
            // hashmap, awkwardly.
            for keyid in self.secret_keys.keys().cloned().collect::<Vec<_>>()
            {
                let mut keypair = loop {
                    let key = self.secret_keys.get_mut(&keyid).unwrap(); // Yuck

                    if ! key.secret().is_encrypted() {
                        break key.clone().into_keypair().unwrap();
                    }

                    let p = rpassword::read_password_from_tty(Some(
                        &format!(
                            "Enter password to decrypt key {}: ",
                            self.key_hints.get(&keyid).unwrap())))?.into();

                    let algo = key.pk_algo();
                    if let Some(()) =
                        key.secret_mut().decrypt_in_place(algo, &p).ok() {
                        break key.clone().into_keypair().unwrap()
                    } else {
                        eprintln!("Bad password.");
                    }
                };

                if let Some(fp) =
                    self.try_decrypt(pkesk, sym_algo, &mut keypair,
                                     &mut decrypt)
                {
                    return Ok(fp);
                }
            }
        }

        if skesks.is_empty() {
            return
                Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.
        loop {
            let password =
                rpassword::read_password_from_tty(Some(
                    "Enter password to decrypt message: "))?.into();

            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        eprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }

            eprintln!("Bad password.");
        }
    }
}

pub fn decrypt(config: Config,
               input: &mut (dyn io::Read + Sync + Send),
               output: &mut dyn io::Write,
               signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
               dump_session_key: bool,
               dump: bool, hex: bool)
               -> Result<()> {
    let helper = Helper::new(&config, signatures, certs, secrets,
                             dump_session_key, dump || hex);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        .mapping(hex)
        .with_policy(&config.policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    if let Some(dumper) = helper.dumper.as_ref() {
        dumper.flush(&mut io::stderr())?;
    }
    helper.vhelper.print_status();
    return Ok(());
}

pub fn decrypt_unwrap(config: Config,
                      input: &mut (dyn io::Read + Sync + Send),
                      output: &mut dyn io::Write,
                      secrets: Vec<Cert>, dump_session_key: bool)
                      -> Result<()>
{
    let mut helper = Helper::new(&config, 0, Vec::new(), secrets,
                                 dump_session_key, false);

    let mut ppr = PacketParser::from_reader(input)?;

    let mut pkesks: Vec<packet::PKESK> = Vec::new();
    let mut skesks: Vec<packet::SKESK> = Vec::new();
    while let PacketParserResult::Some(mut pp) = ppr {
        let sym_algo_hint = if let Packet::AED(ref aed) = pp.packet {
            Some(aed.symmetric_algo())
        } else {
            None
        };

        match pp.packet {
            Packet::SEIP(_) | Packet::AED(_) => {
                {
                    let decrypt = |algo, secret: &SessionKey| {
                        pp.decrypt(algo, secret).is_ok()
                    };
                    helper.decrypt(&pkesks[..], &skesks[..], sym_algo_hint,
                                   decrypt)?;
                }
                if pp.encrypted() {
                    return Err(
                        openpgp::Error::MissingSessionKey(
                            "No session key".into()).into());
                }

                io::copy(&mut pp, output)?;
                return Ok(());
            },
            Packet::MDC(ref mdc) => if ! mdc.valid() {
                return Err(openpgp::Error::ManipulatedMessage.into());
            },
            _ => (),
        }

        let (p, ppr_tmp) = pp.recurse()?;
        match p {
            Packet::PKESK(pkesk) => pkesks.push(pkesk),
            Packet::SKESK(skesk) => skesks.push(skesk),
            _ => (),
        }
        ppr = ppr_tmp;
    }

    Ok(())
}
