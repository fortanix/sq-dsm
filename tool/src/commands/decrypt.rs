use failure::{self, ResultExt};
use std::collections::HashMap;
use std::io;
use rpassword;
extern crate termsize;

extern crate sequoia_openpgp as openpgp;
use sequoia_core::Context;
use crate::openpgp::constants::SymmetricAlgorithm;
use crate::openpgp::conversions::hex;
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::{Fingerprint, TPK, KeyID, Result};
use crate::openpgp::packet::{Key, key::SecretKeyMaterial, Signature, PKESK, SKESK};
use crate::openpgp::parse::PacketParser;
use crate::openpgp::parse::stream::{
    VerificationHelper, DecryptionHelper, Decryptor, MessageStructure,
};
extern crate sequoia_store as store;

use super::{dump::PacketDumper, VHelper};

struct Helper<'a> {
    vhelper: VHelper<'a>,
    secret_keys: HashMap<KeyID, Key>,
    key_identities: HashMap<KeyID, Fingerprint>,
    key_hints: HashMap<KeyID, String>,
    dump_session_key: bool,
    dumper: Option<PacketDumper>,
    hex: bool,
}

impl<'a> Helper<'a> {
    fn new(ctx: &'a Context, store: &'a mut store::Store,
           signatures: usize, tpks: Vec<TPK>, secrets: Vec<TPK>,
           dump_session_key: bool, dump: bool, hex: bool)
           -> Self {
        let mut keys: HashMap<KeyID, Key> = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        for tsk in secrets {
            let can_encrypt = |_: &Key, sig: Option<&Signature>| -> bool {
                if let Some(sig) = sig {
                    sig.key_flags().can_encrypt_at_rest()
                        || sig.key_flags().can_encrypt_for_transport()
                } else {
                    false
                }
            };

            let hint = match tsk.userids().nth(0) {
                Some(uid) => format!("{} ({})", uid.userid(),
                                     tsk.fingerprint().to_keyid()),
                None => format!("{}", tsk.fingerprint().to_keyid()),
            };

            if can_encrypt(tsk.primary().key(), tsk.primary_key_signature()) {
                let id = tsk.fingerprint().to_keyid();
                keys.insert(id.clone(), tsk.primary().key().clone());
                identities.insert(id.clone(), tsk.fingerprint());
                hints.insert(id, hint.clone());
            }

            for skb in tsk.subkeys() {
                let key = skb.key();
                if can_encrypt(key, skb.binding_signature()) {
                    let id = key.fingerprint().to_keyid();
                    keys.insert(id.clone(), key.clone());
                    identities.insert(id.clone(), tsk.fingerprint());
                    hints.insert(id, hint.clone());
                }
            }
        }

        Helper {
            vhelper: VHelper::new(ctx, store, signatures, tpks),
            secret_keys: keys,
            key_identities: identities,
            key_hints: hints,
            dump_session_key: dump_session_key,
            dumper: if dump || hex {
                let width =
                    termsize::get().map(|s| s.cols as usize).unwrap_or(80);
                Some(PacketDumper::new(width, false))
            } else {
                None
            },
            hex: hex,
        }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        self.vhelper.get_public_keys(ids)
    }
    fn check(&mut self, structure: &MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn mapping(&self) -> bool {
        self.hex
    }

    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        if let Some(dumper) = self.dumper.as_mut() {
            dumper.packet(&mut io::stderr(),
                          pp.recursion_depth() as usize,
                          pp.header().clone(), pp.packet.clone(),
                          pp.map().map(|m| m.clone()), None)?;
        }
        Ok(())
    }

    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        // First, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get(&keyid) {
                if let Some(SecretKeyMaterial::Unencrypted { .. }) = key.secret() {
                    if let Ok(sk) = key.clone().into_keypair()
                        .and_then(|mut keypair| pkesk.decrypt(&mut keypair))
                        .and_then(|(algo, sk)| { decrypt(algo, &sk)?; Ok(sk) })
                    {
                        if self.dump_session_key {
                            eprintln!("Session key: {}", hex::encode(&sk));
                        }
                        return Ok(self.key_identities.get(keyid)
                                  .map(|fp| fp.clone()));
                    }
                }
            }
        }

        // Second, we try those keys that are encrypted.
        'pkesk_loop: for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some(key) = self.secret_keys.get(&keyid) {
                if key.secret().map(|s| ! s.is_encrypted())
                    .unwrap_or(true)
                {
                    continue;
                }

                loop {
                    let p = rpassword::read_password_from_tty(Some(
                        &format!(
                            "Enter password to decrypt key {}: ",
                            self.key_hints.get(&keyid).unwrap())))
                        ?.into();

                    let mut key = key.clone();
                    let algo = key.pk_algo();
                    if let Some(()) =
                        key.secret_mut()
                        .and_then(|s| s.decrypt_in_place(algo, &p).ok())
                    {
                        let mut keypair = key.into_keypair().unwrap();
                        match pkesk.decrypt(&mut keypair)
                            .and_then(|(algo, sk)| {
                                decrypt(algo, &sk)?; Ok(sk)
                            })
                        {
                            Ok(sk) => {
                                if self.dump_session_key {
                                    eprintln!("Session key: {}",
                                              hex::encode(&sk));
                                }
                                return Ok(self.key_identities.get(keyid)
                                          .map(|fp| fp.clone()));
                            },
                            Err(e) => {
                                eprintln!("Decryption using {} failed:\n  {}",
                                          self.key_hints.get(&keyid).unwrap(),
                                          e);
                                continue 'pkesk_loop;
                            },
                        }
                    } else {
                        eprintln!("Bad password.");
                    }
                }
            }
        }

        if skesks.is_empty() {
            return
                Err(failure::err_msg("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.
        loop {
            let password =
                rpassword::read_password_from_tty(Some(
                    "Enter password to decrypt message: "))?.into();

            for skesk in skesks {
                if let Ok(sk) = skesk.decrypt(&password)
                    .and_then(|(algo, sk)| { decrypt(algo, &sk)?; Ok(sk) })
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

pub fn decrypt(ctx: &Context, store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               signatures: usize, tpks: Vec<TPK>, secrets: Vec<TPK>,
               dump_session_key: bool,
               dump: bool, hex: bool)
               -> Result<()> {
    let helper = Helper::new(ctx, store, signatures, tpks, secrets,
                             dump_session_key, dump, hex);
    let mut decryptor = Decryptor::from_reader(input, helper, None)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            e.into()
        }).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    if let Some(dumper) = helper.dumper.as_ref() {
        dumper.flush(&mut io::stderr())?;
    }
    helper.vhelper.print_status();
    return Ok(());
}
