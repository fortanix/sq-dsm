use failure::{self, ResultExt};
use std::collections::HashMap;
use std::io;
use rpassword;

extern crate openpgp;
use sequoia_core::Context;
use openpgp::{TPK, KeyID, SecretKey, Result};
use openpgp::packet::{Key, Signature, PKESK, SKESK};
use openpgp::parse::PacketParser;
use openpgp::parse::stream::{
    VerificationHelper, VerificationResult, DecryptionHelper, Decryptor, Secret,
};
extern crate sequoia_store as store;

use super::{dump::{HexDumper, dump_packet}, VHelper};

struct Helper<'a> {
    vhelper: VHelper<'a>,
    secret_keys: HashMap<KeyID, Key>,
    dump: bool,
    hex: bool,
    pkesk_i: usize,
}

impl<'a> Helper<'a> {
    fn new(ctx: &'a Context, store: &'a mut store::Store,
           signatures: usize, tpks: Vec<TPK>, secrets: Vec<TPK>,
           dump: bool, hex: bool)
           -> Self {
        let mut keys: HashMap<KeyID, Key> = HashMap::new();
        for tsk in secrets {
            let can_encrypt = |_: &Key, sig: Option<&Signature>| -> bool {
                if let Some(sig) = sig {
                    sig.key_flags().can_encrypt_at_rest()
                        || sig.key_flags().can_encrypt_for_transport()
                } else {
                    false
                }
            };

            if can_encrypt(tsk.primary(), tsk.primary_key_signature()) {
                keys.insert(tsk.fingerprint().to_keyid(), tsk.primary().clone());
            }

            for skb in tsk.subkeys() {
                let key = skb.subkey();
                if can_encrypt(key, skb.binding_signature()) {
                    keys.insert(key.fingerprint().to_keyid(), key.clone());
                }
            }
        }

        Helper {
            vhelper: VHelper::new(ctx, store, signatures, tpks),
            secret_keys: keys,
            dump: dump,
            hex: hex,
            pkesk_i: 0,
        }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        self.vhelper.get_public_keys(ids)
    }
    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
        self.vhelper.check(sigs)
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn mapping(&self) -> bool {
        self.hex
    }

    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        if self.dump || self.hex {
            dump_packet(&mut io::stderr(),
                        2 * pp.recursion_depth as usize,
                        false,
                        Some(&pp.header), &pp.packet)?;
            eprintln!();
        }

        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.write(&mut io::stderr(), bytes, field)?;
            }
            eprintln!();
        }

        Ok(())
    }

    fn get_secret(&mut self, pkesks: &[&PKESK], _skesks: &[&SKESK])
                  -> Result<Option<Secret>> {
        while let Some(pkesk) = pkesks.get(self.pkesk_i) {
            let keyid = pkesk.recipient();
            let key = if let Some(key) = self.secret_keys.get(keyid) {
                key
            } else {
                self.pkesk_i += 1;
                continue;
            };

            // XXX: Deal with encrypted keys.
            if let Some(SecretKey::Unencrypted{ref mpis}) = key.secret() {
                return Ok(Some(Secret::Asymmetric {
                    key: key.clone(),
                    secret: mpis.clone(),
                }))
            } else {
                self.pkesk_i += 1;
                continue;
            }
        }

        Ok(Some(Secret::Symmetric {
            password: rpassword::prompt_password_stderr(
                "Enter password to decrypt message: ")?,
        }))
    }
}

pub fn decrypt(ctx: &Context, store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               signatures: usize, tpks: Vec<TPK>, secrets: Vec<TPK>,
               dump: bool, hex: bool)
               -> Result<()> {
    let helper = Helper::new(ctx, store, signatures, tpks, secrets, dump, hex);
    let mut decryptor = Decryptor::from_reader(input, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            e.into()
        }).context("Decryption failed")?;

    decryptor.into_helper().vhelper.print_status();
    return Ok(());
}
