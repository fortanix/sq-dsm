use failure;
use std::collections::HashMap;
use std::io;
use rpassword;

extern crate openpgp;
use openpgp::{Packet, TPK, KeyID, SecretKey, Result};
use openpgp::packet::{Key, Signature};
use openpgp::parse::PacketParserResult;
extern crate sequoia_store as store;

use super::{INDENT, HexDumper, dump_packet};

pub fn decrypt(input: &mut io::Read, output: &mut io::Write,
               secrets: Vec<TPK>, dump: bool, map: bool)
           -> Result<()> {
    let mut keys: HashMap<KeyID, Key> = HashMap::new();
    for tsk in secrets {
        let can_encrypt = |key: &Key, sig: Option<&Signature>| -> bool {
            if let Some(sig) = sig {
                (sig.key_flags().can_encrypt_at_rest()
                 || sig.key_flags().can_encrypt_for_transport())
                // Check expiry.
                    && sig.signature_alive()
                    && sig.key_alive(key)
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

    let mut pkesks: Vec<openpgp::packet::PKESK> = Vec::new();
    let mut skesks: Vec<openpgp::packet::SKESK> = Vec::new();
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
        if ! pp.possible_message() {
            return Err(failure::err_msg("Malformed OpenPGP message"));
        }

        if dump || map {
            dump_packet(&mut io::stderr(),
                        &INDENT[0..4 * pp.recursion_depth as usize],
                        false,
                        &pp.packet)?;
            eprintln!();
        }

        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.write(&mut io::stderr(), bytes, field)?;
            }
            eprintln!();
        }

        match pp.packet {
            Packet::SEIP(_) => {
                let mut decrypted = false;
                for pkesk in pkesks.iter() {
                    if let Some(tsk) = keys.get(pkesk.recipient()) {
                        // XXX: Deal with encrypted keys.
                        if let Some(SecretKey::Unencrypted{ref mpis}) =
                            tsk.secret()
                        {
                            if let Ok((algo, key)) = pkesk.decrypt(tsk, mpis) {
	                        let r = pp.decrypt(algo, &key[..]);
                                if r.is_ok() {
                                    decrypted = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if ! decrypted && ! skesks.is_empty() {
                    let pass = rpassword::prompt_password_stderr(
                        "Enter password to decrypt message: ")?
                    .into_bytes();

                    for skesk in skesks.iter() {
                        let (algo, key) = skesk.decrypt(&pass)?;

	                let r = pp.decrypt(algo, &key[..]);
                        if r.is_ok() {
                            break;
                        }
                    }
                }
            },
            Packet::Literal(_) => {
                io::copy(&mut pp, output)?;
            },
            _ => (),
        }

        let ((packet, _), (ppr_tmp, _)) = pp.recurse()?;
        ppr = ppr_tmp;

        match packet {
            Packet::PKESK(pkesk) => pkesks.push(pkesk),
            Packet::SKESK(skesk) => skesks.push(skesk),
            _ => (),
        }
    }
    if let PacketParserResult::EOF(eof) = ppr {
        if eof.is_message() {
            Ok(())
        } else {
            Err(failure::err_msg("Malformed OpenPGP message"))
        }
    } else {
        unreachable!()
    }
}
