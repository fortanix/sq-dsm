use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use rpassword;

extern crate openpgp;
use openpgp::constants::DataFormat;
use openpgp::{Packet, Key, TPK, KeyID, SecretKey, Signature, Result};
use openpgp::parse::PacketParserResult;
use openpgp::parse::stream::{
    Verifier, VerificationResult, VerificationHelper,
};
use openpgp::serialize::stream::{
    wrap, Signer, LiteralWriter, Encryptor, EncryptionMode,
};
extern crate sequoia_store as store;

// Indent packets according to their recursion level.
const INDENT: &'static str
    = "                                                  ";

pub fn decrypt(input: &mut io::Read, output: &mut io::Write,
               secrets: Vec<TPK>, dump: bool, map: bool)
           -> Result<()> {
    let mut keys: HashMap<KeyID, Key> = HashMap::new();
    for tsk in secrets {
        let can_encrypt = |key: &Key, sig: &Signature| -> bool {
            (sig.key_flags().can_encrypt_at_rest()
             || sig.key_flags().can_encrypt_for_transport())
            // Check expiry.
                && sig.signature_alive()
                && sig.key_alive(key)
        };

        if tsk.primary_key_signature()
            .map(|sig| can_encrypt(tsk.primary(), sig))
            .unwrap_or(false)
        {
            keys.insert(tsk.fingerprint().to_keyid(), tsk.primary().clone());
        }

        for skb in tsk.subkeys() {
            let key = skb.subkey();
            if can_encrypt(key, skb.binding_signature()) {
                keys.insert(key.fingerprint().to_keyid(), key.clone());
            }
        }
    }

    let mut pkesks: Vec<openpgp::PKESK> = Vec::new();
    let mut skesks: Vec<openpgp::SKESK> = Vec::new();
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
        if ! pp.possible_message() {
            return Err(failure::err_msg("Malformed OpenPGP message"));
        }

        if dump || map {
            eprintln!("{}{:?}",
                      &INDENT[0..pp.recursion_depth as usize], pp.packet);
        }

        if let Some(ref map) = pp.map {
            eprintln!();
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.print(bytes, field);
            }
            println!();
        }

        match pp.packet {
            Packet::SEIP(_) => {
                let mut decrypted = false;
                for pkesk in pkesks.iter() {
                    if let Some(tsk) = keys.get(&pkesk.recipient) {
                        // XXX: Deal with encrypted keys.
                        if let Some(SecretKey::Unencrypted{ref mpis}) = tsk.secret {
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

        let (packet, _, ppr_tmp, _) = pp.recurse()?;
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

pub fn sign(input: &mut io::Read, output: &mut io::Write,
            secrets: Vec<openpgp::TPK>, detached: bool)
            -> Result<()> {
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

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;
    Ok(())
}

struct VHelper {
    tpks: Option<Vec<TPK>>,
    good: usize,
    unknown: usize,
    bad: usize,
    error: Option<failure::Error>,
}

impl VHelper {
    fn new(tpks: Vec<TPK>) -> Self {
        VHelper {
            tpks: Some(tpks),
            good: 0,
            unknown: 0,
            bad: 0,
            error: None,
        }
    }

    fn get_error(&mut self) -> Result<()> {
        if let Some(e) = self.error.take() {
            Err(e)
        } else {
            Ok(())
        }
    }

    fn print_status(&self) {
        eprintln!("{} good signatures, {} bad signatures, {} not checked.",
                  self.good, self.bad, self.unknown);
    }

    fn success(&self) -> bool {
        self.good > 0 && self.bad == 0
    }
}

impl VerificationHelper for VHelper {
    fn get_public_keys(&mut self, _ids: &[KeyID]) -> Result<Vec<TPK>> {
        Ok(self.tpks.take().unwrap())
    }

    fn result(&mut self, result: VerificationResult) -> Result<()> {
        use self::VerificationResult::*;
        match result {
            Good(sig) => {
                eprintln!("Good signature from {}",
                          sig.get_issuer().unwrap());
                self.good += 1;
            },
            Unknown(sig) => {
                eprintln!("No key to check signature from {}",
                          sig.get_issuer().unwrap());
                self.unknown += 1;
            },
            Bad(sig) => {
                if let Some(issuer) = sig.get_issuer() {
                    eprintln!("Bad signature from {}", issuer);
                } else {
                    eprintln!("Bad signature without issuer information");
                }
                self.bad += 1;
            },
        }
        Ok(())
    }

    fn error(&mut self, error: failure::Error) {
        self.error = Some(error);
    }
}

pub fn verify(input: &mut io::Read, output: &mut io::Write,
              tpks: Vec<TPK>)
              -> Result<()> {
    let helper = VHelper::new(tpks);
    let mut verifier = Verifier::from_reader(input, helper)?;

    if verifier.helper_ref().bad == 0 {
        if let Err(e) = io::copy(&mut verifier, output) {
            verifier.helper_mut().get_error()?;
            Err(e)?;
        }
    }

    let helper = verifier.into_helper();
    helper.print_status();
    if helper.success() {
        Ok(())
    } else {
        Err(failure::err_msg("Verification failed"))
    }
}

pub fn dump(input: &mut io::Read, output: &mut io::Write, map: bool)
        -> Result<()> {
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            writeln!(output, "{}{:?}\n",
                     &INDENT[0..pp.recursion_depth as usize], pp.packet)?;
            for (field, bytes) in map.iter() {
                hd.print(bytes, field);
            }
            println!();
        } else {
            if let openpgp::Packet::Literal(_) = pp.packet {
                // XXX: We should actually stream this.  In fact,
                // we probably only want to print out the first
                // line or so and then print the total number of
                // bytes.
                pp.buffer_unread_content()?;
            }
            writeln!(output, "{}{:?}",
                     &INDENT[0..pp.recursion_depth as usize], pp.packet)?;
        }

        let (_, _, ppr_, _) = pp.recurse()?;
        ppr = ppr_;
    }
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

        let (_, old_depth, ppr_, new_depth) = pp.recurse()?;
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

struct HexDumper {
    offset: usize,
}

impl HexDumper {
    fn new() -> Self {
        HexDumper {
            offset: 0,
        }
    }

    fn print(&mut self, buf: &[u8], msg: &str) {
        let mut msg_printed = false;
        print!("{:08x}  ", self.offset);
        for i in 0 .. self.offset % 16 {
            if i != 7 {
                print!("   ");
            } else {
                print!("    ");
            }
        }

        for c in buf {
            print!("{:02x} ", c);
            self.offset += 1;
            match self.offset % 16 {
                0 => {
                    if ! msg_printed {
                        print!("  {}", msg);
                        msg_printed = true;
                    }

                    print!("\n{:08x}  ", self.offset)
                },
                8 => print!(" "),
                _ => (),
            }
        }

        for i in self.offset % 16 .. 16 {
            if i != 7 {
                print!("   ");
            } else {
                print!("    ");
            }
        }

        if ! msg_printed {
            print!("  {}", msg);
        }
        println!();
    }
}
