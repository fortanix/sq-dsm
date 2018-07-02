use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, Write};
use rpassword;

extern crate openpgp;
use openpgp::Packet;
use openpgp::packet::Tag;
use openpgp::parse::PacketParserResult;
use openpgp::serialize::stream::{
    wrap, LiteralWriter, Encryptor, EncryptionMode,
};
extern crate sequoia_store as store;

// Indent packets according to their recursion level.
const INDENT: &'static str
    = "                                                  ";

pub fn decrypt(input: &mut io::Read, output: &mut io::Write,
               dump: bool, map: bool)
           -> Result<(), failure::Error> {
    #[derive(PartialEq)]
    enum State {
        Start(Vec<()>, Vec<openpgp::SKESK>),
        Deciphered,
        Done,
    }
    let mut state = State::Start(vec![], vec![]);
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
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

        state = match state {
            // Look for an PKESK or SKESK packet.
            State::Start(pkesks, mut skesks) =>
                match pp.packet {
                    Packet::SEIP(_) => {
                        let mut state = None;
                        for _pkesk in pkesks.iter() {
                            // XXX try to decrypt those
                        }
                        if ! skesks.is_empty() {
                            let pass = rpassword::prompt_password_stderr(
                                "Enter password to decrypt message: ")?
                                .into_bytes();

                            for skesk in skesks.iter() {
                                let (algo, key) =
                                    skesk.decrypt(&pass)?;

	                        let r = pp.decrypt(algo, &key[..]);
                                if r.is_ok() {
                                    state = Some(State::Deciphered);
                                    break;
                                }
                            }
                        }
                        state.unwrap_or(State::Start(pkesks, skesks))
                    },
                    _ => State::Start(pkesks, skesks),
                },

            // Look for the literal data packet.
            State::Deciphered =>
                if let Packet::Literal(_) = pp.packet {
                    io::copy(&mut pp, output)?;
                    State::Done
                } else {
                    State::Deciphered
                },

            // We continue to parse, useful for dumping
            // encrypted packets.
            State::Done => State::Done,
        };

        let (packet, _, ppr_tmp, _) = pp.recurse()?;
        ppr = ppr_tmp;

        state = match state {
            // Look for an PKESK or SKESK packet.
            State::Start(pkesks, mut skesks) =>
                match packet {
                    Packet::Unknown(u) => {
                        match u.tag {
                            Tag::PKESK =>
                                eprintln!("Decryption using PKESK not yet \
                                           supported."),
                            _ => (),
                        }
                        State::Start(pkesks, skesks)
                    },
                    Packet::SKESK(skesk) => {
                        skesks.push(skesk);
                        State::Start(pkesks, skesks)
                    },
                    _ => State::Start(pkesks, skesks),
                },

            // Do nothing in all other states.
            s => s,
        };
    }

    if state != State::Done {
        return Err(failure::err_msg("Decryption failed."));
    }
    Ok(())
}

pub fn encrypt(store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               npasswords: usize, recipients: Vec<&str>)
               -> Result<(), failure::Error> {
    let mut tpks = Vec::with_capacity(recipients.len());
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
    let mut literal_writer = LiteralWriter::new(encryptor, 'b', None, 0)
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    Ok(())
}

pub fn dump(input: &mut io::Read, output: &mut io::Write, map: bool)
        -> Result<(), failure::Error> {
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
             -> Result<(), failure::Error> {
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
