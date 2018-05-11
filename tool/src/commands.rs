use failure;
use std::io;
use rpassword;

extern crate openpgp;
use openpgp::{Packet, Tag};

// Indent packets according to their recursion level.
const INDENT: &'static str
    = "                                                  ";

pub fn decrypt(input: &mut io::Read, output: &mut io::Write,
               dump: bool, map: bool)
           -> Result<(), failure::Error> {
    #[derive(PartialEq)]
    enum State {
        Start,
        Decrypted(u8, Vec<u8>),
        Deciphered,
        Done,
    }
    let mut state = State::Start;
    let mut ppo
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let Some(mut pp) = ppo {
        if dump || map {
            eprintln!("{}{:?}",
                      &INDENT[0..pp.recursion_depth as usize], pp.packet);
        }

        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.print(bytes, field);
            }
            println!();
        }

        state = match state {
            // Look for an PKESK or SKESK packet.
            State::Start =>
                match pp.packet {
                    Packet::Unknown(ref u) => {
                        match u.tag {
                            Tag::PKESK =>
                                eprintln!("Decryption using PKESK not yet \
                                           supported."),
                            _ => (),
                        }
                        State::Start
                    },
                    Packet::SKESK(ref skesk) => {
                        let pass = rpassword::prompt_password_stderr(
                            "Enter passphrase to decrypt message: ")?;
                        match skesk.decrypt(pass.into_bytes().as_ref()) {
                            Ok((algo, key)) => State::Decrypted(algo.into(), key),
                            Err(e) => {
                                eprintln!("Decryption failed: {}", e);
                                State::Start
                            },
                        }
                    },
                    _ => State::Start,
                },

            // Look for an SEIP packet.
            State::Decrypted(algo, key) =>
                if let Packet::SEIP(_) = pp.packet {
	            pp.decrypt(algo.into(), &key[..])?;
                    State::Deciphered
                } else {
                    State::Decrypted(algo, key)
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

        let (_, _, ppo_tmp, _) = pp.recurse()?;
        ppo = ppo_tmp;
    }

    if state != State::Done {
        return Err(failure::err_msg("Decryption failed."));
    }
    Ok(())
}

pub fn dump(input: &mut io::Read, output: &mut io::Write, map: bool)
        -> Result<(), failure::Error> {
    let mut ppo
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let Some(mut pp) = ppo {
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

        let (_, _, ppo_, _) = pp.recurse()?;
        ppo = ppo_;
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
