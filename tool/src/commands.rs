use failure;
use std::io;
use rpassword;

extern crate openpgp;
use openpgp::{Packet, Tag};

// Indent packets according to their recursion level.
const INDENT: &'static str
    = "                                                  ";

pub fn decrypt(input: &mut io::Read, output: &mut io::Write, dump: bool)
           -> Result<(), failure::Error> {
    #[derive(PartialEq)]
    enum State {
        Start,
        Decrypted(u8, Vec<u8>),
        Deciphered,
        Done,
    }
    let mut state = State::Start;
    let mut ppo = openpgp::parse::PacketParser::from_reader(input)?;

    while let Some(mut pp) = ppo {
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

        if dump {
            eprintln!("{}{:?}",
                      &INDENT[0..pp.recursion_depth as usize], pp.packet);
        }

        let (_, _, ppo_tmp, _) = pp.recurse()?;
        ppo = ppo_tmp;
    }

    if state != State::Done {
        return Err(failure::err_msg("Decryption failed."));
    }
    Ok(())
}
