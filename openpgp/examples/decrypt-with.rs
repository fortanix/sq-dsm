/// This program demonstrates how to decrypt a stream of data.

use std::env;
use std::io;
use std::collections::HashMap;

extern crate openpgp;
use openpgp::{
    Packet,
    KeyID,
    Key,
    TPK,
    SecretKey,
};
use openpgp::parse::PacketParserResult;

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple decryption filter.\n\n\
                Usage: {} <keyfile> [<keyfile>...] <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let mut keys: HashMap<KeyID, Key> = HashMap::new();
    for f in args[1..].iter() {
        let tsk = TPK::from_reader(
            // Use an openpgp::Reader so that we accept both armored
            // and plain PGP data.
            openpgp::Reader::from_file(f)
                .expect("Failed to open file"))
            .expect("Failed to read key");
        for (sig, key) in tsk.keys() {
            if ! sig.map(|s| s.key_flags().can_encrypt_at_rest()
                         || s.key_flags().can_encrypt_for_transport())
                .unwrap_or(false)
            {
                continue;
            }

            keys.insert(key.fingerprint().to_keyid(), key.clone());
        }
    }

    #[derive(PartialEq)]
    enum State {
        Start(Vec<openpgp::PKESK>, Vec<openpgp::SKESK>),
        Deciphered,
        Done,
    }
    let mut state = State::Start(vec![], vec![]);
    let mut input = io::stdin();
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(
            openpgp::Reader::from_reader(&mut input)
                .expect("Failed to build reader"))
        .expect("Failed to build parser");

    while let PacketParserResult::Some(mut pp) = ppr {
        state = match state {
            // Look for an PKESK or SKESK packet.
            State::Start(mut pkesks, mut skesks) =>
                match pp.packet {
                    Packet::SEIP(_) => {
                        let mut state = None;
                        for pkesk in pkesks.iter() {
                            if let Some(tsk) = keys.get(&pkesk.recipient()) {
                                if let Some(SecretKey::Unencrypted{ref mpis}) =
                                    tsk.secret()
                                {
                                    if let Ok((algo, key)) = pkesk.decrypt(tsk, mpis) {
	                                let r = pp.decrypt(algo, &key[..]);
                                        if r.is_ok() {
                                            state = Some(State::Deciphered);
                                            break;
                                        }
                                    }
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
                    io::copy(&mut pp, &mut io::stdout())
                        .expect("Failed to copy data");
                    State::Done
                } else {
                    State::Deciphered
                },

            // We continue to parse, useful for dumping
            // encrypted packets.
            State::Done => State::Done,
        };

        let ((packet, _), (ppr_tmp, _)) = pp.recurse()
            .expect("Failed to recurse");
        ppr = ppr_tmp;

        state = match state {
            // Look for an PKESK or SKESK packet.
            State::Start(mut pkesks, mut skesks) =>
                match packet {
                    Packet::PKESK(pkesk) => {
                        pkesks.push(pkesk);
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
        panic!("decryption failed");
    }
}
