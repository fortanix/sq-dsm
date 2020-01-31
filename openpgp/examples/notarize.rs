/// Notarizes OpenPGP messages using the openpgp crate, Sequoia's
/// low-level API.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::{
    armor,
    Packet,
    parse::{Parse, PacketParserResult},
    serialize::Serialize,
};
use crate::openpgp::serialize::stream::{Message, LiteralWriter, Signer};
use crate::openpgp::policy::StandardPolicy as P;

fn main() {
    let p = &P::new();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple notarizing filter.\n\n\
                Usage: {} <secret-keyfile> [<secret-keyfile>...] \
                <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let mut keys = Vec::new();
    for filename in &args[1..] {
        let tsk = openpgp::Cert::from_file(filename)
            .expect("Failed to read key");
        let mut n = 0;

        for key in tsk.keys()
            .set_policy(p, None).alive().revoked(false).for_signing().secret()
            .map(|ka| ka.key())
        {
            keys.push({
                let mut key = key.clone();
                if key.secret().expect("filtered").is_encrypted() {
                    let password = rpassword::read_password_from_tty(
                        Some(&format!("Please enter password to decrypt \
                                       {}/{}: ",tsk, key))).unwrap();
                    let algo = key.pk_algo();
                    key.secret_mut().expect("filtered")
                        .decrypt_in_place(algo, &password.into())
                        .expect("decryption failed");
                }
                n += 1;
                key.into_keypair().unwrap()
            });
        }

        if n == 0 {
            panic!("Found no suitable signing key on {}", tsk);
        }
    }

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message, &[])
        .expect("Failed to create an armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // Now, create a signer that emits the signature(s).
    let mut signer =
        Signer::new(message, keys.pop().expect("No key for signing"));
    for s in keys {
        signer = signer.add_signer(s);
    }
    let mut signer = signer.build().expect("Failed to create signer");

    // Create a parser for the message to be notarized.
    let mut input = io::stdin();
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(&mut input)
        .expect("Failed to build parser");

    while let PacketParserResult::Some(mut pp) = ppr {
        if let Err(err) = pp.possible_message() {
            panic!("Malformed OpenPGP message: {}", err);
        }

        match pp.packet {
            Packet::PKESK(_) | Packet::SKESK(_) =>
                panic!("Encrypted messages are not supported"),
            Packet::OnePassSig(ref ops) =>
                ops.serialize(&mut signer).expect("Failed to serialize"),
            Packet::Literal(_) => {
                // Then, create a literal writer to wrap the data in a
                // literal message packet.
                let mut literal =
                    LiteralWriter::new(signer).build()
                    .expect("Failed to create literal writer");

                // Copy all the data.
                io::copy(&mut pp, &mut literal)
                    .expect("Failed to sign data");

                signer = literal.finalize_one()
                    .expect("Failed to sign data")
                    .unwrap();
            },
            Packet::Signature(ref sig) =>
                sig.serialize(&mut signer).expect("Failed to serialize"),
            _ => (),
        }

        ppr = pp.recurse().expect("Failed to recurse").1;
    }
    if let PacketParserResult::EOF(eof) = ppr {
        if let Err(err) = eof.is_message() {
            panic!("Malformed OpenPGP message: {}", err)
        }
    } else {
        unreachable!()
    }

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()
        .expect("Failed to write data");
}
