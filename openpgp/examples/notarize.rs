/// Notarizes OpenPGP messages using the openpgp crate, Sequoia's
/// low-level API.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    crypto,
    Packet,
    constants::DataFormat,
    packet::key::SecretKey,
    parse::{Parse, PacketParserResult},
    serialize::Serialize,
};
use openpgp::serialize::stream::{Message, LiteralWriter, Signer};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple notarizing filter.\n\n\
                Usage: {} <secret-keyfile> [<secret-keyfile>...] \
                <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let mut keys = Vec::new();
    'nextfile: for filename in &args[1..] {
        let tsk = openpgp::TPK::from_file(filename)
            .expect("Failed to read key");

        for key in tsk.keys_valid().signing_capable().map(|k| k.2) {
            if let Some(mut secret) = key.secret() {
                let secret_mpis = match secret {
                    SecretKey::Encrypted { .. } => {
                        let password = rpassword::read_password_from_tty(
                            Some(&format!("Please enter password to decrypt \
                                           {}/{}: ",tsk, key))).unwrap();
                        secret.decrypt(key.pk_algo(), &password.into())
                            .expect("decryption failed")
                    },
                    SecretKey::Unencrypted { ref mpis } =>
                        mpis.clone(),
                };

                keys.push(crypto::KeyPair::new(key.clone(), secret_mpis)
                          .unwrap());
                break 'nextfile;
            }
        }

        panic!("Found no suitable signing key on {}", tsk);
    }

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message, &[])
        .expect("Failed to create an armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // Now, create a signer that emits a detached signature.
    let mut signer = Signer::new(
        message,
        keys.iter_mut().map(|s| -> &mut dyn crypto::Signer { s }).collect(),
        None)
        .expect("Failed to create signer");

    // Create a parser for the message to be notarized.
    let mut input = io::stdin();
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(&mut input)
        .expect("Failed to build parser");

    while let PacketParserResult::Some(mut pp) = ppr {
        if ! pp.possible_message() {
            panic!("Malformed OpenPGP message");
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
                    LiteralWriter::new(signer, DataFormat::Binary, None, None)
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
        if ! eof.is_message() {
            panic!("Malformed OpenPGP message")
        }
    } else {
        unreachable!()
    }

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()
        .expect("Failed to write data");
}
