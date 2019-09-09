/// Asymmetrically encrypts and pads OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::constants::DataFormat;
use crate::openpgp::KeyID;
use crate::openpgp::packet::KeyFlags;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{
    Message, LiteralWriter, Encryptor, Recipient,
};
use crate::openpgp::serialize::padding::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("A simple encryption filter.\n\n\
                Usage: {} [at-rest|for-transport] <keyfile> [<keyfile>...] \
                <input >output\n", args[0]);
    }

    let mode = match args[1].as_ref() {
        "at-rest" => KeyFlags::default().set_encrypt_at_rest(true),
        "for-transport" => KeyFlags::default().set_encrypt_for_transport(true),
        x => panic!("invalid mode: {:?}, \
                     must be either 'at-rest' or 'for-transport'",
                    x),
    };

    // Read the transferable public keys from the given files.
    let tpks: Vec<openpgp::TPK> = args[2..].iter().map(|f| {
        openpgp::TPK::from_file(f)
            .expect("Failed to read key")
    }).collect();

    // Build a vector of recipients to hand to Encryptor.
    let recipients =
        tpks.iter()
        .flat_map(|tpk| tpk.keys_valid().key_flags(mode.clone()))
        .map(|(_, _, key)| Recipient::new(KeyID::wildcard(), key))
        .collect::<Vec<_>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message, &[])
        .expect("Failed to create an armored writer");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::new(message,
                                   &[], // No symmetric encryption.
                                   &recipients,
                                   None, None)
        .expect("Failed to create encryptor");

    let padder = Padder::new(encryptor, padme)
        .expect("Failed to create padder");

    let mut literal_writer = LiteralWriter::new(padder, DataFormat::Binary,
                                                None, None)
        .expect("Failed to create literal writer");

    // Copy stdin to our writer stack to encrypt the data.
    io::copy(&mut io::stdin(), &mut literal_writer)
        .expect("Failed to encrypt");

    // Finally, finalize the OpenPGP message by tearing down the
    // writer stack.
    literal_writer.finalize().unwrap();
}