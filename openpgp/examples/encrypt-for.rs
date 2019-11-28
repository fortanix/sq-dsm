/// Asymmetrically encrypts OpenPGP messages using the openpgp crate,
/// Sequoia's low-level API.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{
    Message, LiteralWriter, Encryptor,
};

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

    // Read the certificates from the given files.
    let certs: Vec<openpgp::Cert> = args[2..].iter().map(|f| {
        openpgp::Cert::from_file(f)
            .expect("Failed to read key")
    }).collect();

    // Build a vector of recipients to hand to Encryptor.
    let mut recipients =
        certs.iter()
        .flat_map(|cert| cert.keys_valid().key_flags(mode.clone()))
        .map(|(_, _, key)| key.into())
        .collect::<Vec<_>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message, &[])
        .expect("Failed to create an armored writer");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let mut encryptor = Encryptor::for_recipient(
        message, recipients.pop().expect("No encryption key found"));
    for r in recipients {
        encryptor = encryptor.add_recipient(r)
    }
    let encryptor = encryptor.build().expect("Failed to create encryptor");

    let mut literal_writer = LiteralWriter::new(encryptor).build()
        .expect("Failed to create literal writer");

    // Copy stdin to our writer stack to encrypt the data.
    io::copy(&mut io::stdin(), &mut literal_writer)
        .expect("Failed to encrypt");

    // Finally, finalize the OpenPGP message by tearing down the
    // writer stack.
    literal_writer.finalize().unwrap();
}
