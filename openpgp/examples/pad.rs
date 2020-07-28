/// Asymmetrically encrypts and pads OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::KeyID;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{
    Message, LiteralWriter, Encryptor, Recipient, padding::*,
};
use crate::openpgp::policy::StandardPolicy as P;

fn main() {
    let p = &P::new();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("A simple encryption filter.\n\n\
                Usage: {} [at-rest|for-transport] <keyfile> [<keyfile>...] \
                <input >output\n", args[0]);
    }

    let mode = match args[1].as_ref() {
        "at-rest" => KeyFlags::default().set_storage_encryption(),
        "for-transport" => KeyFlags::default().set_transport_encryption(),
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
    let recipients = certs
        .iter()
        .flat_map(|cert| {
            cert.keys()
                .with_policy(p, None).alive().revoked(false).key_flags(&mode)
        })
        .map(|ka| Recipient::new(KeyID::wildcard(), ka.key()))
        .collect::<Vec<_>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let mut sink = armor::Writer::new(io::stdout(), armor::Kind::Message)
        .expect("Failed to create an armored writer");

    // Stream an OpenPGP message.
    let message = Message::new(&mut sink);

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::for_recipients(message, recipients)
        .build().expect("Failed to create encryptor");

    let padder = Padder::new(encryptor, padme)
        .expect("Failed to create padder");

    let mut literal_writer = LiteralWriter::new(padder).build()
        .expect("Failed to create literal writer");

    // Copy stdin to our writer stack to encrypt the data.
    io::copy(&mut io::stdin(), &mut literal_writer)
        .expect("Failed to encrypt");

    // Finally, finalize the OpenPGP message by tearing down the
    // writer stack.
    literal_writer.finalize().unwrap();

    // Finalize the armor writer.
    sink.finalize()
        .expect("Failed to write data");
}
