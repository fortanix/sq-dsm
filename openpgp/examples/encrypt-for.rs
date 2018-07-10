/// This program demonstrates how to encrypt a stream of data.

use std::env;
use std::io;

extern crate openpgp;
use openpgp::armor;
use openpgp::serialize::stream::{
    wrap, LiteralWriter, Encryptor, EncryptionMode,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("A simple encryption filter.\n\n\
                Usage: {} [at-rest|for-transport] <keyfile> [<keyfile>...] <input >output\n", args[0]);
    }

    let mode = match args[1].as_ref() {
        "at-rest" => EncryptionMode::AtRest,
        "for-transport" => EncryptionMode::ForTransport,
        x => panic!("invalid mode: {:?}, \
                     must be either 'at rest' or 'for transport'",
                    x),
    };

    // Read the transferable public keys from the given files.
    let tpks: Vec<openpgp::TPK> = args[2..].iter().map(|f| {
        openpgp::TPK::from_reader(
            // Use an openpgp::Reader so that we accept both armored
            // and plain PGP data.
            openpgp::Reader::from_file(f)
                .expect("Failed to open file"))
            .expect("Failed to read key")
    }).collect();
    // Build a vector of references to hand to Encryptor.
    let recipients: Vec<&openpgp::TPK> = tpks.iter().collect();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be as
    // armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message);

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::new(wrap(sink),
                                   &[], // No symmetric encryption.
                                   &recipients,
                                   mode)
        .expect("Failed to create encryptor");
    let mut literal_writer = LiteralWriter::new(encryptor, 't', None, None)
        .expect("Failed to create literal writer");

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(&mut io::stdin(), &mut literal_writer)
        .expect("Failed to encrypt");
}
