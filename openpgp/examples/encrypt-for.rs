use std::env;
use std::io;

extern crate openpgp;
use openpgp::armor;
use openpgp::serialize::stream::{
    wrap, LiteralWriter, Encryptor, EncryptionMode,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("A simple encryption filter.\n\n\
                Usage: {} <keyfile> <input >output\n", args[0]);
    }

    let keyfile = &args[1];
    let tpk = openpgp::TPK::from_reader(
        openpgp::Reader::from_file(keyfile).expect("Failed to open file"))
        .expect("Failed to read key");
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message);
    let encryptor = Encryptor::new(wrap(sink), &[], &[&tpk],
                                   EncryptionMode::AtRest)
        .expect("Failed to create encryptor");
    let mut literal_writer = LiteralWriter::new(encryptor, 't', None, 0)
        .expect("Failed to create literal writer");
    io::copy(&mut io::stdin(), &mut literal_writer)
        .expect("Failed to encrypt");
}
