/// This program demonstrates how to make a detached signature.

use std::env;
use std::io;

extern crate sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Message, Signer};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple filter creating a detached signature.\n\n\
                Usage: {} <secret-keyfile> [<secret-keyfile>...] \
                <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let tsks: Vec<openpgp::TPK> = args[1..].iter().map(|f| {
        openpgp::TPK::from_file(f)
            .expect("Failed to read key")
    }).collect();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be
    // ASCII armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Signature, &[])
        .expect("Failed to create armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // Now, create a signer that emits a detached signature.
    let mut signer = Signer::detached(
        message, &tsks.iter().collect::<Vec<&openpgp::TPK>>())
        .expect("Failed to create signer");

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut signer)
        .expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()
        .expect("Failed to write data");
}
