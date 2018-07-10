/// This program demonstrates how to sign data.

use std::env;
use std::io;

extern crate openpgp;
use openpgp::armor;
use openpgp::constants::DataFormat;
use openpgp::serialize::stream::{wrap, LiteralWriter, Signer};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple signing filter.\n\n\
                Usage: {} <secret-keyfile> [<secret-keyfile>...] \
                <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let tsks: Vec<openpgp::TPK> = args[1..].iter().map(|f| {
        openpgp::TPK::from_reader(
            // Use an openpgp::Reader so that we accept both armored
            // and plain PGP data.
            openpgp::Reader::from_file(f)
                .expect("Failed to open file"))
            .expect("Failed to read key")
    }).collect();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be as
    // armored.
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Message);

    // Now, create a signer that emits a detached signature.
    let signer = Signer::new(
        wrap(sink), &tsks.iter().collect::<Vec<&openpgp::TPK>>())
        .expect("Failed to create signer");

    // Then, create a literal writer to wrap the data in a literal
    // message packet.
    let mut literal = LiteralWriter::new(signer, DataFormat::Binary, None, None)
        .expect("Failed to create literal writer");

    // Finally, just copy all the data.
    io::copy(&mut io::stdin(), &mut literal)
        .expect("Failed to sign data");

    // Teardown the stack to ensure all the data is written.
    literal.finalize_all()
        .expect("Failed to write data");
}
