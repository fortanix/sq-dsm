/// This program demonstrates how to make a detached signature.

use std::env;
use std::io;
extern crate rpassword;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::armor;
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{Message, Signer};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple filter creating a detached signature.\n\n\
                Usage: {} <secret-keyfile> [<secret-keyfile>...] \
                <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let mut keys = Vec::new();
    for filename in &args[1..] {
        let tsk = openpgp::Cert::from_file(filename)
            .expect("Failed to read key");
        let mut n = 0;

        for (_, _, key) in tsk.keys_valid().for_signing().secret() {
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
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Signature, &[])
        .expect("Failed to create armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // Now, create a signer that emits the detached signature(s).
    let mut signer =
        Signer::new(message, keys.pop().expect("No key for signing"));
    for s in keys {
        signer = signer.add_signer(s);
    }
    let mut signer =
        signer.detached().build().expect("Failed to create signer");

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut signer)
        .expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()
        .expect("Failed to write data");
}
