/// This program demonstrates how to make a detached signature.

use std::env;
use std::io;
extern crate rpassword;

extern crate sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::crypto;
use openpgp::packet::key::SecretKey;
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
    let mut keys = Vec::new();
    'nextfile: for filename in &args[1..] {
        let tsk = openpgp::TPK::from_file(filename)
            .expect("Failed to read key");

        for key in tsk.keys_valid().signing_capable().map(|k| k.2) {
            if let Some(mut secret) = key.secret() {
                let secret_mpis = match secret {
                    SecretKey::Encrypted { .. } => {
                        let password = rpassword::prompt_password_stderr(
                            &format!("Please enter password to decrypt {}/{}: ",
                                     tsk, key)).unwrap();
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
    let sink = armor::Writer::new(io::stdout(), armor::Kind::Signature, &[])
        .expect("Failed to create armored writer.");

    // Stream an OpenPGP message.
    let message = Message::new(sink);

    // Now, create a signer that emits a detached signature.
    let mut signer = Signer::detached(
        message,
        keys.iter_mut().map(|s| -> &mut dyn crypto::Signer { s }).collect())
        .expect("Failed to create signer");

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut signer)
        .expect("Failed to sign data");

    // Finally, teardown the stack to ensure all the data is written.
    signer.finalize()
        .expect("Failed to write data");
}
