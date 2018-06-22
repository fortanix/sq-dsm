/// This program demonstrates how to make a detached signature.

use std::env;
use std::io;
use std::iter;
extern crate time;

extern crate openpgp;
use openpgp::{armor, Key, Signature};
use openpgp::constants::{SignatureType, HashAlgorithm};
use openpgp::SecretKey;
use openpgp::serialize::Serialize;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple encryption filter.\n\n\
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

    // Hash the file.
    let hash_algo = HashAlgorithm::SHA512;
    let hashes = openpgp::hash_file(io::stdin(), &[hash_algo])
        .expect("Failed to hash file");

    // Get the one hash we computed.
    let hash = &hashes[0].1;

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.  First, we want the output to be as
    // armored.
    let mut sink = armor::Writer::new(io::stdout(), armor::Kind::Message);

    for tsk in tsks {
        // We need to find all (sub)keys capable of signing.
        let can_sign = |key: &Key, sig: &Signature| -> bool {
            sig.key_flags().can_sign()
            // Check expiry.
                && ! sig.signature_expired()
                && ! sig.key_expired(key)
        };

        // Gather all signing-capable subkeys.
        let subkeys = tsk.subkeys().filter_map(|skb| {
            let key = skb.subkey();
            // The first signature is the most recent binding
            // signature.
            if skb.selfsigs().next()
                .map(|sig| can_sign(key, sig))
                .unwrap_or(false) {
                    Some(key)
                } else {
                    None
                }
        });

        // Check if the primary key is signing-capable.
        let primary_can_sign =
        // The key capabilities are defined by the most recent
        // binding signature of the primary user id (or the
        // most recent user id binding if no user id is marked
        // as primary).  In any case, this is the first user id.
            tsk.userids().next().map(|ub| {
                ub.selfsigs().next()
                    .map(|sig| can_sign(tsk.primary(), sig))
                    .unwrap_or(false)
            }).unwrap_or(false);

        // If the primary key is signing-capable, prepend to
        // subkeys via iterator magic.
        let keys =
            iter::once(tsk.primary())
            .filter(|_| primary_can_sign)
            .chain(subkeys);

        // For every suitable key, compute and emit a signature.
        for key in keys {
            if let &SecretKey::Unencrypted { mpis: ref sec } =
                key.secret.as_ref().expect("No secret key")
            {
                // Clone hash so that we can hash the signature
                // packet, and compute the digest.
                let mut hash = hash.clone();

                // Make and hash a signature packet.
                let mut sig = Signature::new(SignatureType::Binary);
                sig.set_signature_creation_time(time::now())
                    .expect("Failed to set creation time");
                sig.set_issuer_fingerprint(key.fingerprint())
                    .expect("Failed to set issuer fingerprint");
                sig.set_issuer(key.keyid())
                    .expect("Failed to set issuer");

                // Make signature.
                sig.sign_hash(&key, sec, hash_algo, hash)
                    .expect("Failed to compute signature");

                // And emit the packet.
                sig.serialize(&mut sink)
                    .expect("Failed to write packet");
            }
        }
    }
}
