/// Decrypts asymmetrically-encrypted OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::collections::HashMap;
use std::env;
use std::io;

extern crate failure;
extern crate sequoia_openpgp as openpgp;

use crate::openpgp::crypto::{KeyPair, SessionKey};
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::parse::{
    Parse,
    stream::{
        DecryptionHelper,
        Decryptor,
        VerificationHelper,
        VerificationResult,
        MessageStructure,
        MessageLayer,
    },
};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("A simple decryption filter.\n\n\
                Usage: {} <keyfile> [<keyfile>...] <input >output\n", args[0]);
    }

    // Read the transferable secret keys from the given files.
    let certs =
        args[1..].iter().map(|f| {
            openpgp::Cert::from_file(f)
                .expect("Failed to read key")
        }).collect();

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor =
        Decryptor::from_reader(io::stdin(), Helper::new(certs), None).unwrap();

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::stdout())
        .expect("Decryption failed");
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper {
    keys: HashMap<openpgp::KeyID, KeyPair>,
}

impl Helper {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(certs: Vec<openpgp::Cert>) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for cert in certs {
            for ka in cert.keys().policy(None)
                .for_storage_encryption().for_transport_encryption()
            {
                // This only works for unencrypted secret keys.
                if let Ok(keypair) =
                    ka.key().clone().mark_parts_secret().unwrap().into_keypair()
                {
                    keys.insert(ka.key().keyid(), keypair);
                }
            }
        }

        Helper {
            keys: keys,
        }
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(&mut self,
                  pkesks: &[openpgp::packet::PKESK],
                  _skesks: &[openpgp::packet::SKESK],
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            if let Some(pair) = self.keys.get_mut(pkesk.recipient()) {
                if let Ok(_) = pkesk.decrypt(pair)
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                {
                    break;
                }
            }
        }
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

impl VerificationHelper for Helper {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                       -> failure::Fallible<Vec<openpgp::Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, structure: MessageStructure)
             -> failure::Fallible<()> {
        use self::VerificationResult::*;
        for layer in structure.iter() {
            match layer {
                MessageLayer::Compression { algo } =>
                    eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } =>
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    },
                MessageLayer::SignatureGroup { ref results } =>
                    for result in results {
                        match result {
                            GoodChecksum { cert, .. } => {
                                eprintln!("Good signature from {}", cert);
                            },
                            NotAlive { sig, .. } => {
                                eprintln!("Good, but not alive signature from {:?}",
                                          sig.get_issuers());
                            },
                            MissingKey { .. } => {
                                eprintln!("No key to check signature");
                            },
                            Error { error, .. } => {
                                eprintln!("Error: {}", error);
                            },
                        }
                    }
            }
        }
        Ok(()) // Implement your verification policy here.
    }
}
