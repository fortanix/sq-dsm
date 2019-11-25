/// Decrypts asymmetrically-encrypted OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::collections::HashMap;
use std::env;
use std::io;

extern crate failure;
extern crate sequoia_openpgp as openpgp;

use crate::openpgp::crypto::{KeyPair, SessionKey};
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::packet::key;
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
    let tpks =
        args[1..].iter().map(|f| {
            openpgp::TPK::from_file(f)
                .expect("Failed to read key")
        }).collect();

    // Now, create a decryptor with a helper using the given TPKs.
    let mut decryptor =
        Decryptor::from_reader(io::stdin(), Helper::new(tpks), None).unwrap();

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::stdout())
        .expect("Decryption failed");
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper {
    keys: HashMap<openpgp::KeyID, KeyPair<key::UnspecifiedRole>>,
}

impl Helper {
    /// Creates a Helper for the given TPKs with appropriate secrets.
    fn new(tpks: Vec<openpgp::TPK>) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for tpk in tpks {
            for (sig, _, key) in tpk.keys_all() {
                if sig.map(|s| (s.key_flags().can_encrypt_at_rest()
                                || s.key_flags().can_encrypt_for_transport()))
                    .unwrap_or(false)
                {
                    // This only works for unencrypted secret keys.
                    if let Ok(keypair) =
                        key.clone().mark_parts_secret().unwrap().into_keypair()
                    {
                        keys.insert(key.keyid(), keypair);
                    }
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
        // recipient's TPK here
        Ok(None)
    }
}

impl VerificationHelper for Helper {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyID])
                       -> failure::Fallible<Vec<openpgp::TPK>> {
        Ok(Vec::new()) // Feed the TPKs to the verifier here.
    }
    fn check(&mut self, structure: &MessageStructure)
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
                            GoodChecksum(ref sig, ..) => {
                                let issuer = sig.issuer()
                                    .expect("good checksum has an issuer");
                                eprintln!("Good signature from {}", issuer);
                            },
                            NotAlive(ref sig) => {
                                let issuer = sig.issuer()
                                    .expect("not alive has an issuer");
                                eprintln!("Good, but not alive signature from {}",
                                          issuer);
                            },
                            MissingKey(ref sig) => {
                                let issuer = sig.issuer()
                                    .expect("missing key checksum has an \
                                             issuer");
                                eprintln!("No key to check signature from {}",
                                          issuer);
                            },
                            BadChecksum(ref sig) =>
                                if let Some(issuer) = sig.issuer() {
                                    eprintln!("Bad signature from {}", issuer);
                                } else {
                                    eprintln!("Bad signature without issuer \
                                               information");
                                },
                        }
                    }
            }
        }
        Ok(()) // Implement your verification policy here.
    }
}
