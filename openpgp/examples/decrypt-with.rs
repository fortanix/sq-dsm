/// Decrypts asymmetrically-encrypted OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::collections::HashMap;
use std::env;
use std::io;

extern crate failure;
extern crate sequoia_openpgp as openpgp;

use openpgp::packet::key::SecretKey;
use openpgp::parse::{
    Parse,
    stream::{
        DecryptionHelper,
        Decryptor,
        Secret,
        VerificationHelper,
        VerificationResult,
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
        Decryptor::from_reader(io::stdin(), Helper::new(tpks)).unwrap();

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::stdout())
        .expect("Decryption failed");
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper {
    keys: HashMap<openpgp::KeyID, Secret>,
    i: usize,
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
                    // Only handle unencrypted secret keys.
                    if let Some(SecretKey::Unencrypted { ref mpis }) =
                        key.secret()
                    {
                        keys.insert(key.fingerprint().to_keyid(),
                                    Secret::Asymmetric {
                                        identity: tpk.fingerprint(),
                                        key: key.clone(),
                                        secret: mpis.clone(),
                                    });
                    }
                }
            }
        }

        Helper {
            keys: keys,
            i: 0,
        }
    }
}

impl DecryptionHelper for Helper {
    fn get_secret(&mut self,
                  pkesks: &[&openpgp::packet::PKESK],
                  _: &[&openpgp::packet::SKESK])
                  -> failure::Fallible<Option<Secret>> {
        let r = pkesks
            .iter()
            .nth(self.i)
            .and_then(|pkesk| {
                self.keys.get(pkesk.recipient())
                    .map(|s| (*s).clone())
            });
        self.i += 1;
        Ok(r)
    }
}

impl VerificationHelper for Helper {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyID])
                       -> failure::Fallible<Vec<openpgp::TPK>> {
        Ok(Vec::new()) // Feed the TPKs to the verifier here.
    }
    fn check(&mut self, _sigs: Vec<Vec<VerificationResult>>)
             -> failure::Fallible<()> {
        Ok(()) // Implement your verification policy here.
    }
}
