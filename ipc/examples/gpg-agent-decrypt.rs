/// Decrypts data using the openpgp crate and secrets in gpg-agent.

use std::collections::HashMap;
use std::io;

extern crate clap;
extern crate sequoia_openpgp as openpgp;
extern crate sequoia_ipc as ipc;

use crate::openpgp::crypto::SessionKey;
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
use crate::ipc::gnupg::{Context, KeyPair};

fn main() {
    let matches = clap::App::new("gpg-agent-decrypt")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connects to gpg-agent and decrypts a message.")
        .arg(clap::Arg::with_name("homedir").value_name("PATH")
             .long("homedir")
             .help("Use this GnuPG home directory, default: $GNUPGHOME"))
        .arg(clap::Arg::with_name("cert").value_name("Cert")
             .required(true)
             .multiple(true)
             .help("Public part of the secret keys managed by gpg-agent"))
        .get_matches();

    let ctx = if let Some(homedir) = matches.value_of("homedir") {
        Context::with_homedir(homedir).unwrap()
    } else {
        Context::new().unwrap()
    };

    // Read the Certs from the given files.
    let certs =
        matches.values_of("cert").expect("required").map(|f| {
            openpgp::Cert::from_file(f)
                .expect("Failed to read key")
        }).collect();

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor =
        Decryptor::from_reader(io::stdin(), Helper::new(&ctx, certs), None)
        .unwrap();

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::stdout())
        .expect("Decryption failed");
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper<'a> {
    ctx: &'a Context,
    keys: HashMap<openpgp::KeyID,
                  openpgp::packet::Key<key::PublicParts, key::UnspecifiedRole>>,
}

impl<'a> Helper<'a> {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(ctx: &'a Context, certs: Vec<openpgp::Cert>) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for cert in certs {
            for ka in cert.keys().policy(None) {
                if ka.binding_signature(None)
                    .map(|s| (s.key_flags().for_storage_encryption()
                              || s.key_flags().for_transport_encryption()))
                    .unwrap_or(false)
                {
                    let key = ka.key();
                    keys.insert(key.keyid(), key.clone().into());
                }
            }
        }

        Helper { ctx, keys, }
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self,
                  pkesks: &[openpgp::packet::PKESK],
                  _skesks: &[openpgp::packet::SKESK],
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            if let Some(key) = self.keys.get(pkesk.recipient()) {
                let mut pair = KeyPair::new(self.ctx, key)?;
                if let Ok(_) = pkesk.decrypt(&mut pair)
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

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                       -> failure::Fallible<Vec<openpgp::Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here.
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
                            GoodChecksum { cert, .. } => {
                                eprintln!("Good signature from {}", cert);
                            },
                            NotAlive { cert, .. } => {
                                eprintln!("Good, but not alive signature from {}",
                                          cert);
                            },
                            MissingKey { .. } => {
                                eprintln!("No key to check signature");
                            },
                            BadChecksum { cert, .. } => {
                                eprintln!("Bad signature from {}", cert);
                            },
                        }
                    }
            }
        }
        Ok(()) // Implement your verification policy here.
    }
}
