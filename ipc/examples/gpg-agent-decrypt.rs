/// Decrypts data using the openpgp crate and secrets in gpg-agent.

use std::collections::HashMap;
use std::io;

extern crate clap;
extern crate sequoia_openpgp as openpgp;
extern crate sequoia_ipc as ipc;

use crate::openpgp::crypto::SessionKey;
use crate::openpgp::constants::SymmetricAlgorithm;
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
        .arg(clap::Arg::with_name("tpk").value_name("TPK")
             .required(true)
             .multiple(true)
             .help("Public part of the secret keys managed by gpg-agent"))
        .get_matches();

    let ctx = if let Some(homedir) = matches.value_of("homedir") {
        Context::with_homedir(homedir).unwrap()
    } else {
        Context::new().unwrap()
    };

    // Read the TPKs from the given files.
    let tpks =
        matches.values_of("tpk").expect("required").map(|f| {
            openpgp::TPK::from_file(f)
                .expect("Failed to read key")
        }).collect();

    // Now, create a decryptor with a helper using the given TPKs.
    let mut decryptor =
        Decryptor::from_reader(io::stdin(), Helper::new(&ctx, tpks), None)
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
    keys: HashMap<openpgp::KeyID, openpgp::packet::key::UnspecifiedPublic>,
}

impl<'a> Helper<'a> {
    /// Creates a Helper for the given TPKs with appropriate secrets.
    fn new(ctx: &'a Context, tpks: Vec<openpgp::TPK>) -> Self {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for tpk in tpks {
            for (sig, _, key) in tpk.keys_all() {
                if sig.map(|s| (s.key_flags().can_encrypt_at_rest()
                                || s.key_flags().can_encrypt_for_transport()))
                    .unwrap_or(false)
                {
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
        // recipient's TPK here
        Ok(None)
    }
}

impl<'a> VerificationHelper for Helper<'a> {
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
                                    .expect("Good, but not live signature has an \
                                             issuer");
                                eprintln!("Good, but not live signature from {}",
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
