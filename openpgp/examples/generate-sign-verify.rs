/// Generates a key, then signs and verifies a message.

use std::io::{self, Write};

extern crate failure;
extern crate sequoia_openpgp as openpgp;
use crate::openpgp::serialize::stream::*;
use crate::openpgp::parse::stream::*;

const MESSAGE: &'static str = "дружба";

fn main() {
    // Generate a key.
    let key = generate().unwrap();

    // Sign the message.
    let mut signed_message = Vec::new();
    sign(&mut signed_message, MESSAGE, &key).unwrap();

    // Verify the message.
    let mut plaintext = Vec::new();
    verify(&mut plaintext, &signed_message, &key).unwrap();

    assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
}

/// Generates an signing-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = openpgp::cert::CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(cert)
}

/// Signs the given message.
fn sign(sink: &mut dyn Write, plaintext: &str, tsk: &openpgp::Cert)
           -> openpgp::Result<()> {
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk.keys().alive().revoked(false).for_signing().nth(0).unwrap()
        .key().clone().mark_parts_secret().unwrap().into_keypair()?;

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to sign a literal data packet.
    let signer = Signer::new(message, keypair).build()?;

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(signer).build()?;

    // Sign the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

/// Verifies the given message.
fn verify(sink: &mut dyn Write, signed_message: &[u8], sender: &openpgp::Cert)
          -> openpgp::Result<()> {
    // Make a helper that that feeds the sender's public key to the
    // verifier.
    let helper = Helper {
        cert: sender,
    };

    // Now, create a verifier with a helper using the given Certs.
    let mut verifier = Verifier::from_bytes(signed_message, helper, None)?;

    // Verify the data.
    io::copy(&mut verifier, sink)?;

    Ok(())
}

struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: &MessageStructure)
             -> openpgp::Result<()> {
        // In this function, we implement our signature verification
        // policy.

        let mut good = false;
        for (i, layer) in structure.iter().enumerate() {
            match (i, layer) {
                // First, we are interested in signatures over the
                // data, i.e. level 0 signatures.
                (0, MessageLayer::SignatureGroup { ref results }) => {
                    // Finally, given a VerificationResult, which only says
                    // whether the signature checks out mathematically, we apply
                    // our policy.
                    match results.get(0) {
                        Some(VerificationResult::GoodChecksum { .. }) =>
                            good = true,
                        Some(VerificationResult::NotAlive { .. }) =>
                            return Err(failure::err_msg(
                                "Signature good, but not alive")),
                        Some(VerificationResult::MissingKey { .. }) =>
                            return Err(failure::err_msg(
                                "Missing key to verify signature")),
                        Some(VerificationResult::BadChecksum { .. }) =>
                            return Err(failure::err_msg("Bad signature")),
                        None =>
                            return Err(failure::err_msg("No signature")),
                    }
                },
                _ => return Err(failure::err_msg(
                    "Unexpected message structure")),
            }
        }

        if good {
            Ok(()) // Good signature.
        } else {
            Err(failure::err_msg("Signature verification failed"))
        }
    }
}
