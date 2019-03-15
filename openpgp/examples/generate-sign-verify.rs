/// Generates a key, then signs and verifies a message.

use std::io::{self, Write};

extern crate failure;
extern crate sequoia_openpgp as openpgp;
use openpgp::serialize::stream::*;
use openpgp::parse::stream::*;

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
fn generate() -> openpgp::Result<openpgp::TPK> {
    let (tpk, _revocation) = openpgp::tpk::TPKBuilder::default()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(tpk)
}

/// Signs the given message.
fn sign(sink: &mut Write, plaintext: &str, tsk: &openpgp::TPK)
           -> openpgp::Result<()> {
    // Get the keypair to do the signing from the TPK.
    let mut keypair = tsk.keys_valid().signing_capable().nth(0).unwrap().2
        .clone().into_keypair()?;

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to sign a literal data packet.
    let signer = Signer::new(message, vec![&mut keypair])?;

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(
        signer, openpgp::constants::DataFormat::Binary, None, None)?;

    // Sign the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

/// Verifies the given message.
fn verify(sink: &mut Write, signed_message: &[u8], sender: &openpgp::TPK)
          -> openpgp::Result<()> {
    // Make a helper that that feeds the sender's public key to the
    // verifier.
    let helper = Helper {
        tpk: sender,
    };

    // Now, create a verifier with a helper using the given TPKs.
    let mut verifier = Verifier::from_bytes(signed_message, helper)?;

    // Verify the data.
    io::copy(&mut verifier, sink)?;

    Ok(())
}

struct Helper<'a> {
    tpk: &'a openpgp::TPK,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyID])
                       -> openpgp::Result<Vec<openpgp::TPK>> {
        // Return public keys for signature verification here.
        Ok(vec![self.tpk.clone()])
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
             -> openpgp::Result<()> {
        // In this function, we implement our signature verification
        // policy.

        // First, we are interested in signatures over the data,
        // i.e. level 0 signatures.
        let sigs_over_data = sigs.get(0)
            .ok_or_else(|| failure::err_msg("No level 0 signatures found"))?;

        // Now, let's see if there is a signature on that level.
        let sig_result = sigs_over_data.get(0)
            .ok_or_else(|| failure::err_msg("No signature found"))?;

        // Finally, given a VerificationResult, which only says
        // whether the signature checks out mathematically, we apply
        // our policy.
        match sig_result {
            VerificationResult::GoodChecksum(_) =>
                Ok(()), // Good signature
            VerificationResult::MissingKey(_) =>
                Err(failure::err_msg("Missing key to verify signature")),
            VerificationResult::BadChecksum(_) =>
                Err(failure::err_msg("Bad signature")),
        }
    }
}
