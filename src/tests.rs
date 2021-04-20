use super::PgpAgent;

use std::io::{self, Write};

use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::serialize::{stream::*, SerializeInto};
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;

const API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";
const MY_API_KEY: &'static str = "YjI1Y2M4NzUtZTNhOC00MmE5LTk1OWYtOGI0N2IyMDE2OWFmOnl4TThQWWdhclBWVzhQajRBZkVZcUNYM292TUVRVkRYbWh2d1V2OUxLeTB0UDY4eTFJZld2TlJFbmZTckxGdHIwZ25NVk9NMlhWTmZEalNSX3VzRVZB";

#[test]
#[ignore = "generates a key in SDKMS"]
fn generate() {
    PgpAgent::generate_key(
        &API_ENDPOINT,
        &MY_API_KEY,
        "Test"
    ).unwrap();
}

#[test]
fn armored_public_key() {
    let mut agent = PgpAgent::from_key_name(
        &API_ENDPOINT,
        &MY_API_KEY,
        "Test"
    ).unwrap();

    let armored = agent.cert().unwrap().armored().to_vec().unwrap();

    assert_eq!(&armored[..36], "-----BEGIN PGP PUBLIC KEY BLOCK-----".as_bytes());

    {
        use std::io::{self, Write};
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        handle.write_all(&armored).unwrap();
    }
}
#[test]
fn pgp_sign() {
    let mut agent = PgpAgent::from_key_name(
        &API_ENDPOINT,
        &MY_API_KEY,
        "Test"
    ).unwrap();

    const MESSAGE: &'static str = "дружба";

    // Sign the message.
    let mut signed_message = Vec::new();
    agent.sign(&mut signed_message, MESSAGE).unwrap();

    // // Verify the message.
    // let mut plaintext = Vec::new();
    // verify(&mut plaintext, &signed_message, &agent.cert().unwrap());

    // assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
    // println!("{:?}", signed_message);

    {
        use std::io::{self, Write};
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        handle.write_all(&signed_message).unwrap();
    }
}


// From Sequoia-PGP examples.
fn verify(
    sink: &mut dyn Write,
    signed_message: &[u8],
    sender: &openpgp::Cert
    ) -> openpgp::Result<()> {
    // Make a helper that that feeds the sender's public key to the
    // verifier.
    let helper = Helper {
        cert: sender,
    };

    let policy = &StandardPolicy::new();

    // Now, create a verifier with a helper using the given Certs.
    let mut verifier = VerifierBuilder::from_bytes(signed_message)?
        .with_policy(policy, None, helper)?;

    // Verify the data.
    io::copy(&mut verifier, sink)?;

    Ok(())
}

struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure)
             -> openpgp::Result<()> {
        // In this function, we implement our signature verification
        // policy.

        let mut good = false;
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                // First, we are interested in signatures over the
                // data, i.e. level 0 signatures.
                (0, MessageLayer::SignatureGroup { results }) => {
                    // Finally, given a VerificationResult, which only says
                    // whether the signature checks out mathematically, we apply
                    // our policy.
                    match results.into_iter().next() {
                        Some(Ok(_)) =>
                            good = true,
                        Some(Err(e)) =>
                            return Err(openpgp::Error::from(e).into()),
                        None =>
                            return Err(anyhow::anyhow!("No signature")),
                    }
                },
                _ => return Err(anyhow::anyhow!(
                    "Unexpected message structure")),
            }
        }

        if good {
            Ok(()) // Good signature.
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}
