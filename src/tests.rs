use super::PgpAgent;

use std::io::Write;

use sequoia_openpgp as openpgp;

use openpgp::serialize::{stream::*, SerializeInto};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;

const API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";
const MY_API_KEY: &'static str = "YOUR_API_KEY";
const KEY_NAME: &'static str = "MyKey";

#[test]
fn generate() {
    PgpAgent::generate_key(
        &API_ENDPOINT,
        &MY_API_KEY,
        &KEY_NAME,
    ).unwrap();
}

#[test]
fn armored_public_key() {
    let agent = PgpAgent::summon(
        &API_ENDPOINT,
        &MY_API_KEY,
        &KEY_NAME,
    ).unwrap();

    let armored = agent.certificate.armored().to_vec().unwrap();

    assert_eq!(&armored[..36], "-----BEGIN PGP PUBLIC KEY BLOCK-----".as_bytes());

    {
        use std::io::{self, Write};
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        handle.write_all(&armored).unwrap();
    }
}

#[test]
fn armored_signature() {
    let agent = PgpAgent::summon(
        &API_ENDPOINT,
        &MY_API_KEY,
        &KEY_NAME,
    ).unwrap();

    const MESSAGE: &'static str = "дружба\nRoyale With Cheese\n ";

    // Sign the message.
    let mut signed_message = Vec::new();
    agent.sign(&mut signed_message, MESSAGE.as_bytes()).unwrap();

    {
        use std::io::{self, Write};
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        handle.write_all(&signed_message).unwrap();
    }
}

#[test]
fn encrypt_decrypt_roundtrip() {
    const MESSAGE: &'static str = "дружба\nRoyale With Cheese\n ";

    let agent = PgpAgent::summon(
        &API_ENDPOINT,
        &MY_API_KEY,
        &KEY_NAME,
    ).unwrap();

    // Encrypt the message.
    let mut ciphertext = Vec::new();
    let p = &StandardPolicy::new();
    encrypt(p, &mut ciphertext, MESSAGE, &agent.certificate).unwrap();

    // Stdout the message
    {
        use std::io::{self, Write};
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        handle.write_all(&ciphertext).unwrap();
    }

    // Decrypt the message.
    let mut plaintext = Vec::new();
    agent.decrypt(&mut plaintext, &ciphertext).unwrap();

    assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
}

/// Encrypts the given message.
fn encrypt(p: &dyn Policy, sink: &mut (dyn Write + Send + Sync),
           plaintext: &str, recipient: &openpgp::Cert)
    -> openpgp::Result<()>
{
    let recipients =
        recipient.keys().with_policy(p, None).supported().alive().revoked(false)
        .for_transport_encryption();

    let message = Message::new(sink);

    let message = Armorer::new(message).build().unwrap();

    let message = Encryptor::for_recipients(message, recipients)
        .build()?;

    let mut message = LiteralWriter::new(message).build()?;

    message.write_all(plaintext.as_bytes())?;

    message.finalize()?;

    Ok(())
}
