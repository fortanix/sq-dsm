use std::{env, io::Write};

use sequoia_openpgp as openpgp;

use openpgp::serialize::{stream::*, SerializeInto};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;

use super::PgpAgent;

const TEST_ENV: &'static str = ".test.env";
const TEST_ENV_API_KEY: &'static str = "TEST_SQ_SDKMS_API_KEY";
const TEST_ENV_API_ENDPOINT: &'static str = "TEST_SQ_SDKMS_API_ENDPOINT";
const KEY_NAME: &'static str = "SundayTesting";

use std::sync::Once;

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| {
        dotenv::from_filename(TEST_ENV).ok();
        PgpAgent::generate_key(
            &env::var(TEST_ENV_API_ENDPOINT).unwrap(),
            &env::var(TEST_ENV_API_KEY).unwrap(),
            &KEY_NAME,
        ).unwrap();
    });
}

#[test]
fn armored_public_key() {
    init();
    let agent = PgpAgent::summon(
        &env::var(TEST_ENV_API_ENDPOINT).unwrap(),
        &env::var(TEST_ENV_API_KEY).unwrap(),
        &KEY_NAME,
    ).unwrap();

    let armored = agent.certificate.armored().to_vec().unwrap();

    assert_eq!(&armored[..36], "-----BEGIN PGP PUBLIC KEY BLOCK-----".as_bytes());
}

#[test]
fn armored_signature() {
    init();
    let agent = PgpAgent::summon(
        &env::var(TEST_ENV_API_ENDPOINT).unwrap(),
        &env::var(TEST_ENV_API_KEY).unwrap(),
        &KEY_NAME,
    ).unwrap();

    const MESSAGE: &'static str = "дружба\nRoyale With Cheese\n ";

    // Sign the message.
    let mut signed_message = Vec::new();
    agent.sign(&mut signed_message, MESSAGE.as_bytes(), true, true).unwrap();
}

#[test]
fn encrypt_decrypt_roundtrip() {
    init();
    const MESSAGE: &'static str = "дружба\nRoyale With Cheese\n ";

    let agent = PgpAgent::summon(
        &env::var(TEST_ENV_API_ENDPOINT).unwrap(),
        &env::var(TEST_ENV_API_KEY).unwrap(),
        &KEY_NAME,
    ).unwrap();

    // Encrypt the message.
    let mut ciphertext = Vec::new();
    let p = &StandardPolicy::new();
    encrypt(p, &mut ciphertext, MESSAGE, &agent.certificate).unwrap();

    // Decrypt the message.
    let mut plaintext = Vec::new();
    agent.decrypt(&mut plaintext, &ciphertext, &StandardPolicy::new()).unwrap();

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
