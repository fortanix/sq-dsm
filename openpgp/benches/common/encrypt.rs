use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};

use std::io::Write;

// naively encrypt, without caring for revocation or expiration
pub fn encrypt_to_cert(
    bytes: &[u8],
    cert: &Cert,
) -> openpgp::Result<Vec<u8>> {
    let mut sink = vec![];
    let p = &StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(p, None)
        .supported()
        .for_transport_encryption()
        .for_storage_encryption();
    let message =
        Encryptor::for_recipients(Message::new(&mut sink), recipients)
            .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(sink)
}

pub fn encrypt_with_password(
    bytes: &[u8],
    password: &str,
) -> openpgp::Result<Vec<u8>> {
    let mut sink = vec![];
    let message =
        Encryptor::with_passwords(Message::new(&mut sink), Some(password))
            .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(sink)
}
