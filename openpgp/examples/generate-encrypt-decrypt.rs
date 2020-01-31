/// Generates a key, then encrypts and decrypts a message.

use std::io::{self, Write};

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::serialize::stream::*;
use crate::openpgp::parse::stream::*;
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;

const MESSAGE: &'static str = "дружба";

fn main() {
    let p = &P::new();

    // Generate a key.
    let key = generate().unwrap();

    // Encrypt the message.
    let mut ciphertext = Vec::new();
    encrypt(p, &mut ciphertext, MESSAGE, &key).unwrap();

    // Decrypt the message.
    let mut plaintext = Vec::new();
    decrypt(p, &mut plaintext, &ciphertext, &key).unwrap();

    assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
}

/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = openpgp::cert::CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(cert)
}

/// Encrypts the given message.
fn encrypt(p: &dyn Policy, sink: &mut dyn Write, plaintext: &str,
           recipient: &openpgp::Cert)
    -> openpgp::Result<()>
{
    // Build a vector of recipients to hand to Encryptor.
    let mut recipients =
        recipient.keys().set_policy(p, None).alive().revoked(false)
        .for_transport_encryption()
        .map(|ka| ka.key().into())
        .collect::<Vec<_>>();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let mut encryptor = Encryptor::for_recipient(
        message, recipients.pop().expect("No encryption key found"));
    for r in recipients {
        encryptor = encryptor.add_recipient(r)
    }
    let encryptor = encryptor.build().expect("Failed to create encryptor");

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(encryptor).build()?;

    // Encrypt the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

/// Decrypts the given message.
fn decrypt(p: &dyn Policy,
           sink: &mut dyn Write, ciphertext: &[u8], recipient: &openpgp::Cert)
           -> openpgp::Result<()> {
    // Make a helper that that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        secret: recipient,
        policy: p,
    };

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor = Decryptor::from_bytes(p, ciphertext, helper, None)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::Cert,
    policy: &'a Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure)
             -> openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
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
        let key = self.secret.keys().set_policy(self.policy, None)
            .for_transport_encryption().nth(0).unwrap().key().clone();

        // The secret key is not encrypted.
        let mut pair = key.mark_parts_secret().unwrap().into_keypair().unwrap();

        pkesks[0].decrypt(&mut pair)
            .and_then(|(algo, session_key)| decrypt(algo, &session_key))
            .map(|_| None)
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
    }
}
