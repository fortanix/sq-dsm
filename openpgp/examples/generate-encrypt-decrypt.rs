/// Generates a key, then encrypts and decrypts a message.

use std::io::{self, Write};

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::constants::SymmetricAlgorithm;
use crate::openpgp::serialize::stream::*;
use crate::openpgp::packet::KeyFlags;
use crate::openpgp::parse::stream::*;

const MESSAGE: &'static str = "дружба";

fn main() {
    // Generate a key.
    let key = generate().unwrap();

    // Encrypt the message.
    let mut ciphertext = Vec::new();
    encrypt(&mut ciphertext, MESSAGE, &key).unwrap();

    // Decrypt the message.
    let mut plaintext = Vec::new();
    decrypt(&mut plaintext, &ciphertext, &key).unwrap();

    assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
}

/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::TPK> {
    let (tpk, _revocation) = openpgp::tpk::TPKBuilder::new()
        .add_userid("someone@example.org")
        .add_encryption_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(tpk)
}

/// Encrypts the given message.
fn encrypt(sink: &mut Write, plaintext: &str, recipient: &openpgp::TPK)
           -> openpgp::Result<()> {
    // Build a vector of recipients to hand to Encryptor.
    let recipients =
        recipient.keys_valid()
        .key_flags(KeyFlags::default()
                   .set_encrypt_at_rest(true)
                   .set_encrypt_for_transport(true))
        .map(|(_, _, key)| key.into())
        .collect::<Vec<_>>();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::new(message,
                                   &[], // No symmetric encryption.
                                   &recipients,
                                   None, None)?;

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(
        encryptor, openpgp::constants::DataFormat::Binary, None, None)?;

    // Encrypt the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

/// Decrypts the given message.
fn decrypt(sink: &mut Write, ciphertext: &[u8], recipient: &openpgp::TPK)
           -> openpgp::Result<()> {
    // Make a helper that that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        secret: recipient,
    };

    // Now, create a decryptor with a helper using the given TPKs.
    let mut decryptor = Decryptor::from_bytes(ciphertext, helper, None)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::TPK,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyID])
                       -> openpgp::Result<Vec<openpgp::TPK>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: &MessageStructure)
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
        // The encryption key is the first and only subkey.
        let key = self.secret.subkeys().nth(0)
            .map(|binding| binding.key().clone())
            .unwrap();

        // The secret key is not encrypted.
        let mut pair = key.mark_parts_secret().into_keypair().unwrap();

        pkesks[0].decrypt(&mut pair)
            .and_then(|(algo, session_key)| decrypt(algo, &session_key))
            .map(|_| None)
        // XXX: In production code, return the Fingerprint of the
        // recipient's TPK here
    }
}
