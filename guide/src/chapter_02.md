Describes key creation, encryption, and decryption.

In this chapter, we will see how to use Sequoia's [low-level API] to
generate an OpenPGP key, and use it to encrypt and decrypt some data.
We will construct this program from top to bottom, concatenating the
fragments yields the [`openpgp/examples/generate-encrypt-decrypt.rs`].

[low-level API]: ../../sequoia_openpgp/index.html
[`openpgp/examples/generate-encrypt-decrypt.rs`]: https://gitlab.com/sequoia-pgp/sequoia/blob/master/openpgp/examples/generate-encrypt-decrypt.rs

```rust
use std::io::{self, Write};

extern crate sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::serialize::stream::*;
use openpgp::parse::stream::*;

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
#
# /// Generates an encryption-capable key.
# fn generate() -> openpgp::Result<openpgp::Cert> {
#     let (cert, _revocation) = openpgp::cert::CertBuilder::new()
#         .add_userid("someone@example.org")
#         .add_transport_encryption_subkey()
#         .generate()?;
#
#     // Save the revocation certificate somewhere.
#
#     Ok(cert)
# }
#
# /// Encrypts the given message.
# fn encrypt(sink: &mut Write, plaintext: &str, recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#    // Build a vector of recipients to hand to Encryptor.
#    let mut recipients =
#        recipient.keys().alive().revoked(false)
#        .for_transport_encryption()
#        .map(|ka| ka.key().into())
#        .collect::<Vec<_>>();
#
#     // Start streaming an OpenPGP message.
#     let message = Message::new(sink);
#
#     // We want to encrypt a literal data packet.
#     let mut encryptor = Encryptor::for_recipient(
#         message, recipients.pop().expect("No encryption key found"));
#     for r in recipients {
#         encryptor = encryptor.add_recipient(r)
#     }
#     let encryptor = encryptor.build().expect("Failed to create encryptor");
#
#     // Emit a literal data packet.
#     let mut literal_writer = LiteralWriter::new(encryptor).build()?;
#
#     // Encrypt the data.
#     literal_writer.write_all(plaintext.as_bytes())?;
#
#     // Finalize the OpenPGP message to make sure that all data is
#     // written.
#     literal_writer.finalize()?;
#
#     Ok(())
# }
#
# /// Decrypts the given message.
# fn decrypt(sink: &mut Write, ciphertext: &[u8], recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#     // Make a helper that that feeds the recipient's secret key to the
#     // decryptor.
#     let helper = Helper {
#         secret: recipient,
#     };
#
#     // Now, create a decryptor with a helper using the given Certs.
#     let mut decryptor = Decryptor::from_bytes(ciphertext, helper, None)?;
#
#     // Decrypt the data.
#     io::copy(&mut decryptor, sink)?;
#
#     Ok(())
# }
#
# struct Helper<'a> {
#     secret: &'a openpgp::Cert,
# }
#
# impl<'a> VerificationHelper for Helper<'a> {
#     fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
#                        -> openpgp::Result<Vec<openpgp::Cert>> {
#         // Return public keys for signature verification here.
#         Ok(Vec::new())
#     }
#
#     fn check(&mut self, _structure: &MessageStructure)
#              -> openpgp::Result<()> {
#         // Implement your signature verification policy here.
#         Ok(())
#     }
# }
#
# impl<'a> DecryptionHelper for Helper<'a> {
#     fn decrypt<D>(&mut self,
#                   pkesks: &[openpgp::packet::PKESK],
#                   _skesks: &[openpgp::packet::SKESK],
#                   mut decrypt: D)
#                   -> openpgp::Result<Option<openpgp::Fingerprint>>
#         where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
#     {
#         // The encryption key is the first and only subkey.
#         let key = self.secret.subkeys().nth(0)
#             .map(|binding| binding.key().clone())
#             .unwrap();
#
#         // The secret key is not encrypted.
#         let mut pair = key.mark_parts_secret().unwrap().into_keypair().unwrap();
#
#         pkesks[0].decrypt(&mut pair)
#             .and_then(|(algo, session_key)| decrypt(algo, &session_key))
#             .map(|_| None)
#         // XXX: In production code, return the Fingerprint of the
#         // recipient's Cert here
#     }
# }
```

# Key generation

First, we need to generate a new key.  This key shall have one user
id, and one encryption-capable subkey.  We use the [`CertBuilder`] to
create it:

[`CertBuilder`]: ../../sequoia_openpgp/cert/struct.CertBuilder.html

```rust
# use std::io::{self, Write};
#
# extern crate sequoia_openpgp as openpgp;
# use openpgp::crypto::SessionKey;
# use openpgp::types::SymmetricAlgorithm;
# use openpgp::serialize::stream::*;
# use openpgp::parse::stream::*;
#
# const MESSAGE: &'static str = "дружба";
#
# fn main() {
#     // Generate a key.
#     let key = generate().unwrap();
#
#     // Encrypt the message.
#     let mut ciphertext = Vec::new();
#     encrypt(&mut ciphertext, MESSAGE, &key).unwrap();
#
#     // Decrypt the message.
#     let mut plaintext = Vec::new();
#     decrypt(&mut plaintext, &ciphertext, &key).unwrap();
#
#     assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
# }
#
/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = openpgp::cert::CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(cert)
}
#
# /// Encrypts the given message.
# fn encrypt(sink: &mut Write, plaintext: &str, recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#    // Build a vector of recipients to hand to Encryptor.
#    let mut recipients =
#        recipient.keys().alive().revoked(false)
#        .for_transport_encryption()
#        .map(|ka| ka.key().into())
#        .collect::<Vec<_>>();
#
#     // Start streaming an OpenPGP message.
#     let message = Message::new(sink);
#
#     // We want to encrypt a literal data packet.
#     let mut encryptor = Encryptor::for_recipient(
#         message, recipients.pop().expect("No encryption key found"));
#     for r in recipients {
#         encryptor = encryptor.add_recipient(r)
#     }
#     let encryptor = encryptor.build().expect("Failed to create encryptor");
#
#     // Emit a literal data packet.
#     let mut literal_writer = LiteralWriter::new(encryptor).build()?;
#
#     // Encrypt the data.
#     literal_writer.write_all(plaintext.as_bytes())?;
#
#     // Finalize the OpenPGP message to make sure that all data is
#     // written.
#     literal_writer.finalize()?;
#
#     Ok(())
# }
#
# /// Decrypts the given message.
# fn decrypt(sink: &mut Write, ciphertext: &[u8], recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#     // Make a helper that that feeds the recipient's secret key to the
#     // decryptor.
#     let helper = Helper {
#         secret: recipient,
#     };
#
#     // Now, create a decryptor with a helper using the given Certs.
#     let mut decryptor = Decryptor::from_bytes(ciphertext, helper, None)?;
#
#     // Decrypt the data.
#     io::copy(&mut decryptor, sink)?;
#
#     Ok(())
# }
#
# struct Helper<'a> {
#     secret: &'a openpgp::Cert,
# }
#
# impl<'a> VerificationHelper for Helper<'a> {
#     fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
#                        -> openpgp::Result<Vec<openpgp::Cert>> {
#         // Return public keys for signature verification here.
#         Ok(Vec::new())
#     }
#
#     fn check(&mut self, _structure: &MessageStructure)
#              -> openpgp::Result<()> {
#         // Implement your signature verification policy here.
#         Ok(())
#     }
# }
#
# impl<'a> DecryptionHelper for Helper<'a> {
#     fn decrypt<D>(&mut self,
#                   pkesks: &[openpgp::packet::PKESK],
#                   _skesks: &[openpgp::packet::SKESK],
#                   mut decrypt: D)
#                   -> openpgp::Result<Option<openpgp::Fingerprint>>
#         where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
#     {
#         // The encryption key is the first and only subkey.
#         let key = self.secret.subkeys().nth(0)
#             .map(|binding| binding.key().clone())
#             .unwrap();
#
#         // The secret key is not encrypted.
#         let mut pair = key.mark_parts_secret().unwrap().into_keypair().unwrap();
#
#         pkesks[0].decrypt(&mut pair)
#             .and_then(|(algo, session_key)| decrypt(algo, &session_key))
#             .map(|_| None)
#         // XXX: In production code, return the Fingerprint of the
#         // recipient's Cert here
#     }
# }
```

# Encryption

To encrypt a message, we first compose a writer stack corresponding to
the desired output format and packet structure.  The resulting object
implements [`io::Write`], and we simply write the plaintext to it.

[`io::Write`]: https://doc.rust-lang.org/std/io/trait.Write.html

```rust
# use std::io::{self, Write};
#
# extern crate sequoia_openpgp as openpgp;
# use openpgp::crypto::SessionKey;
# use openpgp::types::SymmetricAlgorithm;
# use openpgp::serialize::stream::*;
# use openpgp::parse::stream::*;
#
# const MESSAGE: &'static str = "дружба";
#
# fn main() {
#     // Generate a key.
#     let key = generate().unwrap();
#
#     // Encrypt the message.
#     let mut ciphertext = Vec::new();
#     encrypt(&mut ciphertext, MESSAGE, &key).unwrap();
#
#     // Decrypt the message.
#     let mut plaintext = Vec::new();
#     decrypt(&mut plaintext, &ciphertext, &key).unwrap();
#
#     assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
# }
#
# /// Generates an encryption-capable key.
# fn generate() -> openpgp::Result<openpgp::Cert> {
#     let (cert, _revocation) = openpgp::cert::CertBuilder::new()
#         .add_userid("someone@example.org")
#         .add_transport_encryption_subkey()
#         .generate()?;
#
#     // Save the revocation certificate somewhere.
#
#     Ok(cert)
# }
#
/// Encrypts the given message.
fn encrypt(sink: &mut Write, plaintext: &str, recipient: &openpgp::Cert)
           -> openpgp::Result<()> {
    // Build a vector of recipients to hand to Encryptor.
    let mut recipients =
        recipient.keys().alive().revoked(false)
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
#
# /// Decrypts the given message.
# fn decrypt(sink: &mut Write, ciphertext: &[u8], recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#     // Make a helper that that feeds the recipient's secret key to the
#     // decryptor.
#     let helper = Helper {
#         secret: recipient,
#     };
#
#     // Now, create a decryptor with a helper using the given Certs.
#     let mut decryptor = Decryptor::from_bytes(ciphertext, helper, None)?;
#
#     // Decrypt the data.
#     io::copy(&mut decryptor, sink)?;
#
#     Ok(())
# }
#
# struct Helper<'a> {
#     secret: &'a openpgp::Cert,
# }
#
# impl<'a> VerificationHelper for Helper<'a> {
#     fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
#                        -> openpgp::Result<Vec<openpgp::Cert>> {
#         // Return public keys for signature verification here.
#         Ok(Vec::new())
#     }
#
#     fn check(&mut self, _structure: &MessageStructure)
#              -> openpgp::Result<()> {
#         // Implement your signature verification policy here.
#         Ok(())
#     }
# }
#
# impl<'a> DecryptionHelper for Helper<'a> {
#     fn decrypt<D>(&mut self,
#                   pkesks: &[openpgp::packet::PKESK],
#                   _skesks: &[openpgp::packet::SKESK],
#                   mut decrypt: D)
#                   -> openpgp::Result<Option<openpgp::Fingerprint>>
#         where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
#     {
#         // The encryption key is the first and only subkey.
#         let key = self.secret.subkeys().nth(0)
#             .map(|binding| binding.key().clone())
#             .unwrap();
#
#         // The secret key is not encrypted.
#         let mut pair = key.mark_parts_secret().unwrap().into_keypair().unwrap();
#
#         pkesks[0].decrypt(&mut pair)
#             .and_then(|(algo, session_key)| decrypt(algo, &session_key))
#             .map(|_| None)
#         // XXX: In production code, return the Fingerprint of the
#         // recipient's Cert here
#     }
# }
```

# Decryption

Decryption is more difficult than encryption.  When we encrypt, we
control the packet structure being generated.  However, when we
decrypt, the control flow is determined by the message being
processed.

To use Sequoia's low-level streaming decryptor, we need to provide an
object that implements [`VerificationHelper`] and
[`DecryptionHelper`].  This object provides public and secret keys for
the signature verification and decryption, and implements the
signature verification policy.

[`VerificationHelper`]: ../../sequoia_openpgp/parse/stream/trait.VerificationHelper.html
[`DecryptionHelper`]: ../../sequoia_openpgp/parse/stream/trait.DecryptionHelper.html

To decrypt messages, we create a [`Decryptor`] with our helper.
Decrypted data can be read from this using [`io::Read`].

[`Decryptor`]: ../../sequoia_openpgp/parse/stream/struct.Decryptor.html
[`io::Read`]: https://doc.rust-lang.org/std/io/trait.Read.html

```rust
# use std::io::{self, Write};
#
# extern crate sequoia_openpgp as openpgp;
# use openpgp::crypto::SessionKey;
# use openpgp::types::SymmetricAlgorithm;
# use openpgp::serialize::stream::*;
# use openpgp::parse::stream::*;
#
# const MESSAGE: &'static str = "дружба";
#
# fn main() {
#     // Generate a key.
#     let key = generate().unwrap();
#
#     // Encrypt the message.
#     let mut ciphertext = Vec::new();
#     encrypt(&mut ciphertext, MESSAGE, &key).unwrap();
#
#     // Decrypt the message.
#     let mut plaintext = Vec::new();
#     decrypt(&mut plaintext, &ciphertext, &key).unwrap();
#
#     assert_eq!(MESSAGE.as_bytes(), &plaintext[..]);
# }
#
# /// Generates an encryption-capable key.
# fn generate() -> openpgp::Result<openpgp::Cert> {
#     let (cert, _revocation) = openpgp::cert::CertBuilder::new()
#         .add_userid("someone@example.org")
#         .add_transport_encryption_subkey()
#         .generate()?;
#
#     // Save the revocation certificate somewhere.
#
#     Ok(cert)
# }
#
# /// Encrypts the given message.
# fn encrypt(sink: &mut Write, plaintext: &str, recipient: &openpgp::Cert)
#            -> openpgp::Result<()> {
#    // Build a vector of recipients to hand to Encryptor.
#    let mut recipients =
#        recipient.keys().alive().revoked(false)
#        .for_transport_encryption()
#        .map(|ka| ka.key().into())
#        .collect::<Vec<_>>();
#
#     // Start streaming an OpenPGP message.
#     let message = Message::new(sink);
#
#     // We want to encrypt a literal data packet.
#     let mut encryptor = Encryptor::for_recipient(
#         message, recipients.pop().expect("No encryption key found"));
#     for r in recipients {
#         encryptor = encryptor.add_recipient(r)
#     }
#     let encryptor = encryptor.build().expect("Failed to create encryptor");
#
#     // Emit a literal data packet.
#     let mut literal_writer = LiteralWriter::new(encryptor).build()?;
#
#     // Encrypt the data.
#     literal_writer.write_all(plaintext.as_bytes())?;
#
#     // Finalize the OpenPGP message to make sure that all data is
#     // written.
#     literal_writer.finalize()?;
#
#     Ok(())
# }
#
/// Decrypts the given message.
fn decrypt(sink: &mut Write, ciphertext: &[u8], recipient: &openpgp::Cert)
           -> openpgp::Result<()> {
    // Make a helper that that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        secret: recipient,
    };

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor = Decryptor::from_bytes(ciphertext, helper, None)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
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
        let mut pair = key.mark_parts_secret().unwrap().into_keypair().unwrap();

        pkesks[0].decrypt(&mut pair)
            .and_then(|(algo, session_key)| decrypt(algo, &session_key))
            .map(|_| None)
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
    }
}
```

# Further reading

For more examples on how to read a key from a file, and then either
encrypt or decrypt some messages, see
[`openpgp/examples/encrypt-for.rs`] and
[`openpgp/examples/decrypt-with.rs`].

[`openpgp/examples/encrypt-for.rs`]: https://gitlab.com/sequoia-pgp/sequoia/blob/master/openpgp/examples/encrypt-for.rs
[`openpgp/examples/decrypt-with.rs`]: https://gitlab.com/sequoia-pgp/sequoia/blob/master/openpgp/examples/decrypt-with.rs
