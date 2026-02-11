use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::prelude::*;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure,
    VerificationHelper, VerifierBuilder,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{KeyHandle, Result};

use std::io::Write;

// Borrowed from the examples at
// openpgp::parse::stream::DecryptionHelper
// openpgp::parse::stream::Decryptor
struct PasswordHelper {
    password: Password,
}

impl VerificationHelper for PasswordHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for PasswordHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>>
    {
        // Finally, try to decrypt using the SKESKs.
        for skesk in skesks {
            if skesk
                .decrypt(&self.password)
                .map(|(algo, sk)| decrypt(algo, &sk))
                .unwrap_or(false)
            {
                return Ok(None);
            }
        }

        Err(anyhow::anyhow!("Wrong password!"))
    }
}

/// Decrypts the given message using the given password.
pub fn decrypt_with_password(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    password: &str,
) -> openpgp::Result<()> {
    let password = password.into();
    // Make a helper that that feeds the password to the decryptor.
    let helper = PasswordHelper { password };

    // Now, create a decryptor with a helper using the given Certs.
    let p = &StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    std::io::copy(&mut decryptor, sink)?;

    Ok(())
}

// Borrowed from the examples at
// openpgp::parse::stream::DecryptionHelper
// openpgp::parse::stream::Decryptor
struct CertHelper<'a> {
    sender: Option<&'a Cert>,
    recipient: Option<&'a Cert>,
}

impl VerificationHelper for CertHelper<'_> {
    // get candidates for having created the signature
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = Vec::new();
        // maybe check that the cert matches (one of the) ids
        if let Some(sender) = self.sender {
            certs.push(sender.clone());
        }
        Ok(certs)
    }
    // does the signature match the policy
    // e.g. am I the intended recipient
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for (i, layer) in structure.into_iter().enumerate() {
            match layer {
                MessageLayer::Encryption { .. } if i == 0 => (),
                MessageLayer::Compression { .. } if i == 0 || i == 1 => (),
                MessageLayer::SignatureGroup { ref results }
                    if i == 0 || i == 1 || i == 2 =>
                {
                    if !results.iter().any(|r| r.is_ok()) {
                        for result in results {
                            let error = result.as_ref().err().unwrap();
                            println!("{:?}", error);
                        }
                        return Err(anyhow::anyhow!("No valid signature"));
                    }
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unexpected message structure {:?} at level {}",
                        layer,
                        i
                    ))
                }
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for CertHelper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>>
    {
        let p = &StandardPolicy::new();

        let cand_secret_keys: Vec<Key<key::SecretParts, key::UnspecifiedRole>> =
            self.recipient
                .expect("Cannot decrypt without recipient's cert.")
                .keys()
                .with_policy(p, None)
                .for_transport_encryption()
                .for_storage_encryption()
                .secret()
                .map(|amalgamation| amalgamation.key().clone())
                .collect();

        // check that pkesk has right recipient
        // if yes, use decrypt function
        let successful_key = cand_secret_keys
            .iter()
            .cloned()
            .filter_map(|key| {
                pkesks
                    .iter()
                    .find(|pkesk| pkesk.recipient().map(
                        |r| r.aliases(&key.key_handle())).unwrap_or(false))
                    .map(|pkesk| (pkesk, key))
            })
            .find(|(pkesk, key)| {
                let mut keypair = key.clone().into_keypair().unwrap();
                pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .map(|(algo, sk)| decrypt(algo, &sk))
                    .unwrap_or(false)
            })
            .map(|(_, key)| key.fingerprint());

        match successful_key {
            Some(_) => Ok(self.recipient.cloned()),
            None => Err(anyhow::anyhow!("Wrong cert!")),
        }
    }
}

/// Decrypts the given message using the given password.
pub fn decrypt_with_cert(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    cert: &Cert,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the password to the decryptor.
    let helper = CertHelper {
        sender: None,
        recipient: Some(cert),
    };

    // Now, create a decryptor with a helper using the given Certs.
    let p = &StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    std::io::copy(&mut decryptor, sink)?;

    Ok(())
}

/// Decrypts the given message using the given password.
pub fn decrypt_and_verify(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    sender: &Cert,
    recipient: &Cert,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the password to the decryptor.
    let helper = CertHelper {
        sender: Some(sender),
        recipient: Some(recipient),
    };

    // Now, create a decryptor with a helper using the given Certs.
    let p = &StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    std::io::copy(&mut decryptor, sink)?;

    Ok(())
}

/// Verifies the given message using the given sender's cert.
pub fn verify(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    sender: &Cert,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the sender's cert to the verifier.
    let helper = CertHelper {
        sender: Some(sender),
        recipient: None,
    };

    // Now, create a verifier with a helper using the given Certs.
    let p = &StandardPolicy::new();
    let mut verifier = VerifierBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Verify the data.
    std::io::copy(&mut verifier, sink)?;

    Ok(())
}
