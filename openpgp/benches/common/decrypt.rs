use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::packet::{PKESK, SKESK};
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{Fingerprint, KeyHandle, Result};

use std::io::Write;

// Borrowed from the examples at
// sequoia_openpgp::parse::stream::DecryptionHelper
// sequoia_openpgp::parse::stream::Decryptor
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
    fn decrypt<D>(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
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

// This is marked as dead_code. Seems that using a function only from within
// a benchmark loop hides it from the compiler.
#[allow(dead_code)]
// Decrypts the given message using the given password.
pub fn decrypt_with_password(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    password: &str,
) -> sequoia_openpgp::Result<()> {
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
// sequoia_openpgp::parse::stream::DecryptionHelper
// sequoia_openpgp::parse::stream::Decryptor
struct CertHelper<'a> {
    cert: &'a Cert,
}

impl VerificationHelper for CertHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for CertHelper<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let p = &StandardPolicy::new();

        // check that pkesk has right recipient
        // if yes, use decrypt function
        let keys: Vec<Key<key::SecretParts, key::UnspecifiedRole>> = self
            .cert
            .keys()
            .with_policy(p, None)
            .for_transport_encryption()
            .for_storage_encryption()
            .secret()
            .map(|amalgamation| amalgamation.key().clone().into())
            .collect();

        let successful_key = keys
            .iter()
            .cloned()
            .filter_map(|key| {
                pkesks
                    .into_iter()
                    .find(|pkesk| pkesk.recipient() == &key.keyid())
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
            Some(key) => Ok(Some(key)),
            None => Err(anyhow::anyhow!("Wrong cert!")),
        }
    }
}

// This is marked as dead_code. Seems that using a function only from within
// a benchmark loop hides it from the compiler.
#[allow(dead_code)]
// Decrypts the given message using the given password.
pub fn decrypt_with_cert(
    sink: &mut dyn Write,
    ciphertext: &[u8],
    cert: &Cert,
) -> sequoia_openpgp::Result<()> {
    // Make a helper that that feeds the password to the decryptor.
    let helper = CertHelper { cert };

    // Now, create a decryptor with a helper using the given Certs.
    let p = &StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    std::io::copy(&mut decryptor, sink)?;

    Ok(())
}
