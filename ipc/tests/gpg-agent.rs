//! Tests gpg-agent interaction.

use std::io::{self, Write};

extern crate futures;
use futures::future::Future;
use futures::stream::Stream;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::types::{
    HashAlgorithm,
    SymmetricAlgorithm,
};
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::parse::{Parse, stream::*};
use crate::openpgp::serialize::{Serialize, stream::*};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::Policy;

extern crate sequoia_ipc as ipc;
use crate::ipc::gnupg::{Context, Agent, KeyPair};

macro_rules! make_context {
    () => {{
        let ctx = match Context::ephemeral() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is GnuPG installed?", e);
                return Ok(());
            },
        };
        match ctx.start("gpg-agent") {
            Ok(_) => (),
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is the GnuPG agent installed?", e);
                return Ok(());
            },
        }
        ctx
    }};
}

#[test]
fn nop() -> openpgp::Result<()> {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).wait().unwrap();
    agent.send("NOP").unwrap();
    let response = agent.wait().collect::<Vec<_>>();
    assert_eq!(response.len(), 1);
    assert!(response[0].is_ok());
    Ok(())
}

#[test]
fn help() -> openpgp::Result<()>  {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).wait().unwrap();
    agent.send("HELP").unwrap();
    let response = agent.wait().collect::<Vec<_>>();
    assert!(response.len() > 3);
    assert!(response.iter().last().unwrap().is_ok());
    Ok(())
}

const MESSAGE: &'static str = "дружба";

fn gpg_import(ctx: &Context, what: &[u8]) {
    use std::process::{Command, Stdio};

    let mut gpg = Command::new("gpg")
        .stdin(Stdio::piped())
        .arg("--homedir").arg(ctx.directory("homedir").unwrap())
        .arg("--import")
        .spawn()
        .expect("failed to start gpg");
    gpg.stdin.as_mut().unwrap().write_all(what).unwrap();
    let status = gpg.wait().unwrap();
    assert!(status.success());
}

#[test]
fn sign() -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_signing_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf);

        let keypair = KeyPair::new(
            &ctx,
            cert.keys().with_policy(p, None).alive().revoked(false)
                .for_signing().take(1).next().unwrap().key())
            .unwrap();

        let mut message = Vec::new();
        {
            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to sign a literal data packet.
            let signer = Signer::new(message, keypair)
                 // XXX: Is this necessary?  If so, it shouldn't.
                .hash_algo(HashAlgorithm::SHA512).unwrap()
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                signer).build().unwrap();

            // Sign the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: &cert };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier = VerifierBuilder::from_bytes(&message)?
            .with_policy(p, None, helper)?;

        // Verify the data.
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);
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
                            Some(Ok(_)) => good = true,
                            Some(Err(e)) =>
                                return Err(openpgp::Error::from(e).into()),
                            None => (),
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
    Ok(())
}

#[test]
fn decrypt() -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_transport_encryption_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf);

        let mut message = Vec::new();
        {
            let recipients =
                cert.keys().with_policy(p, None).alive().revoked(false)
                .for_transport_encryption()
                .map(|ka| ka.key())
                .collect::<Vec<_>>();

            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to encrypt a literal data packet.
            let encryptor =
                Encryptor::for_recipients(message, recipients)
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                encryptor).build().unwrap();

            // Encrypt the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the recipient's secret key to the
        // decryptor.
        let helper = Helper { policy: p, ctx: &ctx, cert: &cert, };

        // Now, create a decryptor with a helper using the given Certs.
        let mut decryptor = DecryptorBuilder::from_bytes(&message).unwrap()
            .with_policy(p, None, helper).unwrap();

        // Decrypt the data.
        let mut sink = Vec::new();
        io::copy(&mut decryptor, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);

        struct Helper<'a> {
            policy: &'a dyn Policy,
            ctx: &'a Context,
            cert: &'a openpgp::Cert,
        }

        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
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
                          sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D)
                          -> openpgp::Result<Option<openpgp::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) ->
                      openpgp::Result<()>
            {
                let mut keypair = KeyPair::new(
                    self.ctx,
                    self.cert.keys().with_policy(self.policy, None)
                        .for_storage_encryption().for_transport_encryption()
                        .take(1).next().unwrap().key())
                    .unwrap();

                pkesks[0].decrypt(&mut keypair, sym_algo)
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                    .map(|_| None)
                // XXX: In production code, return the Fingerprint of the
                // recipient's Cert here
            }
        }
    }
    Ok(())
}
