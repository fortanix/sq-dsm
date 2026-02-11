#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::{Corpus, fuzz_target};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    Result,
    crypto::SessionKey,
    packet::prelude::*,
    parse::{Parse, stream::*},
    policy::StandardPolicy,
    types::*,
};

const P: &StandardPolicy = &StandardPolicy::new();
const CERT_BYTES: &[u8; 665] = b"
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
lcBgLJq0MVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
cGxlLm9yZz6IkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
CJG8sDyO2FhzDrg4BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
mKQ5PeqXJbWEtVrUtVJaPwMBCAeIeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
=bbbT
-----END PGP PUBLIC KEY BLOCK-----
";
static CERT: LazyLock<Cert> = LazyLock::new(|| Cert::from_bytes(CERT_BYTES).unwrap());
static SK: LazyLock<SessionKey> = LazyLock::new(|| Vec::new().into());


fuzz_target!(|data: &[u8]| -> Corpus {
    struct Helper {}
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _ids: &[KeyHandle])
                     -> openpgp::Result<Vec<Cert>> {
            Ok(vec![CERT.clone()])
        }

        fn check(&mut self, structure: MessageStructure)
                 -> openpgp::Result<()> {
            for (i, layer) in structure.into_iter().enumerate() {
                match layer {
                    MessageLayer::Encryption { .. } if i == 0 => (),
                    MessageLayer::Compression { .. } if i == 1 => (),
                    MessageLayer::SignatureGroup { ref results } => {
                        if ! results.iter().any(|r| r.is_ok()) {
                            return Err(anyhow::anyhow!(
                                "No valid signature"));
                        }
                    }
                    _ => return Err(anyhow::anyhow!(
                        "Unexpected message structure")),
                }
            }
            Ok(())
        }
    }
    impl DecryptionHelper for Helper {
        fn decrypt(
            &mut self,
            _: &[PKESK],
            _: &[SKESK],
            _sym_algo: Option<SymmetricAlgorithm>,
            decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
        ) -> Result<Option<openpgp::Cert>> {
            decrypt(Some(SymmetricAlgorithm::AES128), &SK);
            Ok(Some(CERT.clone()))
        }
    }

    let h = Helper {};
    if let Ok(mut v) = DecryptorBuilder::from_bytes(data)
        .and_then(|b| b.with_policy(P, None, h))
    {
        let _ = std::io::copy(&mut v, &mut std::io::sink());
        Corpus::Keep
    } else {
        Corpus::Keep
    }
});
