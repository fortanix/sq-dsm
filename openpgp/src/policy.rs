//! A mechanism to specify policy.
//!
//! A major goal of the Sequoia OpenPGP crate is to be policy free.
//! However, many mid-level operations build on low-level primitives.
//! For instance, finding a certificate's primary User ID means
//! examining each of its User IDs and their current self-signature.
//! Some algorithms are considered broken (e.g., MD5) and some are
//! considered weak (e.g. SHA-1).  When dealing with data from an
//! untrusted source, for instance, callers will often prefer to
//! ignore signatures that rely on these algorithms even though [RFC
//! 4880] says that "[i]mplementations MUST implement SHA-1."  When
//! trying to decrypt old archives, however, users probably don't want
//! to ignore keys using MD5, even though [RFC 4880] deprecates MD5.
//!
//! Rather than not provide this mid-level functionality, the `Policy`
//! trait allows callers to specify their prefer policy.  This can be
//! highly customized by providing a custom implementation of the
//! `Policy` trait, or it can be slightly refined by tweaking the
//! `StandardPolicy`'s parameters.
//!
//! When implementing the `Policy` trait, it is *essential* that the
//! functions are [idempotent].  That is, if the same `Policy` is used
//! to determine whether a given `Signature` is valid, it must always
//! return the same value.
//!
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.4
//! [pure]: https://en.wikipedia.org/wiki/Pure_function
use std::fmt;

use crate::{
    packet::Signature,
    Result,
};

/// A policy for cryptographic operations.
pub trait Policy : fmt::Debug {
    /// Returns an error if the signature violates the policy.
    ///
    /// This function performs the last check before the library
    /// decides that a signature is valid.  That is, after the library
    /// has determined that the signature is well-formed, alive, not
    /// revoked, etc., it calls this function to allow you to
    /// implement any additional policy.  For instance, you may reject
    /// signatures that make use of cryptographically insecure
    /// algorithms like SHA-1.
    ///
    /// Note: Whereas it is generally better to reject suspicious
    /// signatures, one should be more liberal when considering
    /// revocations: if you reject a revocation certificate, it may
    /// inadvertently make something else valid!
    fn signature(&self, _sig: &Signature) -> Result<()> {
        Ok(())
    }
}

/// The standard policy.
#[derive(Debug, Clone)]
pub struct StandardPolicy {
}

impl Default for StandardPolicy {
    fn default() -> Self {
        Self {
        }
    }
}

impl<'a> From<&'a StandardPolicy> for Option<&'a dyn Policy> {
    fn from(p: &'a StandardPolicy) -> Self {
        Some(p as &dyn Policy)
    }
}

impl StandardPolicy {
    /// Instantiates a new `StandardPolicy` with the default parameters.
    pub const fn new() -> Self {
        Self {
        }
    }
}

impl Policy for StandardPolicy {
}

#[cfg(test)]
mod test {
    use std::io::Read;

    use super::*;
    use crate::Fingerprint;
    use crate::cert::{Cert, CertBuilder};
    use crate::parse::Parse;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn binding_signature() {
        let p = &P::new();

        // A primary and two subkeys.
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        assert_eq!(cert.keys().with_policy(p, None).count(), 3);

        // Reject all direct key signatures.
        #[derive(Debug)]
        struct NoDirectKeySigs;
        impl Policy for NoDirectKeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    DirectKey => Err(format_err!("direct key!")),
                    _ => Ok(()),
                }
            }
        }

        let p = &NoDirectKeySigs {};
        assert_eq!(cert.keys().with_policy(p, None).count(), 0);

        // Reject all subkey signatures.
        #[derive(Debug)]
        struct NoSubkeySigs;
        impl Policy for NoSubkeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    SubkeyBinding => Err(format_err!("subkey signature!")),
                    _ => Ok(()),
                }
            }
        }

        let p = &NoSubkeySigs {};
        assert_eq!(cert.keys().with_policy(p, None).count(), 1);
    }

    #[test]
    fn revocation() -> Result<()> {
        use crate::cert::UserIDRevocationBuilder;
        use crate::cert::SubkeyRevocationBuilder;
        use crate::types::SignatureType;
        use crate::types::ReasonForRevocation;

        let p = &P::new();

        // A primary and two subkeys.
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()?;

        // Make sure we have all keys and all user ids.
        assert_eq!(cert.keys().with_policy(p, None).count(), 3);
        assert_eq!(cert.userids().with_policy(p, None).count(), 1);

        // Reject all user id signatures.
        #[derive(Debug)]
        struct NoPositiveCertifications;
        impl Policy for NoPositiveCertifications {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    PositiveCertification =>
                        Err(format_err!("positive certification!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoPositiveCertifications {};
        assert_eq!(cert.userids().with_policy(p, None).count(), 0);


        // Revoke it.
        let mut keypair = cert.primary_key().key().clone()
            .mark_parts_secret()?.into_keypair()?;
        let ca = cert.userids().nth(0).unwrap();

        // Generate the revocation for the first and only UserID.
        let revocation =
            UserIDRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyRetired,
                b"Left example.org.")?
            .build(&mut keypair, &cert, ca.userid(), None)?;
        assert_eq!(revocation.typ(), SignatureType::CertificationRevocation);

        // Now merge the revocation signature into the Cert.
        let cert = cert.merge_packets(vec![revocation.clone().into()])?;

        // Check that it is revoked.
        assert_eq!(cert.userids().with_policy(p, None).revoked(false).count(), 0);

        // Reject all user id signatures.
        #[derive(Debug)]
        struct NoCertificationRevocation;
        impl Policy for NoCertificationRevocation {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    CertificationRevocation =>
                        Err(format_err!("certification certification!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoCertificationRevocation {};

        // Check that the user id is no longer revoked.
        assert_eq!(cert.userids().with_policy(p, None).revoked(false).count(), 1);


        // Generate the revocation for the first subkey.
        let subkey = cert.keys().subkeys().nth(0).unwrap();
        let revocation =
            SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyRetired,
                    b"Smells funny.").unwrap()
                .build(&mut keypair, &cert, subkey.key(), None)?;
        assert_eq!(revocation.typ(), SignatureType::SubkeyRevocation);

        // Now merge the revocation signature into the Cert.
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 3);
        let cert = cert.merge_packets(vec![revocation.clone().into()])?;
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 2);

        // Reject all subkey revocations.
        #[derive(Debug)]
        struct NoSubkeyRevocation;
        impl Policy for NoSubkeyRevocation {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                match sig.typ() {
                    SubkeyRevocation =>
                        Err(format_err!("subkey revocation!")),
                    _ => Ok(()),
                }
            }
        }
        let p = &NoSubkeyRevocation {};

        // Check that the key is no longer revoked.
        assert_eq!(cert.keys().with_policy(p, None).revoked(false).count(), 3);

        Ok(())
    }


    #[test]
    fn binary_signature() {
        use crate::crypto::SessionKey;
        use crate::types::SymmetricAlgorithm;
        use crate::packet::{PKESK, SKESK};
        use crate::parse::stream::MessageLayer;
        use crate::parse::stream::MessageStructure;
        use crate::parse::stream::Verifier;
        use crate::parse::stream::Decryptor;
        use crate::parse::stream::VerificationHelper;
        use crate::parse::stream::DecryptionHelper;

        #[derive(PartialEq, Debug)]
        struct VHelper {
            good: usize,
            errors: usize,
            keys: Vec<Cert>,
        }

        impl VHelper {
            fn new(keys: Vec<Cert>) -> Self {
                VHelper {
                    good: 0,
                    errors: 0,
                    keys: keys,
                }
            }
        }

        impl VerificationHelper for VHelper {
            fn get_public_keys(&mut self, _ids: &[crate::KeyHandle])
                -> Result<Vec<Cert>>
            {
                Ok(self.keys.clone())
            }

            fn check(&mut self, structure: MessageStructure) -> Result<()>
            {
                use crate::parse::stream::VerificationResult::*;
                for layer in structure.iter() {
                    match layer {
                        MessageLayer::SignatureGroup { ref results } =>
                            for result in results {
                                eprintln!("result: {:?}", result);
                                match result {
                                    GoodChecksum { .. } => self.good += 1,
                                    Error { .. } => self.errors += 1,
                                    _ => (),
                                }
                            }
                        MessageLayer::Compression { .. } => (),
                        _ => unreachable!(),
                    }
                }

                Ok(())
            }
        }

        impl DecryptionHelper for VHelper {
            fn decrypt<D>(&mut self, _: &[PKESK], _: &[SKESK], _: D)
                          -> Result<Option<Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                unreachable!();
            }
        }

        // Reject all data (binary) signatures.
        #[derive(Debug)]
        struct NoBinarySigantures;
        impl Policy for NoBinarySigantures {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;
                eprintln!("{:?}", sig.typ());
                match sig.typ() {
                    Binary =>
                        Err(format_err!("binary!")),
                    _ => Ok(()),
                }
            }
        }
        let no_binary_signatures = &NoBinarySigantures {};

        // Reject all subkey signatures.
        #[derive(Debug)]
        struct NoSubkeySigs;
        impl Policy for NoSubkeySigs {
            fn signature(&self, sig: &Signature) -> Result<()> {
                use crate::types::SignatureType::*;

                match sig.typ() {
                    SubkeyBinding => Err(format_err!("subkey signature!")),
                    _ => Ok(()),
                }
            }
        }
        let no_subkey_signatures = &NoSubkeySigs {};

        let standard = &P::new();

        let keys = [
            "neal.pgp",
        ].iter()
            .map(|f| Cert::from_bytes(crate::tests::key(f)).unwrap())
            .collect::<Vec<_>>();
        let data = "messages/signed-1.gpg";

        let reference = crate::tests::manifesto();



        // Test Verifier.

        // Standard policy => ok.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Verifier::from_bytes(standard, crate::tests::file(data), h,
                                       crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 1);
        assert_eq!(v.helper_ref().errors, 0);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the subkey.
        let h = VHelper::new(keys.clone());
        let mut v = match Verifier::from_bytes(no_subkey_signatures,
                                   crate::tests::file(data), h,
                                   crate::frozen_time()) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the data signature.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Verifier::from_bytes(no_binary_signatures,
                                       crate::tests::file(data), h,
                                       crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);



        // Test Decryptor.

        // Standard policy.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Decryptor::from_bytes(standard, crate::tests::file(data), h,
                                        crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 1);
        assert_eq!(v.helper_ref().errors, 0);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the subkey.
        let h = VHelper::new(keys.clone());
        let mut v = match Decryptor::from_bytes(no_subkey_signatures,
                                                crate::tests::file(data), h,
                                                crate::frozen_time()) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);


        // Kill the data signature.
        let h = VHelper::new(keys.clone());
        let mut v =
            match Decryptor::from_bytes(no_binary_signatures,
                                        crate::tests::file(data), h,
                                        crate::frozen_time()) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };
        assert!(v.message_processed());
        assert_eq!(v.helper_ref().good, 0);
        assert_eq!(v.helper_ref().errors, 1);

        let mut content = Vec::new();
        v.read_to_end(&mut content).unwrap();
        assert_eq!(reference.len(), content.len());
        assert_eq!(reference, &content[..]);
    }
}
