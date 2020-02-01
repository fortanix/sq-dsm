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
    pub fn new() -> Self {
        Self::default()
    }
}

impl Policy for StandardPolicy {
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cert::CertBuilder;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn badbadbad() {
        let p = &P::new();

        // A primary and two subkeys.
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        assert_eq!(cert.keys().set_policy(p, None).count(), 3);

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
        assert_eq!(cert.keys().set_policy(p, None).count(), 0);

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
        assert_eq!(cert.keys().set_policy(p, None).count(), 1);
    }
}
