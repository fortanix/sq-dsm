use std::ops::Deref;

use crate::{
    HashAlgorithm,
    Result,
    SignatureType,
};
use crate::constants::{
    ReasonForRevocation,
};
use crate::crypto::hash::Hash;
use crate::crypto::Signer;
use crate::packet::{
    key,
    signature,
    Signature,
};
use crate::tpk::TPK;

/// A `TPK` revocation builder.
///
/// Note: a TPK revocation has two degrees of freedom: the TPK, and
/// the key used to generate the revocation.
///
/// Normally, the key used to generate the revocation is the TPK's
/// primary key.  However, this is not required.
///
/// If Alice has marked Robert's key (R) as a designated revoker
/// for her key (A), then R can revoke A or parts of A.  In this
/// case, the TPK is A, and the key used to generate the
/// revocation comes from R.
///
/// # Example
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// use openpgp::RevocationStatus;
/// use openpgp::constants::{ReasonForRevocation, SignatureType};
/// use openpgp::tpk::{CipherSuite, TPKBuilder, TPKRevocationBuilder};
/// use openpgp::crypto::KeyPair;
/// use openpgp::parse::Parse;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()>
/// # {
/// let (tpk, _) = TPKBuilder::new()
///     .set_cipher_suite(CipherSuite::Cv25519)
///     .generate()?;
/// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
///            tpk.revoked(None));
///
/// let mut signer = tpk.primary().clone()
///     .mark_parts_secret().into_keypair()?;
/// let sig = TPKRevocationBuilder::new()
///     .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
///                                b"It was the maid :/")?
///     .build(&mut signer, &tpk, None)?;
/// assert_eq!(sig.typ(), SignatureType::KeyRevocation);
///
/// let tpk = tpk.merge_packets(vec![sig.clone().into()])?;
/// assert_eq!(RevocationStatus::Revoked(vec![&sig]),
///            tpk.revoked(None));
/// # Ok(())
/// # }
pub struct TPKRevocationBuilder {
    builder: signature::Builder,
}

impl TPKRevocationBuilder {
    /// Returns a new `TPKRevocationBuilder`.
    pub fn new() -> Self {
        Self {
            builder:
                signature::Builder::new(SignatureType::KeyRevocation)
        }
    }

    /// Sets the reason for revocation.
    pub fn set_reason_for_revocation(self, code: ReasonForRevocation,
                                     reason: &[u8])
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_reason_for_revocation(code, reason)?
        })
    }

    /// Sets the revocation signature's creation time.
    pub fn set_signature_creation_time(self, creation_time: time::Tm)
        -> Result<Self>
    {
        Ok(Self {
            builder: self.builder.set_signature_creation_time(creation_time)?
        })
    }

    /// Returns a revocation certificate for the tpk `TPK` signed by
    /// `signer`.
    pub fn build<H, R>(self, signer: &mut Signer<R>, tpk: &TPK, hash_algo: H)
        -> Result<Signature>
        where H: Into<Option<HashAlgorithm>>,
              R: key::KeyRole
    {
        let hash_algo = hash_algo.into().unwrap_or(HashAlgorithm::SHA512);
        let mut hash = hash_algo.context()?;

        tpk.primary().hash(&mut hash);

        let creation_time
            = self.signature_creation_time().unwrap_or_else(time::now);

        self.builder
            // If not set, set it to now.
            .set_signature_creation_time(creation_time)?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .sign_hash(signer, hash_algo, hash)
    }
}

impl Deref for TPKRevocationBuilder {
    type Target = signature::Builder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}
