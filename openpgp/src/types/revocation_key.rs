use quickcheck::{Arbitrary, Gen};

use crate::{
    cert::prelude::*,
    Error,
    Fingerprint,
    Result,
    types::{
        PublicKeyAlgorithm,
    },
};

/// Designates a key as a valid third-party revoker.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevocationKey {
    /// The public key algorithm used by the authorized key.
    pk_algo: PublicKeyAlgorithm,

    /// Fingerprint of authorized key.
    fp: Fingerprint,

    /// Indicates that the relation between revoker and revokee is
    /// of a sensitive nature.
    sensitive: bool,

    /// Other bits are for future expansion to other kinds of
    /// authorizations.
    unknown: u8,
}

impl From<&Cert> for RevocationKey {
    fn from(cert: &Cert) -> Self {
        RevocationKey::new(cert.primary_key().pk_algo(),
                           cert.fingerprint(),
                           false)
    }
}

impl RevocationKey {
    /// Creates a new instance.
    pub fn new(pk_algo: PublicKeyAlgorithm, fp: Fingerprint, sensitive: bool)
               -> Self
    {
        RevocationKey {
            pk_algo, fp, sensitive, unknown: 0,
        }
    }

    /// Creates a new instance from `bits`.
    pub fn from_bits(pk_algo: PublicKeyAlgorithm, fp: Fingerprint, class: u8)
                     -> Result<Self> {
        if class & REVOCATION_KEY_FLAG_MUST_BE_SET == 0 {
            return Err(Error::InvalidArgument(
                "Most significant bit of class must be set".into()).into());
        }
        let sensitive = class & REVOCATION_KEY_FLAG_SENSITIVE > 0;
        let unknown = class & REVOCATION_KEY_MASK_UNKNOWN;
        Ok(RevocationKey {
            pk_algo, fp, sensitive, unknown,
        })
    }

    /// Returns the `class` octet, the sum of all flags.
    pub fn class(&self) -> u8 {
        REVOCATION_KEY_FLAG_MUST_BE_SET
            | if self.sensitive() {
                REVOCATION_KEY_FLAG_SENSITIVE
            } else {
                0
            }
            | self.unknown
    }

    /// Returns the revoker's identity.
    pub fn revoker(&self) -> (PublicKeyAlgorithm, &Fingerprint) {
        (self.pk_algo, &self.fp)
    }

    /// Sets the revoker's identity.
    pub fn set_revoker(&mut self, pk_algo: PublicKeyAlgorithm, fp: Fingerprint)
                       -> (PublicKeyAlgorithm, Fingerprint) {
        let pk_algo = std::mem::replace(&mut self.pk_algo, pk_algo);
        let fp = std::mem::replace(&mut self.fp, fp);
        (pk_algo, fp)
    }

    /// Returns whether or not the relation between revoker and
    /// revokee is of a sensitive nature.
    pub fn sensitive(&self) -> bool {
        self.sensitive
    }

    /// Sets whether or not the relation between revoker and revokee
    /// is of a sensitive nature.
    pub fn set_sensitive(mut self, v: bool) -> Self {
        self.sensitive = v;
        self
    }
}

/// This bit must be set.
const REVOCATION_KEY_FLAG_MUST_BE_SET: u8 = 0x80;

/// Relation is of a sensitive nature.
const REVOCATION_KEY_FLAG_SENSITIVE: u8 = 0x40;

/// Mask covering the unknown bits.
const REVOCATION_KEY_MASK_UNKNOWN: u8 = ! (REVOCATION_KEY_FLAG_MUST_BE_SET
                                           | REVOCATION_KEY_FLAG_SENSITIVE);

impl Arbitrary for RevocationKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        RevocationKey {
            pk_algo: Arbitrary::arbitrary(g),
            fp: Arbitrary::arbitrary(g),
            sensitive: Arbitrary::arbitrary(g),
            unknown: u8::arbitrary(g) & REVOCATION_KEY_MASK_UNKNOWN,
        }
    }
}
