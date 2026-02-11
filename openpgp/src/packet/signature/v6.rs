//! OpenPGP v6 signature implementation.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::{
    Error,
    HashAlgorithm,
    Packet,
    PublicKeyAlgorithm,
    Result,
    SignatureType,
    crypto::mpi,
    packet::{
        Signature,
        signature::{
            Signature4,
            subpacket::{
                SubpacketArea,
            },
        },
    },
};

/// Holds a v6 Signature packet.
///
/// This holds a [version 6] Signature packet.  Normally, you won't
/// directly work with this data structure, but with the [`Signature`]
/// enum, which is version agnostic.  An exception is when you need to
/// do version-specific operations.  But currently, there aren't any
/// version-specific methods.
///
///   [version 6]: https://www.rfc-editor.org/rfc/rfc9580.html#name-versions-4-and-6-signature-
///   [`Signature`]: super::Signature
#[derive(Clone)]
pub struct Signature6 {
    pub(crate) common: Signature4,
    salt: Vec<u8>,
}
assert_send_and_sync!(Signature6);

impl TryFrom<Signature> for Signature6 {
    type Error = anyhow::Error;

    fn try_from(sig: Signature) -> Result<Self> {
        match sig {
            Signature::V6(sig) => Ok(sig),
            sig => Err(
                Error::InvalidArgument(
                    format!(
                        "Got a v{}, require a v6 signature",
                        sig.version()))
                    .into()),
        }
    }
}

// Yes, Signature6 derefs to Signature4.  This is because Signature
// derefs to Signature4 so this is the only way to add support for v6
// sigs without breaking the semver.
impl Deref for Signature6 {
    type Target = Signature4;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for Signature6 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

impl fmt::Debug for Signature6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signature6")
            .field("version", &self.version())
            .field("typ", &self.typ())
            .field("pk_algo", &self.pk_algo())
            .field("hash_algo", &self.hash_algo())
            .field("hashed_area", self.hashed_area())
            .field("unhashed_area", self.unhashed_area())
            .field("additional_issuers", &self.additional_issuers)
            .field("digest_prefix",
                   &crate::fmt::to_hex(&self.digest_prefix, false))
            .field("salt", &crate::fmt::hex::encode(&self.salt))
            .field(
                "computed_digest",
                &self
                    .computed_digest
                    .get()
                    .map(|hash| crate::fmt::to_hex(&hash[..], false)),
            )
            .field("level", &self.level)
            .field("mpis", &self.mpis)
            .finish()
    }
}

impl PartialEq for Signature6 {
    /// This method tests for self and other values to be equal, and
    /// is used by ==.
    ///
    /// This method compares the serialized version of the two
    /// packets.  Thus, the computed values are ignored ([`level`],
    /// [`computed_digest`]).
    ///
    /// [`level`]: Signature6::level()
    /// [`computed_digest`]: Signature6::computed_digest()
    fn eq(&self, other: &Signature6) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Signature6 {}

impl PartialOrd for Signature6 {
    fn partial_cmp(&self, other: &Signature6) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature6 {
    fn cmp(&self, other: &Signature6) -> Ordering {
        self.common.cmp(&other.common)
            .then_with(|| self.salt.cmp(&other.salt))
    }
}

impl std::hash::Hash for Signature6 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use std::hash::Hash as StdHash;
        StdHash::hash(&self.common, state);
        StdHash::hash(&self.salt, state);
    }
}

impl Signature6 {
    /// Creates a new signature packet from common fields and salt.
    pub(crate) fn from_common(mut common: Signature4, salt: Vec<u8>)
                              -> Result<Self>
    {
        common.fields.version = 6;
        Ok(Signature6 { common, salt })
    }

    /// Creates a new signature packet.
    ///
    /// If you want to sign something, consider using the
    /// [`SignatureBuilder`] interface.
    ///
    /// [`SignatureBuilder`]: crate::packet::signature::SignatureBuilder
    pub fn new(typ: SignatureType, pk_algo: PublicKeyAlgorithm,
               hash_algo: HashAlgorithm, hashed_area: SubpacketArea,
               unhashed_area: SubpacketArea,
               digest_prefix: [u8; 2],
               salt: Vec<u8>,
               mpis: mpi::Signature) -> Result<Self> {
        Signature6::from_common(
            Signature4::new(typ, pk_algo, hash_algo,
                            hashed_area, unhashed_area,
                            digest_prefix, mpis),
            salt)
    }

    /// Gets the public key algorithm.
    // SigantureFields::pk_algo is private, because we don't want it
    // available on SignatureBuilder, which also derefs to
    // &SignatureFields.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.fields.pk_algo()
    }

    /// Gets the hash prefix.
    pub fn digest_prefix(&self) -> &[u8; 2] {
        &self.digest_prefix
    }

    /// Sets the hash prefix.
    #[allow(dead_code)]
    pub(crate) fn set_digest_prefix(&mut self, prefix: [u8; 2]) -> [u8; 2] {
        ::std::mem::replace(&mut self.digest_prefix, prefix)
    }

    /// Gets the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Sets the salt.
    #[allow(dead_code)]
    pub(crate) fn set_salt(&mut self, salt: Vec<u8>) -> Vec<u8> {
        ::std::mem::replace(&mut self.salt, salt)
    }

    /// Gets the signature packet's MPIs.
    pub fn mpis(&self) -> &mpi::Signature {
        &self.mpis
    }

    /// Sets the signature packet's MPIs.
    #[allow(dead_code)]
    pub(crate) fn set_mpis(&mut self, mpis: mpi::Signature) -> mpi::Signature
    {
        ::std::mem::replace(&mut self.mpis, mpis)
    }

    /// Gets the computed hash value.
    ///
    /// This is set by the [`PacketParser`] when parsing the message.
    ///
    /// [`PacketParser`]: crate::parse::PacketParser
    pub fn computed_digest(&self) -> Option<&[u8]> {
        self.computed_digest.get().map(|d| &d[..])
    }

    /// Gets the signature level.
    ///
    /// A level of 0 indicates that the signature is directly over the
    /// data, a level of 1 means that the signature is a notarization
    /// over all level 0 signatures and the data, and so on.
    pub fn level(&self) -> usize {
        self.level
    }

    /// Returns whether this signature should be exported.
    ///
    /// This checks whether the [`Exportable Certification`] subpacket
    /// is absent or present and 1, and that the signature does not
    /// include any sensitive [`Revocation Key`] (designated revokers)
    /// subpackets.
    ///
    ///   [`Exportable Certification`]: https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification
    ///   [`Revocation Key`]: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key-deprecated
    pub fn exportable(&self) -> Result<()> {
        if ! self.exportable_certification().unwrap_or(true) {
            return Err(Error::InvalidOperation(
                "Cannot export non-exportable certification".into()).into());
        }

        if self.revocation_keys().any(|r| r.sensitive()) {
            return Err(Error::InvalidOperation(
                "Cannot export signature with sensitive designated revoker"
                    .into()).into());
        }

        Ok(())
    }
}

impl From<Signature6> for Packet {
    fn from(s: Signature6) -> Self {
        Packet::Signature(s.into())
    }
}

impl From<Signature6> for super::Signature {
    fn from(s: Signature6) -> Self {
        super::Signature::V6(s)
    }
}

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};
#[cfg(test)]
use crate::packet::signature::ArbitraryBounded;

#[cfg(test)]
impl ArbitraryBounded for Signature6 {
    fn arbitrary_bounded(g: &mut Gen, depth: usize) -> Self {
        let common = Signature4::arbitrary_bounded(g, depth);
        let salt_size = common.hash_algo().salt_size().unwrap_or(16);
        let mut salt = vec![0u8; salt_size];
        salt.iter_mut().for_each(|p| *p = u8::arbitrary(g));
        Self::from_common(common, salt)
            .expect("salt has the right size")
    }
}

#[cfg(test)]
impl_arbitrary_with_bound!(Signature6);
