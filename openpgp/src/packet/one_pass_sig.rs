//! One-pass signature packets.
//!
//! See [One-Pass Signature Packet] for details.
//!
//! [One-Pass Signature Packet]: https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::{
    Error,
    KeyHandle,
    Result,
    packet::{
        Packet,
        Signature,
    },
    types::{
        SignatureType,
        PublicKeyAlgorithm,
        HashAlgorithm,
    },
};

mod v3;
pub use v3::OnePassSig3;
mod v6;
pub use v6::OnePassSig6;

/// Holds a one-pass signature packet.
///
/// See [One-Pass Signature Packet] for details.
///
/// A `OnePassSig` packet is not normally instantiated directly.  In
/// most cases, you'll create one as a side effect of signing a
/// message using the [streaming serializer], or parsing a signed
/// message using the [`PacketParser`].
///
/// [One-Pass Signature Packet]: https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t
/// [`PacketParser`]: crate::parse::PacketParser
/// [streaming serializer]: crate::serialize::stream
#[non_exhaustive]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum OnePassSig {
    /// OnePassSig packet version 3.
    V3(OnePassSig3),

    /// OnePassSig packet version 6.
    V6(OnePassSig6),
}
assert_send_and_sync!(OnePassSig);

impl OnePassSig {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            OnePassSig::V3(_) => 3,
            OnePassSig::V6(_) => 6,
        }
    }

    /// Gets the signature type.
    pub fn typ(&self) -> SignatureType {
        match self {
            OnePassSig::V3(p) => p.typ(),
            OnePassSig::V6(p) => p.typ(),
        }
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        match self {
            OnePassSig::V3(p) => p.pk_algo(),
            OnePassSig::V6(p) => p.pk_algo(),
        }
    }

    /// Gets the hash algorithm.
    pub fn hash_algo(&self) -> HashAlgorithm {
        match self {
            OnePassSig::V3(p) => p.hash_algo(),
            OnePassSig::V6(p) => p.hash_algo(),
        }
    }

    /// Gets the salt, if any.
    pub fn salt(&self) -> Option<&[u8]> {
        match self {
            OnePassSig::V3(_) => None,
            OnePassSig::V6(p) => Some(p.salt()),
        }
    }

    /// Gets the issuer.
    pub fn issuer(&self) -> KeyHandle {
        match self {
            OnePassSig::V3(p) => p.issuer().into(),
            OnePassSig::V6(p) => p.issuer().into(),
        }
    }

    /// Gets the last flag.
    pub fn last(&self) -> bool {
        match self {
            OnePassSig::V3(p) => p.last(),
            OnePassSig::V6(p) => p.last(),
        }
    }

    /// Sets the last flag.
    pub fn set_last(&mut self, last: bool) -> bool {
        match self {
            OnePassSig::V3(p) => p.set_last(last),
            OnePassSig::V6(p) => p.set_last(last),
        }
    }

    /// Gets the raw value of the last flag.
    pub fn last_raw(&self) -> u8 {
        match self {
            OnePassSig::V3(p) => p.last_raw(),
            OnePassSig::V6(p) => p.last_raw(),
        }
    }
}

impl From<OnePassSig> for Packet {
    fn from(s: OnePassSig) -> Self {
        Packet::OnePassSig(s)
    }
}

impl<'a> std::convert::TryFrom<&'a Signature> for OnePassSig {
    type Error = anyhow::Error;

    fn try_from(s: &'a Signature) -> Result<Self> {
        match s.version() {
            3 | 4 => OnePassSig3::try_from(s).map(Into::into),
            6 => OnePassSig6::try_from(s).map(Into::into),
            n => Err(Error::InvalidOperation(
                format!("Unsupported signature version {}", n)).into()),
        }
    }
}

#[cfg(test)]
impl Arbitrary for super::OnePassSig {
    fn arbitrary(g: &mut Gen) -> Self {
        if Arbitrary::arbitrary(g) {
            OnePassSig3::arbitrary(g).into()
        } else {
            OnePassSig6::arbitrary(g).into()
        }
    }
}
