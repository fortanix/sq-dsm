//! A version 6 one-pass signature packet.

use std::convert::TryFrom;
use std::fmt;
use std::mem;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::{
    Error,
    Fingerprint,
    HashAlgorithm,
    Packet,
    PublicKeyAlgorithm,
    Result,
    SignatureType,
    packet::{
        Signature,
        OnePassSig,
        one_pass_sig::{
            OnePassSig3,
        },
    },
};

/// Holds a version 6 one-pass signature packet.
///
/// This holds a [version 6 One-Pass Signature Packet].  Normally, you won't
/// directly work with this data structure, but with the [`OnePassSig`]
/// enum, which is version agnostic.  An exception is when you need to
/// do version-specific operations.
///
/// [version 6 One-Pass Signature Packet]: https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t
/// [`OnePassSig`]: crate::packet::OnePassSig
///
/// # A note on equality
///
/// The `last` flag is represented as a `u8` and is compared
/// literally, not semantically.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct OnePassSig6 {
    pub(crate) common: OnePassSig3,
    salt: Vec<u8>,
    issuer: Fingerprint,
}
assert_send_and_sync!(OnePassSig6);

impl TryFrom<OnePassSig> for OnePassSig6 {
    type Error = anyhow::Error;

    fn try_from(ops: OnePassSig) -> Result<Self> {
        match ops {
            OnePassSig::V6(ops) => Ok(ops),
            ops => Err(
                Error::InvalidArgument(
                    format!(
                        "Got a v{}, require a v6 one-pass signature",
                        ops.version()))
                    .into()),
        }
    }
}

impl fmt::Debug for OnePassSig6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OnePassSig6")
            .field("typ", &self.typ())
            .field("hash_algo", &self.hash_algo())
            .field("pk_algo", &self.pk_algo())
            .field("salt", &crate::fmt::hex::encode(self.salt()))
            .field("issuer", &self.issuer())
            .field("last", &self.last())
            .finish()
    }
}

impl OnePassSig6 {
    /// Returns a new One-Pass Signature packet.
    pub fn new(typ: SignatureType, issuer: Fingerprint) ->  Self {
        OnePassSig6 {
            common: OnePassSig3::new(typ),
            salt: vec![],
            issuer,
        }
    }

    /// Gets the signature type.
    pub fn typ(&self) -> SignatureType {
        self.common.typ()
    }

    /// Sets the signature type.
    pub fn set_type(&mut self, t: SignatureType) -> SignatureType {
        self.common.set_type(t)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.common.pk_algo()
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm) -> PublicKeyAlgorithm {
        self.common.set_pk_algo(algo)
    }

    /// Gets the hash algorithm.
    pub fn hash_algo(&self) -> HashAlgorithm {
        self.common.hash_algo()
    }

    /// Sets the hash algorithm.
    pub fn set_hash_algo(&mut self, algo: HashAlgorithm) -> HashAlgorithm {
        self.common.set_hash_algo(algo)
    }

    /// Gets the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Sets the salt.
    pub fn set_salt(&mut self, salt: Vec<u8>) -> Vec<u8> {
        mem::replace(&mut self.salt, salt)
    }

    /// Gets the issuer.
    pub fn issuer(&self) -> &Fingerprint {
        &self.issuer
    }

    /// Sets the issuer.
    pub fn set_issuer(&mut self, issuer: Fingerprint) -> Fingerprint {
        mem::replace(&mut self.issuer, issuer)
    }

    /// Gets the last flag.
    pub fn last(&self) -> bool {
        self.common.last()
    }

    /// Sets the last flag.
    pub fn set_last(&mut self, last: bool) -> bool {
        self.common.set_last(last)
    }

    /// Gets the raw value of the last flag.
    pub fn last_raw(&self) -> u8 {
        self.common.last_raw()
    }

    /// Sets the raw value of the last flag.
    pub fn set_last_raw(&mut self, last: u8) -> u8 {
        self.common.set_last_raw(last)
    }
}

impl From<OnePassSig6> for OnePassSig {
    fn from(s: OnePassSig6) -> Self {
        OnePassSig::V6(s)
    }
}

impl From<OnePassSig6> for Packet {
    fn from(p: OnePassSig6) -> Self {
        OnePassSig::from(p).into()
    }
}

impl<'a> std::convert::TryFrom<&'a Signature> for OnePassSig6 {
    type Error = anyhow::Error;

    fn try_from(s: &'a Signature) -> Result<Self> {
        let s = if let Signature::V6(s) = s {
            s
        } else {
            return Err(Error::InvalidArgument(format!(
                "Can not derive a v6 OnePassSig from a v{} Signature",
                s.version())).into());
        };

        let issuer = match s.issuer_fingerprints().next() {
            Some(i) => i.clone(),
            None =>
                return Err(Error::InvalidArgument(
                    "Signature has no issuer fingerprints".into()).into()),
        };
        let mut common = OnePassSig3::new(s.typ());
        common.set_hash_algo(s.hash_algo());
        common.set_pk_algo(s.pk_algo());
        Ok(OnePassSig6 {
            common,
            salt: s.salt().to_vec(),
            issuer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arbitrary_helper::arbitrary_bounded_vec;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    impl Arbitrary for OnePassSig6 {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut ops = OnePassSig6::new(SignatureType::arbitrary(g),
                                           Fingerprint::arbitrary_v6(g));
            ops.set_hash_algo(HashAlgorithm::arbitrary(g));
            ops.set_pk_algo(PublicKeyAlgorithm::arbitrary(g));
            ops.set_last_raw(u8::arbitrary(g));
            ops.set_salt(arbitrary_bounded_vec(g, 256));
            ops
        }
    }

    quickcheck! {
        fn roundtrip(p: OnePassSig6) -> bool {
            let q = OnePassSig6::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
