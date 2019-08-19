//! One-pass signature packets.
//!
//! See [Section 5.4 of RFC 4880] for details.
//!
//!   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4

use std::fmt;
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::Packet;
use crate::packet;
use crate::packet::Signature;
use crate::Result;
use crate::KeyID;
use crate::HashAlgorithm;
use crate::PublicKeyAlgorithm;
use crate::SignatureType;
use crate::serialize::SerializeInto;

/// Holds a one-pass signature packet.
///
/// See [Section 5.4 of RFC 4880] for details.
///
///   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4
#[derive(Eq, Hash, Clone)]
pub struct OnePassSig3 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Type of the signature.
    typ: SignatureType,
    /// Hash algorithm used to compute the signature.
    hash_algo: HashAlgorithm,
    /// Public key algorithm of this signature.
    pk_algo: PublicKeyAlgorithm,
    /// Key ID of the signing key.
    issuer: KeyID,
    /// A one-octet number holding a flag showing whether the signature
    /// is nested.
    last: u8,
}

impl fmt::Debug for OnePassSig3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OnePassSig3")
            .field("typ", &self.typ)
            .field("hash_algo", &self.hash_algo)
            .field("pk_algo", &self.pk_algo)
            .field("issuer", &self.issuer)
            .field("last", &self.last)
            .finish()
    }
}

impl PartialEq for OnePassSig3 {
    fn eq(&self, other: &OnePassSig3) -> bool {
        // Comparing the relevant fields is error prone in case we add
        // a field at some point.  Instead, we compare the serialized
        // versions.
        if let (Ok(a), Ok(b)) = (self.to_vec(), other.to_vec()) {
            a == b
        } else {
            false
        }
    }
}

impl OnePassSig3 {
    /// Returns a new `Signature` packet.
    pub fn new(typ: SignatureType) ->  Self {
        OnePassSig3 {
            common: Default::default(),
            typ: typ,
            hash_algo: HashAlgorithm::Unknown(0),
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            issuer: KeyID::new(0),
            last: 1,
        }
    }

    /// Gets the signature type.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Sets the signature type.
    pub fn set_type(&mut self, t: SignatureType) -> SignatureType {
        ::std::mem::replace(&mut self.typ, t)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm) -> PublicKeyAlgorithm {
        ::std::mem::replace(&mut self.pk_algo, algo)
    }

    /// Gets the hash algorithm.
    pub fn hash_algo(&self) -> HashAlgorithm {
        self.hash_algo
    }

    /// Sets the hash algorithm.
    pub fn set_hash_algo(&mut self, algo: HashAlgorithm) -> HashAlgorithm {
        ::std::mem::replace(&mut self.hash_algo, algo)
    }

    /// Gets the issuer.
    pub fn issuer(&self) -> &KeyID {
        &self.issuer
    }

    /// Sets the issuer.
    pub fn set_issuer(&mut self, issuer: KeyID) -> KeyID {
        ::std::mem::replace(&mut self.issuer, issuer)
    }

    /// Gets the last flag.
    pub fn last(&self) -> bool {
        self.last > 0
    }

    /// Sets the last flag.
    pub fn set_last(&mut self, last: bool) -> bool {
        ::std::mem::replace(&mut self.last, if last { 1 } else { 0 }) > 0
    }

    /// Gets the raw value of the last flag.
    pub fn last_raw(&self) -> u8 {
        self.last
    }

    /// Sets the raw value of the last flag.
    pub fn set_last_raw(&mut self, last: u8) -> u8 {
        ::std::mem::replace(&mut self.last, last)
    }
}

impl From<OnePassSig3> for super::OnePassSig {
    fn from(s: OnePassSig3) -> Self {
        super::OnePassSig::V3(s)
    }
}

impl From<OnePassSig3> for Packet {
    fn from(p: OnePassSig3) -> Self {
        super::OnePassSig::from(p).into()
    }
}

impl<'a> From<&'a Signature> for Result<OnePassSig3> {
    fn from(s: &'a Signature) -> Self {
        let issuer = match s.issuer() {
            Some(i) => i,
            None =>
                return Err(Error::InvalidArgument(
                    "Signature has no issuer".into()).into()),
        };

        Ok(OnePassSig3 {
            common: Default::default(),
            typ: s.typ(),
            hash_algo: s.hash_algo(),
            pk_algo: s.pk_algo(),
            issuer: issuer,
            last: 0,
        })
    }
}

impl Arbitrary for OnePassSig3 {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut ops = OnePassSig3::new(SignatureType::arbitrary(g));
        ops.set_hash_algo(HashAlgorithm::arbitrary(g));
        ops.set_pk_algo(PublicKeyAlgorithm::arbitrary(g));
        ops.set_issuer(KeyID::arbitrary(g));
        ops.set_last_raw(u8::arbitrary(g));
        ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: OnePassSig3) -> bool {
            let q = OnePassSig3::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
