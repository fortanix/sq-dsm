use std::fmt;
use quickcheck::{Arbitrary, Gen};

use Error;
use packet;
use packet::Signature;
use Packet;
use Result;
use KeyID;
use HashAlgorithm;
use PublicKeyAlgorithm;
use SignatureType;
use serialize::Serialize;

/// Holds a one-pass signature packet.
///
/// See [Section 5.4 of RFC 4880] for details.
///
///   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4
#[derive(Eq, Hash, Clone)]
pub struct OnePassSig {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// One-pass-signature packet version. Must be 3.
    version: u8,
    /// Type of the signature.
    sigtype: SignatureType,
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

impl fmt::Debug for OnePassSig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OnePassSig")
            .field("version", &self.version)
            .field("sigtype", &self.sigtype)
            .field("hash_algo", &self.hash_algo)
            .field("pk_algo", &self.pk_algo)
            .field("issuer", &self.issuer)
            .field("last", &self.last)
            .finish()
    }
}

impl PartialEq for OnePassSig {
    fn eq(&self, other: &OnePassSig) -> bool {
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

impl OnePassSig {
    /// Returns a new `Signature` packet.
    pub fn new(sigtype: SignatureType) ->  Self {
        OnePassSig {
            common: Default::default(),
            version: 3,
            sigtype: sigtype,
            hash_algo: HashAlgorithm::Unknown(0),
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            issuer: KeyID::new(0),
            last: 1,
        }
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the signature type.
    pub fn sigtype(&self) -> SignatureType {
        self.sigtype
    }

    /// Sets the signature type.
    pub fn set_sigtype(&mut self, t: SignatureType) -> SignatureType {
        ::std::mem::replace(&mut self.sigtype, t)
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

impl From<OnePassSig> for Packet {
    fn from(s: OnePassSig) -> Self {
        Packet::OnePassSig(s)
    }
}

impl<'a> From<&'a Signature> for Result<OnePassSig> {
    fn from(s: &'a Signature) -> Self {
        let issuer = match s.issuer() {
            Some(i) => i,
            None =>
                return Err(Error::InvalidArgument(
                    "Signature has no issuer".into()).into()),
        };

        Ok(OnePassSig {
            common: Default::default(),
            version: 3,
            sigtype: s.sigtype(),
            hash_algo: s.hash_algo(),
            pk_algo: s.pk_algo(),
            issuer: issuer,
            last: 0,
        })
    }
}

impl Arbitrary for OnePassSig {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut ops = OnePassSig::new(SignatureType::arbitrary(g));
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
    use parse::Parse;
    use serialize::Serialize;

    quickcheck! {
        fn roundtrip(p: OnePassSig) -> bool {
            let q = OnePassSig::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
