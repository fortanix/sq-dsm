use std::fmt;

use OnePassSig;
use Packet;
use KeyID;
use HashAlgorithm;
use PublicKeyAlgorithm;
use SignatureType;
use serialize::Serialize;

impl fmt::Debug for OnePassSig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signature")
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
        return self.to_vec() == other.to_vec();
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

    /// Sets the signature type.
    pub fn sigtype(mut self, t: SignatureType) -> Self {
        self.sigtype = t;
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, algo: PublicKeyAlgorithm) -> Self {
        self.pk_algo = algo;
        self
    }

    /// Sets the hash algorithm.
    pub fn hash_algo(mut self, algo: HashAlgorithm) -> Self {
        self.hash_algo = algo;
        self
    }

    /// Sets the issuer.
    pub fn issuer(mut self, issuer: KeyID) -> Self {
        self.issuer = issuer;
        self
    }

    /// Sets the last flag.
    pub fn last(mut self, last: bool) -> Self {
        self.last = if last { 1 } else { 0 };
        self
    }

    /// Convert the `OnePassSig` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::OnePassSig(self)
    }
}
