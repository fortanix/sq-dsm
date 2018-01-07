use std::fmt;
use std::cell::RefCell;

use PacketCommon;
use Signature;
use Packet;
use serialize::signature_serialize;

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hashed_area = format!("{} bytes", self.hashed_area.len());
        let unhashed_area = format!("{} bytes", self.unhashed_area.len());
        let mpis = format!("{} bytes", self.mpis.len());

        // Get the issuer.  Prefer the issuer fingerprint to the
        // issuer keyid, which may be stored in the unhashed area.
        let issuer = if let Some(tmp) = self.issuer_fingerprint() {
            tmp.1.to_string()
        } else if let Some(tmp) = self.issuer() {
            tmp.1.to_string()
        } else {
            "Unknown".to_string()
        };

        f.debug_struct("Signature")
            .field("version", &self.version)
            .field("sigtype", &self.sigtype)
            .field("issuer", &issuer)
            .field("pk_algo", &self.pk_algo)
            .field("hash_algo", &self.hash_algo)
            .field("hashed_area", &hashed_area)
            .field("unhashed_area", &unhashed_area)
            .field("hash_prefix", &self.hash_prefix)
            .field("mpis", &mpis)
            .finish()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        // Comparing the relevant fields is error prone in case we add
        // a field at some point.  Instead, we compare the serialized
        // versions.  As a small optimization, we compare the MPIs.
        // Note: two `Signatures` could be different even if they have
        // the same MPI if the MPI was not invalidated when changing a
        // field.
        if self.mpis != other.mpis {
            return false;
        }

        // Do a full check by serializing the fields.

        // 4k should avoid reallocations most of the time.
        let mut buffer = Vec::with_capacity(4096);

        // Serializing to a vector can't fail.
        signature_serialize(&mut buffer, self).unwrap();

        let mut buffer2 = Vec::with_capacity(4096);
        signature_serialize(&mut buffer2, other).unwrap();

        return buffer == buffer2;
    }
}

impl Signature {
    /// Returns a new `Signature` packet.
    pub fn new(sigtype: u8) ->  Self {
        Signature {
            common: PacketCommon::default(),
            version: 4,
            sigtype: sigtype,
            pk_algo: 0,
            hash_algo: 0,
            hashed_area: Vec::new(),
            hashed_area_parsed: RefCell::new(None),
            unhashed_area: Vec::new(),
            unhashed_area_parsed: RefCell::new(None),
            hash_prefix: [0, 0],
            mpis: Vec::new(),
        }
    }

    /// Sets the signature type.
    pub fn sigtype(mut self, t: u8) -> Self {
        self.sigtype = t;
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, algo: u8) -> Self {
        // XXX: Do we invalidate the signature data?
        self.pk_algo = algo;
        self
    }

    /// Sets the hash algorithm.
    pub fn hash_algo(mut self, algo: u8) -> Self {
        // XXX: Do we invalidate the signature data?
        self.hash_algo = algo;
        self
    }

    // XXX: Add subpacket handling.

    // XXX: Add signature generation and validation support.


    /// Convert the `Signature` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Signature(self)
    }
}
