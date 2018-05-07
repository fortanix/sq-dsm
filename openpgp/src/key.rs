use std::fmt;

use mpis::MPIs;

use Tag;
use Key;
use Packet;
use PublicKeyAlgorithm;

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &self.fingerprint())
            .field("version", &self.version)
            .field("creation_time", &self.creation_time)
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .finish()
    }
}

impl Key {
    /// Returns a new `Key` packet.  This can be used to hold either a
    /// public key, a public key, a private key, or a private subkey.
    pub fn new() -> Self {
        Key {
            common: Default::default(),
            version: 4,
            creation_time: 0,
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            mpis: MPIs::new(),
        }
    }

    /// Sets the literal packet's date field using a Unix timestamp.
    ///
    /// A Unix timestamp is the number of seconds since the Unix
    /// epoch.
    ///
    /// Note: the date is stored in big endian format.  The timestamp
    /// should be provided in the default endianness.
    pub fn creation_time(mut self, timestamp: u32) -> Self {
        self.creation_time = timestamp.to_be();
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, pk_algo: PublicKeyAlgorithm) -> Self {
        self.pk_algo = pk_algo;
        self
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn to_packet(self, tag: Tag) -> Packet {
        match tag {
            Tag::PublicKey => Packet::PublicKey(self),
            Tag::PublicSubkey => Packet::PublicSubkey(self),
            Tag::SecretKey => Packet::SecretKey(self),
            Tag::SecretSubkey => Packet::SecretSubkey(self),
            _ => panic!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag),
        }
    }
}
