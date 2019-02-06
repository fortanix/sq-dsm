use std::ops::{Deref, DerefMut};

use constants::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use packet::{self, Common};
use Packet;
use Error;
use Result;

/// Holds an AEAD encrypted data packet.
///
/// An AEAD encrypted data packet is a container.  See [Section 5.16
/// of RFC 4880bis] for details.
///
/// [Section 5.16 of RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.16
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct AED {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// AED version. Must be 1.
    version: u8,
    /// Cipher algorithm.
    cipher: SymmetricAlgorithm,
    /// AEAD algorithm.
    aead: AEADAlgorithm,
    /// Chunk size.
    chunk_size: usize,
    /// Initialization vector for the AEAD algorithm.
    iv: Box<[u8]>,
}

impl AED {
    /// Creates a new AED object.
    pub fn new(cipher: SymmetricAlgorithm,
               aead: AEADAlgorithm,
               chunk_size: usize,
               iv: Box<[u8]>) -> Result<Self> {
        if chunk_size.count_ones() != 1 {
            return Err(Error::InvalidArgument(
                format!("chunk size is not a power of two: {}", chunk_size))
                .into());
        }

        if chunk_size < 64 {
            return Err(Error::InvalidArgument(
                format!("chunk size is too small: {}", chunk_size))
                .into());
        }

        Ok(AED {
            common: Default::default(),
            version: 1,
            cipher: cipher,
            aead: aead,
            chunk_size: chunk_size,
            iv: iv,
        })
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the cipher algorithm.
    pub fn cipher(&self) -> SymmetricAlgorithm {
        self.cipher
    }

    /// Sets the cipher algorithm.
    pub fn set_cipher(&mut self, cipher: SymmetricAlgorithm) {
        self.cipher = cipher;
    }

    /// Gets the AEAD algorithm.
    pub fn aead(&self) -> AEADAlgorithm {
        self.aead
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead(&mut self, aead: AEADAlgorithm) {
        self.aead = aead;
    }

    /// Gets the chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Gets the chunk size.
    pub fn set_chunk_size(&mut self, chunk_size: usize) -> Result<()> {
        if chunk_size.count_ones() != 1 {
            return Err(Error::InvalidArgument(
                format!("chunk size is not a power of two: {}", chunk_size))
                .into());
        }

        if chunk_size < 64 {
            return Err(Error::InvalidArgument(
                format!("chunk size is too small: {}", chunk_size))
                .into());
        }

        self.chunk_size = chunk_size;
        Ok(())
    }

    /// Gets the size of a chunk with digest.
    pub fn chunk_digest_size(&self) -> Result<usize> {
        Ok(self.chunk_size + self.aead.digest_size()?)
    }

    /// Gets the initialization vector for the AEAD algorithm.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Sets the initialization vector for the AEAD algorithm.
    pub fn set_iv(&mut self, iv: Box<[u8]>) {
        self.iv = iv;
    }
}

impl From<AED> for Packet {
    fn from(s: AED) -> Self {
        Packet::AED(s)
    }
}

// Allow transparent access of common fields.
impl<'a> Deref for AED {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

// Allow transparent access of common fields.
impl<'a> DerefMut for AED {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut s = AED::new(SymmetricAlgorithm::AES128,
                             AEADAlgorithm::EAX,
                             64,
                             vec![].into_boxed_slice()).unwrap();
        assert_eq!(s.body(), None);
        s.set_body(vec![0, 1, 2]);
        assert_eq!(s.body(), Some(&[0, 1, 2][..]));
    }
}
