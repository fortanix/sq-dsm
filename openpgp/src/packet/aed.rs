//! AEAD encrypted data packets.

use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::packet;
use crate::Packet;
use crate::Error;
use crate::Result;

/// Holds an AEAD encrypted data packet.
///
/// An AEAD encrypted data packet is a container.  See [Section 5.16
/// of RFC 4880bis] for details.
///
/// [Section 5.16 of RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.16
///
/// This feature is [experimental](../../index.html#experimental-features).
#[derive(Clone, Debug)]
pub struct AED1 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Symmetric algorithm.
    sym_algo: SymmetricAlgorithm,
    /// AEAD algorithm.
    aead: AEADAlgorithm,
    /// Chunk size.
    chunk_size: usize,
    /// Initialization vector for the AEAD algorithm.
    iv: Box<[u8]>,

    /// This is a container packet.
    container: packet::Container,
}

impl PartialEq for AED1 {
    fn eq(&self, other: &AED1) -> bool {
        self.sym_algo == other.sym_algo
            && self.aead == other.aead
            && self.chunk_size == other.chunk_size
            && self.iv == other.iv
            && self.container == other.container
    }
}

impl Eq for AED1 {}

impl std::hash::Hash for AED1 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.sym_algo, state);
        std::hash::Hash::hash(&self.aead, state);
        std::hash::Hash::hash(&self.chunk_size, state);
        std::hash::Hash::hash(&self.iv, state);
        std::hash::Hash::hash(&self.container, state);
    }
}

impl AED1 {
    /// Creates a new AED1 object.
    pub fn new(sym_algo: SymmetricAlgorithm,
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

        Ok(AED1 {
            common: Default::default(),
            sym_algo: sym_algo,
            aead: aead,
            chunk_size: chunk_size,
            iv: iv,
            container: Default::default(),
        })
    }

    /// Gets the symmetric algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the sym_algo algorithm.
    pub fn set_symmetric_algo(&mut self, sym_algo: SymmetricAlgorithm)
                              -> SymmetricAlgorithm {
        ::std::mem::replace(&mut self.sym_algo, sym_algo)
    }

    /// Gets the AEAD algorithm.
    pub fn aead(&self) -> AEADAlgorithm {
        self.aead
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead(&mut self, aead: AEADAlgorithm) -> AEADAlgorithm {
        ::std::mem::replace(&mut self.aead, aead)
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
    pub fn set_iv(&mut self, iv: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.iv, iv)
    }
}

impl_container_forwards!(AED1);

impl From<AED1> for Packet {
    fn from(p: AED1) -> Self {
        super::AED::from(p).into()
    }
}

impl From<AED1> for super::AED {
    fn from(p: AED1) -> Self {
        super::AED::V1(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut s = AED1::new(SymmetricAlgorithm::AES128,
                              AEADAlgorithm::EAX,
                              64,
                              vec![].into_boxed_slice()).unwrap();
        assert_eq!(s.body(), &[]);
        s.set_body(vec![0, 1, 2]);
        assert_eq!(s.body(), &[0, 1, 2]);
    }
}
