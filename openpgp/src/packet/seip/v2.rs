//! Symmetrically Encrypted Integrity Protected data packets version 2.
//!
//! An encrypted data packet is a container.  See [Version 2
//! Symmetrically Encrypted and Integrity Protected Data Packet
//! Format] for details.
//!
//! [Version 2 Symmetrically Encrypted and Integrity Protected Data Packet Format]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-2-symmetrically-enc
use crate::{
    Error,
    packet::{
        self,
        Packet,
        SEIP,
    },
    Result,
    types::{
        AEADAlgorithm,
        SymmetricAlgorithm,
    },
};

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Version 2
/// Symmetrically Encrypted and Integrity Protected Data Packet
/// Format] for details.
///
/// [Version 2 Symmetrically Encrypted and Integrity Protected Data Packet Format]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-2-symmetrically-enc
///
/// # A note on equality
///
/// An unprocessed (encrypted) `SEIP2` packet is never considered equal
/// to a processed (decrypted) one.  Likewise, a processed (decrypted)
/// packet is never considered equal to a structured (parsed) one.
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SEIP2 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// Symmetric algorithm.
    sym_algo: SymmetricAlgorithm,

    /// AEAD algorithm.
    aead: AEADAlgorithm,

    /// Chunk size.
    chunk_size: u64,

    /// Salt.
    salt: [u8; 32],

    /// This is a container packet.
    container: packet::Container,
}

assert_send_and_sync!(SEIP2);

impl SEIP2 {
    /// Creates a new SEIP2 packet.
    pub fn new(sym_algo: SymmetricAlgorithm,
               aead: AEADAlgorithm,
               chunk_size: u64,
               salt: [u8; 32])
               -> Result<Self>
    {
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

        Ok(SEIP2 {
            common: Default::default(),
            sym_algo,
            aead,
            chunk_size,
            salt,
            container: Default::default(),
        })
    }

    /// Gets the symmetric algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the symmetric algorithm.
    pub fn set_symmetric_algo(&mut self, sym_algo: SymmetricAlgorithm)
                              -> SymmetricAlgorithm {
        std::mem::replace(&mut self.sym_algo, sym_algo)
    }

    /// Gets the AEAD algorithm.
    pub fn aead(&self) -> AEADAlgorithm {
        self.aead
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead(&mut self, aead: AEADAlgorithm) -> AEADAlgorithm {
        std::mem::replace(&mut self.aead, aead)
    }

    /// Gets the chunk size.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Sets the chunk size.
    pub fn set_chunk_size(&mut self, chunk_size: u64) -> Result<()> {
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

    /// Gets the size of a chunk with a digest.
    pub fn chunk_digest_size(&self) -> Result<u64> {
        Ok(self.chunk_size + self.aead.digest_size()? as u64)
    }

    /// Gets the salt.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Sets the salt.
    pub fn set_salt(&mut self, salt: [u8; 32]) -> [u8; 32] {
        std::mem::replace(&mut self.salt, salt)
    }
}

impl_processed_body_forwards!(SEIP2);

impl From<SEIP2> for SEIP {
    fn from(p: SEIP2) -> Self {
        SEIP::V2(p)
    }
}

impl From<SEIP2> for Packet {
    fn from(s: SEIP2) -> Self {
        Packet::SEIP(s.into())
    }
}
