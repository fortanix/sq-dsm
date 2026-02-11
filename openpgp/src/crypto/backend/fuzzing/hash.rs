use std::io;

use crate::crypto::hash::Digest;
use crate::Result;
use crate::types::{HashAlgorithm};

#[derive(Clone)]
struct NullHasher();

impl io::Write for NullHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Digest for NullHasher {
    fn update(&mut self, data: &[u8]) {
        // Nop.
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        digest.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        Ok(())
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        true
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: HashAlgorithm::is_supported()
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        Ok(Box::new(NullHasher()))
    }
}
