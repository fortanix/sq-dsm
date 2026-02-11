use std::io;

use crate::crypto::hash::Digest;
use crate::{Error, Result};
use crate::types::HashAlgorithm;

#[derive(Clone)]
struct Hash(botan::HashFunction);

impl Digest for Hash {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("infallible");
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        let d = self.0.finish().expect("infallible");
        let l = d.len().min(digest.len());
        digest[..l].copy_from_slice(&d[..l]);
        Ok(())
    }
}

impl io::Write for Hash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        // Do nothing.
        Ok(())
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgorithm::SHA1 => true,
            HashAlgorithm::SHA224 => true,
            HashAlgorithm::SHA256 => true,
            HashAlgorithm::SHA384 => true,
            HashAlgorithm::SHA512 => true,
            HashAlgorithm::SHA3_256 => true,
            HashAlgorithm::SHA3_512 => true,
            HashAlgorithm::RipeMD => true,
            HashAlgorithm::MD5 => true,
            HashAlgorithm::Private(_) => false,
            HashAlgorithm::Unknown(_) => false,
        }
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
        Ok(Box::new(Hash(
            botan::HashFunction::new(self.botan_name()?)
                .map_err(|_| Error::UnsupportedHashAlgorithm(self))?)))
    }
}

impl HashAlgorithm {
    /// Returns the name of the algorithm for use with Botan's
    /// constructor.
    pub(crate) fn botan_name(self) -> Result<&'static str> {
        match self {
            HashAlgorithm::SHA1 => Ok("SHA-1"),
            HashAlgorithm::SHA224 => Ok("SHA-224"),
            HashAlgorithm::SHA256 => Ok("SHA-256"),
            HashAlgorithm::SHA384 => Ok("SHA-384"),
            HashAlgorithm::SHA512 => Ok("SHA-512"),
            HashAlgorithm::SHA3_256 => Ok("SHA-3(256)"),
            HashAlgorithm::SHA3_512 => Ok("SHA-3(512)"),
            HashAlgorithm::MD5 => Ok("MD5"),
            HashAlgorithm::RipeMD => Ok("RIPEMD-160"),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_supported() {
        for h in (0..=255).into_iter().map(HashAlgorithm::from) {
            assert_eq!(h.is_supported(), h.context().is_ok());
        }
    }
}
