use core::convert::TryFrom;

use crate::crypto::hash::Digest;
use crate::types::HashAlgorithm;
use crate::{Error, Result};

use win_crypto_ng::hash as cng;

impl Digest for cng::Hash {
    fn digest_size(&self) -> usize {
        self.hash_size().expect("CNG to not fail internally")
    }

    fn update(&mut self, data: &[u8]) {
        let _ = self.hash(data);
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        // TODO: Replace with CNG reusable hash objects, supported from Windows 8
        // This would allow us to not re-create the CNG hash object each time we
        // want to finish digest calculation
        let algorithm = self.hash_algorithm()
            .expect("CNG hash object to know its algorithm");
        let new = cng::HashAlgorithm::open(algorithm)
            .expect("CNG to open a new correct hash provider")
            .new_hash()
            .expect("Failed to create a new CNG hash object");

        let old = std::mem::replace(self, new);
        let buffer = old.finish()
            .expect("CNG to not fail internally");

        digest.copy_from_slice(&buffer.as_slice()[..digest.len()]);
        Ok(())
    }
}

impl TryFrom<HashAlgorithm> for cng::HashAlgorithmId {
    type Error = Error;

    fn try_from(value: HashAlgorithm) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            HashAlgorithm::SHA1 => cng::HashAlgorithmId::Sha1,
            HashAlgorithm::SHA256 => cng::HashAlgorithmId::Sha256,
            HashAlgorithm::SHA384 => cng::HashAlgorithmId::Sha384,
            HashAlgorithm::SHA512 => cng::HashAlgorithmId::Sha512,
            HashAlgorithm::MD5 => cng::HashAlgorithmId::Md5,
            algo => Err(Error::UnsupportedHashAlgorithm(algo))?,
        })
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgorithm::SHA1 => true,
            HashAlgorithm::SHA256 => true,
            HashAlgorithm::SHA384 => true,
            HashAlgorithm::SHA512 => true,
            HashAlgorithm::MD5 => true,
            _ => false,
        }
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if the selected crypto
    /// backend does not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: #method.is_supported
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        let algo = cng::HashAlgorithmId::try_from(self)?;
        let algo = cng::HashAlgorithm::open(algo)?;

        Ok(Box::new(algo.new_hash().expect(
            "CNG to always create a hasher object for valid algo",
        )))
    }
}
