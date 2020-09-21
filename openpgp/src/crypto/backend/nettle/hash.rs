use crate::crypto::hash::Digest;
use crate::{Error, Result};
use crate::types::{HashAlgorithm};

impl<T: nettle::hash::Hash + Clone> Digest for T {
    fn digest_size(&self) -> usize {
        self.digest_size()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn digest(&mut self, digest: &mut [u8]) {
        self.digest(digest);
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
    ///   [`HashAlgorithm::is_supported`]: #method.is_supported
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        use nettle::hash::{Sha224, Sha256, Sha384, Sha512};
        use nettle::hash::insecure_do_not_use::{
            Sha1,
            Md5,
            Ripemd160,
        };

        match self {
            HashAlgorithm::SHA1 => Ok(Box::new(Sha1::default())),
            HashAlgorithm::SHA224 => Ok(Box::new(Sha224::default())),
            HashAlgorithm::SHA256 => Ok(Box::new(Sha256::default())),
            HashAlgorithm::SHA384 => Ok(Box::new(Sha384::default())),
            HashAlgorithm::SHA512 => Ok(Box::new(Sha512::default())),
            HashAlgorithm::MD5 => Ok(Box::new(Md5::default())),
            HashAlgorithm::RipeMD => Ok(Box::new(Ripemd160::default())),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        }
    }

    /// Returns the ASN.1 OID of this hash algorithm.
    pub fn oid(self) -> Result<&'static [u8]> {
        use nettle::rsa;

        match self {
            HashAlgorithm::SHA1 => Ok(rsa::ASN1_OID_SHA1),
            HashAlgorithm::SHA224 => Ok(rsa::ASN1_OID_SHA224),
            HashAlgorithm::SHA256 => Ok(rsa::ASN1_OID_SHA256),
            HashAlgorithm::SHA384 => Ok(rsa::ASN1_OID_SHA384),
            HashAlgorithm::SHA512 => Ok(rsa::ASN1_OID_SHA512),
            HashAlgorithm::MD5 => Ok(rsa::ASN1_OID_MD5),
            HashAlgorithm::RipeMD => Ok(rsa::ASN1_OID_RIPEMD160),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        }
    }
}
