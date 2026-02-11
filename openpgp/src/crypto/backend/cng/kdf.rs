use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

use crate::{
    Result,
    crypto::{
        SessionKey,
        backend::interface::Kdf,
    },
};

impl Kdf for super::Backend {
    fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        Ok(Hkdf::<Sha256>::new(salt, &ikm).expand(info, okm)
           .map_err(|e| crate::Error::InvalidOperation(e.to_string()))?)
    }

    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        Ok(Hkdf::<Sha512>::new(salt, &ikm).expand(info, okm)
           .map_err(|e| crate::Error::InvalidOperation(e.to_string()))?)
    }
}
