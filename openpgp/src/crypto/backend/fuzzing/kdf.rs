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
        assert!(okm.len() <= 255 * 32);
        okm.iter_mut().for_each(|p| *p = 4);
        Ok(())
    }

    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        assert!(okm.len() <= 255 * 32);
        okm.iter_mut().for_each(|p| *p = 8);
        Ok(())
    }
}
