use openssl::{
    md::Md,
    pkey::Id,
    pkey_ctx::PkeyCtx,
};

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
        let mut pkey = PkeyCtx::new_id(Id::HKDF)?;
        pkey.derive_init()?;
        pkey.set_hkdf_md(Md::sha256())?;
        pkey.set_hkdf_key(&ikm)?;
        if let Some(salt) = salt {
            pkey.set_hkdf_salt(salt)?;
        }
        pkey.add_hkdf_info(info)?;
        pkey.derive(Some(okm))?;
        Ok(())
    }

    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        let mut pkey = PkeyCtx::new_id(Id::HKDF)?;
        pkey.derive_init()?;
        pkey.set_hkdf_md(Md::sha512())?;
        pkey.set_hkdf_key(&ikm)?;
        if let Some(salt) = salt {
            pkey.set_hkdf_salt(salt)?;
        }
        pkey.add_hkdf_info(info)?;
        pkey.derive(Some(okm))?;
        Ok(())
    }
}
