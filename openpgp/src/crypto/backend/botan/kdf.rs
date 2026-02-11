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

        const NO_SALT: [u8; 32] = [0; 32];
        let salt = salt.unwrap_or(&NO_SALT);

        // XXX: It'd be nice to write that directly to `okm`, but botan-rs
        // does not have such an interface.
        let okm_heap: SessionKey =
            botan::kdf("HKDF(SHA-256)", okm.len(), &*ikm, salt, info)?
            .into();

        // XXX: Now copy the secret.
        let l = okm.len().min(okm_heap.len());
        okm[..l].copy_from_slice(&okm_heap[..l]);

        Ok(())
    }

    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        assert!(okm.len() <= 255 * 64);

        const NO_SALT: [u8; 64] = [0; 64];
        let salt = salt.unwrap_or(&NO_SALT);

        // XXX: It'd be nice to write that directly to `okm`, but botan-rs
        // does not have such an interface.
        let okm_heap: SessionKey =
            botan::kdf("HKDF(SHA-512)", okm.len(), &*ikm, salt, info)?
            .into();

        // XXX: Now copy the secret.
        let l = okm.len().min(okm_heap.len());
        okm[..l].copy_from_slice(&okm_heap[..l]);

        Ok(())
    }
}
