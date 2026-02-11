use std::borrow::Cow;

use crate::Result;
use crate::crypto::{
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        true
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, _mode: BlockCipherMode,
		      _key: &Protected, _iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        Ok(Box::new(NullCipher()))
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, _mode: BlockCipherMode,
		      _key: &Protected, _iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        Ok(Box::new(NullCipher()))
    }
}

struct NullCipher();

impl Context for NullCipher {
    fn encrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        dst.copy_from_slice(src);
        Ok(())
    }

    fn decrypt(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<()> {
        dst.copy_from_slice(src);
        Ok(())
    }
}
