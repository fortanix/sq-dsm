//! Implementation of AEAD using Nettle cryptographic library.

use crate::Result;

use crate::crypto::aead::{Context, CipherOp};
use crate::crypto::mem::Protected;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

struct NullAEADMode {}

const DIGEST_SIZE: usize = 16;

impl seal::Sealed for NullAEADMode {}
impl Context for NullAEADMode {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let l = dst.len() - DIGEST_SIZE;
        dst[..l].copy_from_slice(src);
        dst[l..].iter_mut().for_each(|p| *p = 0x04);
        Ok(())
    }
    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        dst.copy_from_slice(&src[..src.len() - DIGEST_SIZE]);
        Ok(())
    }
    fn digest_size(&self) -> usize {
        DIGEST_SIZE
    }
}

impl crate::crypto::backend::interface::Aead for super::Backend {
    fn supports_algo(_: AEADAlgorithm) -> bool {
        true
    }

    fn supports_algo_with_symmetric(_: AEADAlgorithm,
                                    _: SymmetricAlgorithm)
                                    -> bool
    {
        true
    }

    fn context(
        algo: AEADAlgorithm,
        sym_algo: SymmetricAlgorithm,
        key: &Protected,
        aad: &[u8],
        nonce: &[u8],
        _op: CipherOp,
    ) -> Result<Box<dyn Context>> {
        Ok(Box::new(NullAEADMode {}))
    }
}
