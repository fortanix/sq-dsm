//! Implementation of AEAD using Windows CNG API.
#![allow(unused_variables)]

use crate::Result;

use crate::crypto::aead::Aead;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<Box<dyn Aead>> {
        unimplemented!()
    }
}
