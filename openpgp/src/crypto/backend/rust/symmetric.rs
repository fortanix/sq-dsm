use std::borrow::Cow;
use std::slice;

use cipher::BlockDecryptMut;
use cipher::BlockEncryptMut;
use cipher::KeyInit;
use cipher::KeyIvInit;
use cipher::generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};

use crate::crypto::{
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

use super::GenericArrayExt;

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        use SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            IDEA => true,
            TripleDES => true,
            CAST5 => true,
            Blowfish => true,
            AES128 => true,
            AES192 => true,
            AES256 => true,
            Twofish => true,
            Camellia128 => true,
            Camellia192 => true,
            Camellia256 => true,
            Private(_) => false,
            Unknown(_) => false,
            Unencrypted => false,
        }
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB =>
                algo.make_encrypt_cfb(key, iv.into_owned()),

            BlockCipherMode::CBC =>
                algo.make_encrypt_cbc(key, iv.into_owned()),

            BlockCipherMode::ECB =>
                algo.make_encrypt_ecb(key),
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB =>
                algo.make_decrypt_cfb(key, iv.into_owned()),

            BlockCipherMode::CBC =>
                algo.make_decrypt_cbc(key, iv.into_owned()),

            BlockCipherMode::ECB =>
                algo.make_decrypt_ecb(key),
        }
    }
}

enum CfbEncrypt {
    Idea(cfb_mode::Encryptor<idea::Idea>),
    TripleDES(cfb_mode::Encryptor<des::TdesEde3>),
    Cast5(cfb_mode::Encryptor<cast5::Cast5>),
    Blowfish(cfb_mode::Encryptor<blowfish::Blowfish>),
    Aes128(cfb_mode::Encryptor<aes::Aes128>),
    Aes192(cfb_mode::Encryptor<aes::Aes192>),
    Aes256(cfb_mode::Encryptor<aes::Aes256>),
    Twofish(cfb_mode::Encryptor<twofish::Twofish>),
    Camellia128(cfb_mode::Encryptor<camellia::Camellia128>),
    Camellia192(cfb_mode::Encryptor<camellia::Camellia192>),
    Camellia256(cfb_mode::Encryptor<camellia::Camellia256>),
}

enum CfbDecrypt {
    Idea(cfb_mode::Decryptor<idea::Idea>),
    TripleDES(cfb_mode::Decryptor<des::TdesEde3>),
    Cast5(cfb_mode::Decryptor<cast5::Cast5>),
    Blowfish(cfb_mode::Decryptor<blowfish::Blowfish>),
    Aes128(cfb_mode::Decryptor<aes::Aes128>),
    Aes192(cfb_mode::Decryptor<aes::Aes192>),
    Aes256(cfb_mode::Decryptor<aes::Aes256>),
    Twofish(cfb_mode::Decryptor<twofish::Twofish>),
    Camellia128(cfb_mode::Decryptor<camellia::Camellia128>),
    Camellia192(cfb_mode::Decryptor<camellia::Camellia192>),
    Camellia256(cfb_mode::Decryptor<camellia::Camellia256>),
}

enum CbcEncrypt {
    Idea(cbc::Encryptor<idea::Idea>),
    TripleDES(cbc::Encryptor<des::TdesEde3>),
    Cast5(cbc::Encryptor<cast5::Cast5>),
    Blowfish(cbc::Encryptor<blowfish::Blowfish>),
    Aes128(cbc::Encryptor<aes::Aes128>),
    Aes192(cbc::Encryptor<aes::Aes192>),
    Aes256(cbc::Encryptor<aes::Aes256>),
    Twofish(cbc::Encryptor<twofish::Twofish>),
    Camellia128(cbc::Encryptor<camellia::Camellia128>),
    Camellia192(cbc::Encryptor<camellia::Camellia192>),
    Camellia256(cbc::Encryptor<camellia::Camellia256>),
}

enum CbcDecrypt {
    Idea(cbc::Decryptor<idea::Idea>),
    TripleDES(cbc::Decryptor<des::TdesEde3>),
    Cast5(cbc::Decryptor<cast5::Cast5>),
    Blowfish(cbc::Decryptor<blowfish::Blowfish>),
    Aes128(cbc::Decryptor<aes::Aes128>),
    Aes192(cbc::Decryptor<aes::Aes192>),
    Aes256(cbc::Decryptor<aes::Aes256>),
    Twofish(cbc::Decryptor<twofish::Twofish>),
    Camellia128(cbc::Decryptor<camellia::Camellia128>),
    Camellia192(cbc::Decryptor<camellia::Camellia192>),
    Camellia256(cbc::Decryptor<camellia::Camellia256>),
}

enum EcbEncrypt {
    Idea(ecb::Encryptor<idea::Idea>),
    TripleDES(ecb::Encryptor<des::TdesEde3>),
    Cast5(ecb::Encryptor<cast5::Cast5>),
    Blowfish(ecb::Encryptor<blowfish::Blowfish>),
    Aes128(ecb::Encryptor<aes::Aes128>),
    Aes192(ecb::Encryptor<aes::Aes192>),
    Aes256(ecb::Encryptor<aes::Aes256>),
    Twofish(ecb::Encryptor<twofish::Twofish>),
    Camellia128(ecb::Encryptor<camellia::Camellia128>),
    Camellia192(ecb::Encryptor<camellia::Camellia192>),
    Camellia256(ecb::Encryptor<camellia::Camellia256>),
}

enum EcbDecrypt {
    Idea(ecb::Decryptor<idea::Idea>),
    TripleDES(ecb::Decryptor<des::TdesEde3>),
    Cast5(ecb::Decryptor<cast5::Cast5>),
    Blowfish(ecb::Decryptor<blowfish::Blowfish>),
    Aes128(ecb::Decryptor<aes::Aes128>),
    Aes192(ecb::Decryptor<aes::Aes192>),
    Aes256(ecb::Decryptor<aes::Aes256>),
    Twofish(ecb::Decryptor<twofish::Twofish>),
    Camellia128(ecb::Decryptor<camellia::Camellia128>),
    Camellia192(ecb::Decryptor<camellia::Camellia192>),
    Camellia256(ecb::Decryptor<camellia::Camellia256>),
}

macro_rules! impl_block_size {
    ($mode:ident) => {
        fn block_size(&self) -> usize {
            #[allow(deprecated)]
            match self {
                $mode::Idea(_) =>
                    <idea::Idea as cipher::BlockSizeUser>::block_size(),
                $mode::TripleDES(_) =>
                    <des::TdesEde3 as cipher::BlockSizeUser>::block_size(),
                $mode::Cast5(_) =>
                    <cast5::Cast5 as cipher::BlockSizeUser>::block_size(),
                $mode::Blowfish(_) =>
                    <blowfish::Blowfish as cipher::BlockSizeUser>::block_size(),
                $mode::Aes128(_) =>
                    <aes::Aes128 as cipher::BlockSizeUser>::block_size(),
                $mode::Aes192(_) =>
                    <aes::Aes192 as cipher::BlockSizeUser>::block_size(),
                $mode::Aes256(_) =>
                    <aes::Aes256 as cipher::BlockSizeUser>::block_size(),
                $mode::Twofish(_) =>
                    <twofish::Twofish as cipher::BlockSizeUser>::block_size(),
                $mode::Camellia128(_) =>
                    <camellia::Camellia128 as cipher::BlockSizeUser>::block_size(),
                $mode::Camellia192(_) =>
                    <camellia::Camellia192 as cipher::BlockSizeUser>::block_size(),
                $mode::Camellia256(_) =>
                    <camellia::Camellia256 as cipher::BlockSizeUser>::block_size(),
            }
        }
    }
}

macro_rules! impl_enc_mode {
    ($mode:ident) => {
        impl $mode {
            impl_block_size!($mode);
        }

        impl Context for $mode
        {
            fn encrypt(
                &mut self,
                dst: &mut [u8],
                src: &[u8],
            ) -> Result<()> {
              zero_stack!(4096 bytes after running {
                debug_assert_eq!(dst.len(), src.len());
                let bs = self.block_size();
                let missing = (bs - (dst.len() % bs)) % bs;
                if missing > 0 {
                    let mut buf = vec![0u8; src.len() + missing];
                    buf[..src.len()].copy_from_slice(src);
                    #[allow(deprecated)]
                    match self {
                        $mode::Idea(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::TripleDES(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Cast5(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Blowfish(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes128(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes192(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes256(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Twofish(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia128(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia192(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia256(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.encrypt_blocks_mut(blocks)
                        }
                    }
                    dst.copy_from_slice(&buf[..dst.len()]);
                } else {
                    dst.copy_from_slice(src);
                    #[allow(deprecated)]
                    match self {
                        $mode::Idea(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::TripleDES(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Cast5(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Blowfish(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes128(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes192(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Aes256(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Twofish(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia128(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia192(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia256(m) => {
                            let blocks = to_blocks(dst);
                            m.encrypt_blocks_mut(blocks)
                        }
                    }
                }
                Ok(())
              })
            }

            fn decrypt(
                &mut self,
                _dst: &mut [u8],
                _src: &[u8],
            ) -> Result<()> {
                Err(Error::InvalidOperation(
                    "decryption not supported in encryption mode".into())
                    .into())
            }
        }
    }
}

macro_rules! impl_dec_mode {
    ($mode:ident) => {
        impl $mode {
            impl_block_size!($mode);
        }

        impl Context for $mode
        {
            fn encrypt(
                &mut self,
                _dst: &mut [u8],
                _src: &[u8],
            ) -> Result<()> {
                Err(Error::InvalidOperation(
                    "encryption not supported in decryption mode".into())
                    .into())
            }

            fn decrypt(
                &mut self,
                dst: &mut [u8],
                src: &[u8],
            ) -> Result<()> {
              zero_stack!(4096 bytes after running {
                debug_assert_eq!(dst.len(), src.len());
                let bs = self.block_size();
                let missing = (bs - (dst.len() % bs)) % bs;
                if missing > 0 {
                    let mut buf = Protected::new(src.len() + missing);
                    buf[..src.len()].copy_from_slice(src);
                    #[allow(deprecated)]
                    match self {
                        $mode::Idea(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::TripleDES(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Cast5(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Blowfish(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes128(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes192(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes256(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Twofish(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia128(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia192(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia256(m) => {
                            let blocks = to_blocks(&mut buf);
                            m.decrypt_blocks_mut(blocks)
                        }
                    }
                    dst.copy_from_slice(&buf[..dst.len()]);
                } else {
                    dst.copy_from_slice(src);
                    #[allow(deprecated)]
                    match self {
                        $mode::Idea(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::TripleDES(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Cast5(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Blowfish(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes128(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes192(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Aes256(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Twofish(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia128(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia192(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                        $mode::Camellia256(m) => {
                            let blocks = to_blocks(dst);
                            m.decrypt_blocks_mut(blocks)
                        }
                    }
                }
                Ok(())
              })
            }
        }
    }
}

impl_enc_mode!(CfbEncrypt);
impl_dec_mode!(CfbDecrypt);
impl_enc_mode!(CbcEncrypt);
impl_dec_mode!(CbcDecrypt);
impl_enc_mode!(EcbEncrypt);
impl_dec_mode!(EcbDecrypt);

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

/// Creates a context for encrypting/decrypting in CFB/ECB mode.
macro_rules! make_mode {
    ($fn:ident, $enum:ident, $mode:ident::$mode2:ident $(, $iv:ident:$ivt:ty)?) => {
        fn $fn(self, key: &[u8], $($iv: $ivt)?) -> Result<Box<dyn Context>> {
          zero_stack!(8192 bytes after running || -> Result<Box<dyn Context>> {
            use cipher::generic_array::GenericArray as GA;

            use SymmetricAlgorithm::*;

            #[allow(deprecated)]
            match self {
                IDEA => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Idea(
                        $mode::$mode2::<idea::Idea>::new(key $(, $iv)?))))
                },
                TripleDES => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::TripleDES(
                        $mode::$mode2::<des::TdesEde3>::new(key $(, $iv)?))))
                },
                CAST5 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Cast5(
                        $mode::$mode2::<cast5::Cast5>::new(key $(, $iv)?))))
                },
                Blowfish => {
                    // Right... the blowfish constructor expects a 56
                    // byte key, but in OpenPGP the key is only 16
                    // bytes.
                    assert_eq!(key.len(), 16);
                    let mut key_expanded = [0; 56];
                    key_expanded[..16].copy_from_slice(&key);
                    let key = GA::try_from_slice(&key_expanded)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Blowfish(
                        $mode::$mode2::<blowfish::Blowfish>::new(key $(, $iv)?))))
                },
                AES128 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Aes128(
                        $mode::$mode2::<aes::Aes128>::new(key $(, $iv)?))))
                },
                AES192 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Aes192(
                        $mode::$mode2::<aes::Aes192>::new(key $(, $iv)?))))
                },
                AES256 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Aes256(
                        $mode::$mode2::<aes::Aes256>::new(key $(, $iv)?))))
                },
                Twofish => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Twofish(
                        $mode::$mode2::<twofish::Twofish>::new(key $(, $iv)?))))
                },
                Camellia128 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Camellia128(
                        $mode::$mode2::<camellia::Camellia128>::new(key $(, $iv)?))))
                },
                Camellia192 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Camellia192(
                        $mode::$mode2::<camellia::Camellia192>::new(key $(, $iv)?))))
                },
                Camellia256 => {
                    let key = GA::try_from_slice(&key)?;
                    $( let $iv = &GA::try_from_slice(&$iv)?; )?
                    Ok(Box::new($enum::Camellia256(
                        $mode::$mode2::<camellia::Camellia256>::new(key $(, $iv)?))))
                },
                Private(_) | Unknown(_) | Unencrypted =>
                {
                    Err(Error::UnsupportedSymmetricAlgorithm(self).into())
                }
            }
          })
        }
    }
}

impl SymmetricAlgorithm {
    make_mode!(make_encrypt_cfb, CfbEncrypt, cfb_mode::Encryptor, iv: Vec<u8>);
    make_mode!(make_decrypt_cfb, CfbDecrypt, cfb_mode::Decryptor, iv: Vec<u8>);
    make_mode!(make_encrypt_cbc, CbcEncrypt, cbc::Encryptor, iv: Vec<u8>);
    make_mode!(make_decrypt_cbc, CbcDecrypt, cbc::Decryptor, iv: Vec<u8>);
    make_mode!(make_encrypt_ecb, EcbEncrypt, ecb::Encryptor);
    make_mode!(make_decrypt_ecb, EcbDecrypt, ecb::Decryptor);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// Anchors the constants used in Sequoia with the ones from
    /// RustCrypto.
    #[test]
    fn key_size() -> Result<()> {
        assert_eq!(SymmetricAlgorithm::IDEA.key_size()?,
                   <idea::Idea as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::TripleDES.key_size()?,
                   <des::TdesEde3 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::CAST5.key_size()?,
                   <cast5::Cast5 as cipher::KeySizeUser>::key_size());
        // RFC4880, Section 9.2: Blowfish (128 bit key, 16 rounds)
        assert_eq!(SymmetricAlgorithm::Blowfish.key_size()?, 16);
        assert_eq!(SymmetricAlgorithm::AES128.key_size()?,
                   <aes::Aes128 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::AES192.key_size()?,
                   <aes::Aes192 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::AES256.key_size()?,
                   <aes::Aes256 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::Twofish.key_size()?,
                   <twofish::Twofish as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::Camellia128.key_size()?,
                   <camellia::Camellia128 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::Camellia192.key_size()?,
                   <camellia::Camellia192 as cipher::KeySizeUser>::key_size());
        assert_eq!(SymmetricAlgorithm::Camellia256.key_size()?,
                   <camellia::Camellia256 as cipher::KeySizeUser>::key_size());
        Ok(())
    }

    /// Anchors the constants used in Sequoia with the ones from
    /// RustCrypto.
    #[test]
    fn block_size() -> Result<()> {
        assert_eq!(SymmetricAlgorithm::IDEA.block_size()?,
                   <idea::Idea as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::TripleDES.block_size()?,
                   <des::TdesEde3 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::CAST5.block_size()?,
                   <cast5::Cast5 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::Blowfish.block_size()?,
                   <blowfish::Blowfish as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::AES128.block_size()?,
                   <aes::Aes128 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::AES192.block_size()?,
                   <aes::Aes192 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::AES256.block_size()?,
                   <aes::Aes256 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::Twofish.block_size()?,
                   <twofish::Twofish as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::Camellia128.block_size()?,
                   <camellia::Camellia128 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::Camellia192.block_size()?,
                   <camellia::Camellia192 as cipher::BlockSizeUser>::block_size());
        assert_eq!(SymmetricAlgorithm::Camellia256.block_size()?,
                   <camellia::Camellia256 as cipher::BlockSizeUser>::block_size());
        Ok(())
    }
}
