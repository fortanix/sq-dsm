//! Implementation of AEAD using Windows CNG API.

use crate::{Error, Result};
use crate::crypto::aead::Aead;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};
use super::symmetric::Ctr;

use win_crypto_ng::hash::{Hash, HashAlgorithm, MacAlgorithmId};
use win_crypto_ng::symmetric::SymmetricAlgorithmId;

const EAX_BLOCK_SIZE: usize = 16;
const EAX_DIGEST_SIZE: usize = 16;

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::EAX => match sym_algo {
                | SymmetricAlgorithm::AES128
                | SymmetricAlgorithm::AES192
                | SymmetricAlgorithm::AES256 => {
                    Ok(Box::new(EaxAes::with_key_and_nonce(key, nonce)?))
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}

/// EAX-AES mode.
///
/// See https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf.
struct EaxAes {
    omac_nonce: Vec<u8>,
    omac_data: Hash,
    omac_msg: Hash,
    ctr: Ctr,
}

impl EaxAes {
    fn with_key_and_nonce(key: &[u8], nonce: &[u8]) -> Result<Self> {
        fn omac_init_with_iv(
            prov: &HashAlgorithm<MacAlgorithmId>,
            key: &[u8],
            iv: u8,
        ) -> Result<Hash> {
            let mut omac = prov.new_mac(key, None)?;
            // Prepend the IV
            omac.hash(&[0; EAX_BLOCK_SIZE - 1])?;
            omac.hash(&[iv])?;
            Ok(omac)
        }

        let provider = HashAlgorithm::open(MacAlgorithmId::AesCmac)?;
        // N ← OMAC_0^K(N)
        let mut omac_nonce = omac_init_with_iv(&provider, key, 0)?;
        omac_nonce.hash(nonce)?;
        let omac_nonce = omac_nonce.finish()?.into_inner();
        // H ← OMAC_1^K(H), init with 1 but hash online associated data later
        let omac_data = omac_init_with_iv(&provider, key, 1)?;
        // C ← OMAC_2^K(C), init with 2 but hash online resulting ciphertext later
        let omac_msg = omac_init_with_iv(&provider, key, 2)?;

        let ctr = Ctr::with_cipher_and_iv(SymmetricAlgorithmId::Aes, key, &omac_nonce)?;

        Ok(EaxAes { omac_nonce, omac_data, omac_msg, ctr })
    }
}


impl Aead for EaxAes {
    /// Adds associated data `ad`.
    fn update(&mut self, ad: &[u8]) {
        let _ = self.omac_data.hash(ad);
     }

    /// Encrypts one block `src` to `dst`.
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
       let _ = Ctr::encrypt(&mut self.ctr, dst, src);
        let _ = self.omac_msg.hash(dst);
    }
    /// Decrypts one block `src` to `dst`.
    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        let _ = self.omac_msg.hash(src);
        let _ = Ctr::decrypt(&mut self.ctr, dst, src);
     }

    /// Produce the digest.
    fn digest(&mut self, digest: &mut [u8]) {
        // TODO: It'd be great if wouldn't have to clone
        let omac_data = self.omac_data.clone().finish().unwrap().into_inner();
        let omac_msg = self.omac_msg.clone().finish().unwrap().into_inner();

        let (nonce, data, msg) = (self.omac_nonce.iter(), omac_data.iter(), omac_msg.iter());
        for (((out, n), d), m) in digest.iter_mut().zip(nonce).zip(data).zip(msg) {
            *out = n ^ d ^ m;
        }
    }

    /// Length of the digest in bytes.
    fn digest_size(&self) -> usize { EAX_DIGEST_SIZE }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::Aead;

    trait HexSlice: std::borrow::Borrow<str> {
        fn as_hex(&self) -> Vec<u8> {
            let res: Vec<u8> = self.borrow().as_bytes().rchunks(2)
                .map(|slice| std::str::from_utf8(slice).unwrap())
                .map(|chr| u8::from_str_radix(chr, 16).unwrap())
                .rev()
                .collect();
            res
        }
    }
    impl<'a> HexSlice for &'a str {}

    #[test]
    fn eax() {
        // Test vectors from https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
        let mut eax = EaxAes::with_key_and_nonce(
            &"233952DEE4D5ED5F9B9C6D6FF80FF478".as_hex(),
            &"62EC67F9C3A4A407FCB2A8C49031A8B3".as_hex()
        ).unwrap();
        eax.update(&"6BFB914FD07EAE6B".as_hex());
        let mut digest = [0; 16];
        eax.digest(&mut digest);
        assert_eq!(&digest, &*"E037830E8389F27B025A2D6527E79D01".as_hex());

        let mut eax = EaxAes::with_key_and_nonce(
            &"91945D3F4DCBEE0BF45EF52255F095A4".as_hex(),
            &"BECAF043B0A23D843194BA972C66DEBD".as_hex()
        ).unwrap();
        eax.update(&"FA3BFD4806EB53FA".as_hex());
        let mut out = [0; 2];
        eax.encrypt(&mut out, &"F7FB".as_hex());
        let mut digest = [0; 16];
        eax.digest(&mut digest);
        let output = [&out[..], &digest[..]].concat();
        assert_eq!(output, &*"19DD5C4C9331049D0BDAB0277408F67967E5".as_hex());

        let mut eax = EaxAes::with_key_and_nonce(
            &"8395FCF1E95BEBD697BD010BC766AAC3".as_hex(),
            &"22E7ADD93CFC6393C57EC0B3C17D6B44".as_hex()
        ).unwrap();
        eax.update(&"126735FCC320D25A".as_hex());
        let mut out1 = [0; 16];
        eax.encrypt(&mut out1, &"CA40D7446E545FFAED3BD12A740A659F".as_hex());
        let mut out2 = [0; 5];
        eax.encrypt(&mut out2, &"FBBB3CEAB7".as_hex());
        let mut digest = [0; 16];
        eax.digest(&mut digest);
        let output = [&out1[..], &out2[..], &digest[..]].concat();
        assert_eq!(output, &*"CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E".as_hex());
    }
}
