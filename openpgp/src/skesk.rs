use Result;
use SymmetricAlgo;
use SKESK;
use Packet;
use symmetric::symmetric_key_size;

use nettle::Cipher;
use nettle::cipher::Aes128;
use nettle::Mode;
use nettle::mode::Cfb;

impl SKESK {
    /// Convert the `SKESK` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::SKESK(self)
    }

    /// Returns the session key.
    pub fn decrypt(&self, password: &[u8]) -> Result<(u8, Vec<u8>)> {
        let key = self.s2k.s2k(password, symmetric_key_size(self.symm_algo)?)?;

        if self.esk.len() == 0 {
            return Ok((self.symm_algo, key));
        }

        /// XXX: We only support AES128 right now.  Ideally, we'd have
        /// a function like hash_context to get a generic decryptor,
        /// but the Nettle wrapper needs to be changed a bit.
        assert_eq!(self.symm_algo, SymmetricAlgo::AES128.to_numeric());

        let mut dec = Cfb::<Aes128>::with_encrypt_key(&key[..]);

        let mut iv = vec![0u8; Aes128::BLOCK_SIZE];
        let mut sk = vec![0u8; self.esk.len()];
        dec.decrypt(&mut iv[..], &mut sk[..], &self.esk[..]);

        assert!(sk.len() > 0);
        let symm_algo = sk[0];
        let key_len = symmetric_key_size(symm_algo).unwrap_or(sk.len() - 1);

        let key = sk[1..1 + key_len].to_vec();

        return Ok((symm_algo, key));
    }
}
