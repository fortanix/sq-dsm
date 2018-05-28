use Result;
use S2K;
use Error;
use SymmetricAlgorithm;
use packet;
use Packet;

/// Holds an symmetrically encrypted session key.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3
#[derive(PartialEq, Clone, Debug)]
pub struct SKESK {
    pub common: packet::Common,
    pub version: u8,
    pub symm_algo: SymmetricAlgorithm,
    pub s2k: S2K,
    // The encrypted session key.
    pub esk: Vec<u8>,
}

impl SKESK {
    /// Convert the `SKESK` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::SKESK(self)
    }

    /// Derives the key inside this SKESK from `password`. Returns a tuple of the symmetric cipher
    /// to use with the key and the key itself.
    pub fn decrypt(&self, password: &[u8])
        -> Result<(SymmetricAlgorithm, Vec<u8>)>
    {
        let key = self.s2k.derive_key(password, self.symm_algo.key_size()?)?;

        if self.esk.len() == 0 {
            // No ESK, we return the derived key.

            match self.s2k {
                S2K::Simple{ .. } =>
                    Err(Error::InvalidOperation("SKESK: Cannot use Simple S2K without ESK".into()).into()),
                _ => Ok((self.symm_algo, key)),
            }
        } else {
            // Use the derived key to decrypt the ESK. Unlike SEP & SEIP we have
            // to use plain CFB here.
            let blk_sz = self.symm_algo.block_size()?;
            let mut iv = vec![0u8; blk_sz];
            let mut dec  = self.symm_algo.make_decrypt_cfb(&key[..])?;
            let mut plain = vec![0u8; self.esk.len()];
            let cipher = &self.esk[..];

            for (pl,ct) in plain[..].chunks_mut(blk_sz).zip(cipher.chunks(blk_sz)) {
                dec.decrypt(&mut iv[..], pl, ct);
            }

            let sym = SymmetricAlgorithm::from(plain[0]);
            let key = plain[1..].to_vec();

            Ok((sym, key))
        }
    }
}
