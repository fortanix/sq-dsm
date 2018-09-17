use Result;
use s2k::S2K;
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
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct SKESK {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Packet version. Must be 4.
    pub(crate) version: u8,
    /// Symmetric algorithm used to encrypt the session key.
    pub(crate) symm_algo: SymmetricAlgorithm,
    /// Key derivation method for the symmetric key.
    pub(crate) s2k: S2K,
    /// The encrypted session key.
    pub(crate) esk: Option<Vec<u8>>,
}

impl SKESK {
    /// Creates a new SKESK packet.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload, and is also used to encrypt the
    /// given session key.
    pub fn new(algo: SymmetricAlgorithm, s2k: S2K,
               session_key: &[u8], password: &[u8])
               -> Result<SKESK> {
        // Derive key and make a cipher.
        let key = s2k.derive_key(password, algo.key_size()?)?;
        let mut cipher = algo.make_encrypt_cfb(&key[..])?;
        let block_size = algo.block_size()?;
        let mut iv = vec![0u8; block_size];

        // We need to prefix the cipher specifier to the session key.
        let mut psk = Vec::with_capacity(1 + session_key.len());
        psk.push(algo.into());
        psk.extend_from_slice(session_key);
        let mut esk = vec![0u8; psk.len()];

        for (pt, ct) in psk[..].chunks(block_size)
            .zip(esk.chunks_mut(block_size)) {
                cipher.encrypt(&mut iv[..], ct, pt);
        }

        Ok(SKESK{
            common: Default::default(),
            version: 4,
            symm_algo: algo,
            s2k: s2k,
            esk: Some(esk),
        })
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the symmetric encryption algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.symm_algo
    }

    /// Sets the symmetric encryption algorithm.
    pub fn set_symmetric_algo(&mut self, algo: SymmetricAlgorithm) {
        self.symm_algo = algo;
    }

    /// Gets the key derivation method.
    pub fn s2k(&self) -> &S2K {
        &self.s2k
    }

    /// Sets the key derivation method.
    pub fn set_s2k(&mut self, s2k: S2K) {
        self.s2k = s2k;
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> Option<&[u8]> {
        self.esk.as_ref().map(|esk| esk.as_slice())
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Option<Vec<u8>>) {
        self.esk = esk;
    }

    /// Convert the `SKESK` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::SKESK(self)
    }

    /// Derives the key inside this SKESK from `password`. Returns a
    /// tuple of the symmetric cipher to use with the key and the key
    /// itself.
    pub fn decrypt(&self, password: &[u8])
        -> Result<(SymmetricAlgorithm, Vec<u8>)>
    {
        let key = self.s2k.derive_key(password, self.symm_algo.key_size()?)?;

        if let Some(ref esk) = self.esk {
            // Use the derived key to decrypt the ESK. Unlike SEP &
            // SEIP we have to use plain CFB here.
            let blk_sz = self.symm_algo.block_size()?;
            let mut iv = vec![0u8; blk_sz];
            let mut dec  = self.symm_algo.make_decrypt_cfb(&key[..])?;
            let mut plain = vec![0u8; esk.len()];
            let cipher = &esk[..];

            for (pl, ct)
                in plain[..].chunks_mut(blk_sz).zip(cipher.chunks(blk_sz))
            {
                dec.decrypt(&mut iv[..], pl, ct);
            }

            let sym = SymmetricAlgorithm::from(plain[0]);
            let key = plain[1..].to_vec();

            Ok((sym, key))
        } else {
            // No ESK, we return the derived key.

            match self.s2k {
                S2K::Simple{ .. } =>
                    Err(Error::InvalidOperation(
                        "SKESK: Cannot use Simple S2K without ESK".into())
                        .into()),
                _ => Ok((self.symm_algo, key)),
            }
        }
    }
}

impl From<SKESK> for Packet {
    fn from(s: SKESK) -> Self {
        s.to_packet()
    }
}
