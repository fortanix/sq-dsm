//! Symmetric-Key Encrypted Session Key Packets.
//!
//! SKESK packets hold symmetrically encrypted session keys.  The
//! session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.3 of RFC 9580] for details.
//!
//! [Section 5.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Result;
use crate::crypto::{
    S2K,
    Password,
    SessionKey,
};

use crate::Error;
use crate::types::{
    SymmetricAlgorithm,
};
use crate::packet::{self, SKESK};
use crate::Packet;

/// Holds a symmetrically encrypted session key version 4.
///
/// Holds a symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 9580] for details.
///
/// [Section 5.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3
#[derive(Clone, Debug)]
pub struct SKESK4 {
    /// CTB header fields.
    pub(crate) common: packet::Common,

    /// Packet version. Must be 4 or 5.
    ///
    /// This struct is also used by SKESK6, hence we have a version
    /// field.
    pub(crate) version: u8,

    /// Symmetric algorithm used to encrypt the session key.
    pub(crate) sym_algo: SymmetricAlgorithm,

    /// Key derivation method for the symmetric key.
    pub(crate) s2k: S2K,

    /// The encrypted session key.
    ///
    /// If we recognized the S2K object during parsing, we can
    /// successfully parse the data into S2K and ciphertext.  However,
    /// if we do not recognize the S2K type, we do not know how large
    /// its parameters are, so we cannot cleanly parse it, and have to
    /// accept that the S2K's body bleeds into the rest of the data.
    pub(crate) esk: std::result::Result<Option<Box<[u8]>>, // optional ciphertext.
                                        Box<[u8]>>,        // S2K body + maybe ciphertext.
}
assert_send_and_sync!(SKESK4);

// Because the S2K and ESK cannot be cleanly separated at parse time,
// we need to carefully compare and hash SKESK4 packets.

impl PartialEq for SKESK4 {
    fn eq(&self, other: &SKESK4) -> bool {
        self.version == other.version
            && self.sym_algo == other.sym_algo
            // Treat S2K and ESK as opaque blob.
            && {
                // XXX: This would be nicer without the allocations.
                use crate::serialize::MarshalInto;
                let mut a = self.s2k.to_vec().unwrap();
                let mut b = other.s2k.to_vec().unwrap();
                a.extend_from_slice(self.raw_esk());
                b.extend_from_slice(other.raw_esk());
                a == b
            }
    }
}

impl Eq for SKESK4 {}

impl std::hash::Hash for SKESK4 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
        self.sym_algo.hash(state);
        // Treat S2K and ESK as opaque blob.
        // XXX: This would be nicer without the allocations.
        use crate::serialize::MarshalInto;
        let mut a = self.s2k.to_vec().unwrap();
        a.extend_from_slice(self.raw_esk());
        a.hash(state);
    }
}

impl SKESK4 {
    /// Creates a new SKESK version 4 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(esk_algo: SymmetricAlgorithm, s2k: S2K,
               esk: Option<Box<[u8]>>) -> Result<SKESK4> {
        Self::new_raw(esk_algo, s2k, Ok(esk.and_then(|esk| {
            if esk.len() == 0 { None } else { Some(esk) }
        })))
    }

    /// Creates a new SKESK version 4 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub(crate) fn new_raw(esk_algo: SymmetricAlgorithm, s2k: S2K,
                          esk: std::result::Result<Option<Box<[u8]>>,
                                                   Box<[u8]>>)
                          -> Result<SKESK4> {
        Ok(SKESK4{
            common: Default::default(),
            version: 4,
            sym_algo: esk_algo,
            s2k,
            esk,
        })
    }

    /// Creates a new SKESK4 packet with the given password.
    ///
    /// This function takes two [`SymmetricAlgorithm`] arguments: The
    /// first, `payload_algo`, is the algorithm used to encrypt the
    /// message's payload (i.e. the one used in the [`SEIP`]), and the
    /// second, `esk_algo`, is used to encrypt the session key.
    /// Usually, one should use the same algorithm, but if they
    /// differ, the `esk_algo` should be at least as strong as the
    /// `payload_algo` as not to weaken the security of the payload
    /// encryption.
    ///
    ///   [`SymmetricAlgorithm`]: crate::types::SymmetricAlgorithm
    ///   [`SEIP`]: crate::packet::SEIP
    pub fn with_password(payload_algo: SymmetricAlgorithm,
                         esk_algo: SymmetricAlgorithm,
                         s2k: S2K,
                         session_key: &SessionKey, password: &Password)
                         -> Result<SKESK4> {
        if session_key.len() != payload_algo.key_size()? {
            return Err(Error::InvalidArgument(format!(
                "Invalid size of session key, got {} want {}",
                session_key.len(), payload_algo.key_size()?)).into());
        }

        // Derive key and make a cipher.
        let key = s2k.derive_key(password, esk_algo.key_size()?)?;
        let block_size = esk_algo.block_size()?;

        use crate::crypto::symmetric::BlockCipherMode;
        use crate::crypto::backend::{Backend, interface::Symmetric};
        let mut cipher = Backend::encryptor(esk_algo, BlockCipherMode::CFB,
                                            key.as_protected(), None)?;

        // We need to prefix the cipher specifier to the session key.
        let mut psk: SessionKey = vec![0; 1 + session_key.len()].into();
        psk[0] = payload_algo.into();
        psk[1..].copy_from_slice(session_key);
        let mut esk = vec![0u8; psk.len()];

        for (pt, ct) in psk[..].chunks(block_size)
            .zip(esk.chunks_mut(block_size)) {
                cipher.encrypt(ct, pt)?;
        }

        SKESK4::new(esk_algo, s2k, Some(esk.into()))
    }

    /// Gets the symmetric encryption algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the symmetric encryption algorithm.
    pub fn set_symmetric_algo(&mut self, algo: SymmetricAlgorithm) -> SymmetricAlgorithm {
        ::std::mem::replace(&mut self.sym_algo, algo)
    }

    /// Gets the key derivation method.
    pub fn s2k(&self) -> &S2K {
        &self.s2k
    }

    /// Sets the key derivation method.
    pub fn set_s2k(&mut self, s2k: S2K) -> S2K {
        ::std::mem::replace(&mut self.s2k, s2k)
    }

    /// Gets the encrypted session key.
    ///
    /// If the [`S2K`] mechanism is not supported by Sequoia, this
    /// function will fail.  Note that the information is not lost,
    /// but stored in the packet.  If the packet is serialized again,
    /// it is written out.
    ///
    ///   [`S2K`]: crate::crypto::S2K
    pub fn esk(&self) -> Result<Option<&[u8]>> {
        self.esk.as_ref()
            .map(|esko| esko.as_ref().map(|esk| &esk[..]))
            .map_err(|_| Error::MalformedPacket(
                format!("Unknown S2K: {:?}", self.s2k)).into())
    }

    /// Returns the encrypted session key, possibly including the body
    /// of the S2K object.
    pub(crate) fn raw_esk(&self) -> &[u8] {
        match self.esk.as_ref() {
            Ok(Some(esk)) => &esk[..],
            Ok(None) => &[][..],
            Err(s2k_esk) => &s2k_esk[..],
        }
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Option<Box<[u8]>>) -> Option<Box<[u8]>> {
        ::std::mem::replace(
            &mut self.esk,
            Ok(esk.and_then(|esk| {
                if esk.len() == 0 { None } else { Some(esk) }
            })))
            .unwrap_or(None)
    }

    /// Derives the key inside this SKESK4 from `password`.
    ///
    /// Returns a tuple of the symmetric cipher to use with the key
    /// and the key itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        let key = self.s2k.derive_key(password, self.sym_algo.key_size()?)?;

        if let Some(esk) = self.esk()? {
            // Use the derived key to decrypt the ESK. Unlike SEP &
            // SEIP we have to use plain CFB here.
            let blk_sz = self.sym_algo.block_size()?;

            use crate::crypto::symmetric::BlockCipherMode;
            use crate::crypto::backend::{Backend, interface::Symmetric};
            let mut dec = Backend::decryptor(self.sym_algo, BlockCipherMode::CFB,
                                             key.as_protected(), None)?;

            let mut plain: SessionKey = vec![0u8; esk.len()].into();
            let cipher = esk;

            for (pl, ct)
                in plain[..].chunks_mut(blk_sz).zip(cipher.chunks(blk_sz))
            {
                dec.decrypt(pl, ct)?;
            }

            // Get the algorithm from the front.
            let sym = SymmetricAlgorithm::from(plain[0]);
            Ok((sym, plain[1..].into()))
        } else {
            // No ESK, we return the derived key.
            Ok((self.sym_algo, key))
        }
    }
}

impl From<SKESK4> for super::SKESK {
    fn from(p: SKESK4) -> Self {
        super::SKESK::V4(p)
    }
}

impl From<SKESK4> for Packet {
    fn from(s: SKESK4) -> Self {
        Packet::SKESK(SKESK::V4(s))
    }
}

#[cfg(test)]
impl Arbitrary for SKESK4 {
    fn arbitrary(g: &mut Gen) -> Self {
        SKESK4::new(SymmetricAlgorithm::arbitrary(g),
                    S2K::arbitrary(g),
                    Option::<Vec<u8>>::arbitrary(g).map(|v| v.into()))
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip_v4(p: SKESK4) -> bool {
            let p = SKESK::from(p);
            let q = SKESK::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    /// Tests various S2K methods, with and without encrypted session
    /// key.
    #[test]
    fn skesk4_s2k_variants() -> Result<()> {
        use std::io::Read;
        use crate::{
            Cert,
            packet::{SKESK, PKESK},
            parse::stream::*,
        };

        struct H();
        impl VerificationHelper for H {
            fn get_certs(&mut self, _ids: &[crate::KeyHandle])
                         -> Result<Vec<Cert>> {
                Ok(Vec::new())
            }

            fn check(&mut self, _m: MessageStructure)
                     -> Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for H {
            fn decrypt(&mut self, _: &[PKESK], skesks: &[SKESK],
                       _: Option<SymmetricAlgorithm>,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                       -> Result<Option<Cert>>
            {
                assert_eq!(skesks.len(), 1);
                let (cipher, sk) = skesks[0].decrypt(&"password".into())?;
                assert_eq!(cipher, Some(SymmetricAlgorithm::AES256));
                let r = decrypt(cipher, &sk);
                assert!(r);
                Ok(None)
            }
        }

        let p = &crate::policy::StandardPolicy::new();
        for variant in &["simple", "salted", "iterated.min", "iterated.max"] {
            for esk in &["", ".esk"] {
                let name = format!("s2k/{}{}.pgp", variant, esk);
                eprintln!("{}", name);
                let mut verifier = DecryptorBuilder::from_bytes(
                    crate::tests::message(&name))?
                    .with_policy(p, None, H())?;
                let mut b = Vec::new();
                verifier.read_to_end(&mut b)?;
                assert_eq!(&b, b"Hello World :)");
            }
        }

        Ok(())
    }
}
