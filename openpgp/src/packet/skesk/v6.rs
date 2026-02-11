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
    self,
    S2K,
    Password,
    SessionKey,
    backend::{Backend, interface::Kdf},
};
use crate::Error;
use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::packet::{
    Packet,
    SKESK,
    skesk::SKESK4,
};

/// Holds a symmetrically encrypted session key version 6.
///
/// Holds a symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Version 6 Symmetric
/// Key Encrypted Session Key Packet Format] for details.
///
/// [Version 6 Symmetric Key Encrypted Session Key Packet Format]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SKESK6 {
    /// Common fields.
    pub(crate) skesk4: SKESK4,

    /// AEAD algorithm.
    aead_algo: AEADAlgorithm,

    /// Initialization vector for the AEAD algorithm.
    aead_iv: Box<[u8]>,
}
assert_send_and_sync!(SKESK6);

impl SKESK6 {
    /// Creates a new SKESK version 6 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(sym_algo: SymmetricAlgorithm,
               aead_algo: AEADAlgorithm,
               s2k: S2K,
               aead_iv: Box<[u8]>,
               esk: Box<[u8]>)
               -> Result<Self> {
        Ok(SKESK6 {
            skesk4: SKESK4 {
                common: Default::default(),
                version: 6,
                sym_algo,
                s2k,
                esk: Ok(Some(esk)),
            },
            aead_algo,
            aead_iv,
        })
    }

    /// Creates a new SKESK version 6 packet with the given password.
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
                         esk_aead: AEADAlgorithm, s2k: S2K,
                         session_key: &SessionKey, password: &Password)
                         -> Result<Self> {
        if session_key.len() != payload_algo.key_size()? {
            return Err(Error::InvalidArgument(format!(
                "Invalid size of session key, got {} want {}",
                session_key.len(), payload_algo.key_size()?)).into());
        }

        // Derive key and make a cipher.
        let ad = [0xc3, 6, esk_algo.into(), esk_aead.into()];
        let key = s2k.derive_key(password, esk_algo.key_size()?)?;

        let mut kek: SessionKey = vec![0; esk_algo.key_size()?].into();
        Backend::hkdf_sha256(&key, None, &ad, &mut kek)?;


        // Encrypt the session key with the KEK.
        let mut iv = vec![0u8; esk_aead.nonce_size()?];
        crypto::random(&mut iv)?;
        let mut ctx =
            esk_aead.context(esk_algo, &kek, &ad, &iv)?.for_encryption()?;
        let mut esk_digest =
            vec![0u8; session_key.len() + esk_aead.digest_size()?];
        ctx.encrypt_seal(&mut esk_digest, session_key)?;

        // Attach digest to the ESK, we model it as one.
        SKESK6::new(esk_algo, esk_aead, s2k, iv.into_boxed_slice(),
                    esk_digest.into())
    }

    /// Derives the key inside this `SKESK6` from `password`.
    ///
    /// Returns a tuple containing a placeholder symmetric cipher and
    /// the key itself.  `SKESK6` packets do not contain the symmetric
    /// cipher algorithm and instead rely on the `SEIPDv2` packet that
    /// contains it.
    pub fn decrypt(&self, password: &Password)
                   -> Result<SessionKey> {
        let key = self.s2k().derive_key(password,
                                        self.symmetric_algo().key_size()?)?;

        let mut kek: SessionKey =
            vec![0; self.symmetric_algo().key_size()?].into();
        let ad = [0xc3,
                  6 /* Version.  */,
                  self.symmetric_algo().into(),
                  self.aead_algo.into()];
        Backend::hkdf_sha256(&key, None, &ad, &mut kek)?;

        // Use the derived key to decrypt the ESK.
        let mut cipher = self.aead_algo.context(
            self.symmetric_algo(), &kek, &ad, self.aead_iv())?
            .for_decryption()?;

        let mut plain: SessionKey =
            vec![0; self.esk().len() - self.aead_algo.digest_size()?].into();
        cipher.decrypt_verify(&mut plain, self.esk())?;
        Ok(plain)
    }

    /// Gets the symmetric encryption algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.skesk4.sym_algo
    }

    /// Sets the symmetric encryption algorithm.
    pub fn set_symmetric_algo(&mut self, algo: SymmetricAlgorithm) -> SymmetricAlgorithm {
        ::std::mem::replace(&mut self.skesk4.sym_algo, algo)
    }

    /// Gets the key derivation method.
    pub fn s2k(&self) -> &S2K {
        &self.skesk4.s2k
    }

    /// Sets the key derivation method.
    pub fn set_s2k(&mut self, s2k: S2K) -> S2K {
        ::std::mem::replace(&mut self.skesk4.s2k, s2k)
    }

    /// Gets the AEAD algorithm.
    pub fn aead_algo(&self) -> AEADAlgorithm {
        self.aead_algo
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead_algo(&mut self, algo: AEADAlgorithm) -> AEADAlgorithm {
        ::std::mem::replace(&mut self.aead_algo, algo)
    }

    /// Gets the AEAD initialization vector.
    pub fn aead_iv(&self) -> &[u8] {
        &self.aead_iv
    }

    /// Sets the AEAD initialization vector.
    pub fn set_aead_iv(&mut self, iv: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.aead_iv, iv)
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &[u8] {
        self.skesk4.raw_esk()
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.skesk4.esk, Ok(Some(esk)))
            .expect("v6 SKESK can always be parsed")
            .expect("v6 SKESK packets always have an ESK")
    }
}

impl From<SKESK6> for super::SKESK {
    fn from(p: SKESK6) -> Self {
        super::SKESK::V6(p)
    }
}

impl From<SKESK6> for Packet {
    fn from(s: SKESK6) -> Self {
        Packet::SKESK(SKESK::V6(s))
    }
}

#[cfg(test)]
impl Arbitrary for SKESK6 {
    fn arbitrary(g: &mut Gen) -> Self {
        let symm = SymmetricAlgorithm::arbitrary(g);
        let aead = AEADAlgorithm::arbitrary(g);
        let mut iv = vec![0u8; aead.nonce_size().unwrap_or(16)];
        for b in iv.iter_mut() {
            *b = u8::arbitrary(g);
        }
        let esk_len =
            symm.key_size().unwrap_or(16) + aead.digest_size().unwrap_or(16);
        let mut esk = vec![0u8; esk_len];
        for b in esk.iter_mut() {
            *b = u8::arbitrary(g);
        }
        SKESK6::new(symm,
                    aead,
                    S2K::arbitrary(g),
                    iv.into(),
                    esk.into())
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PacketPile;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip_v6(p: SKESK6) -> bool {
            let p = SKESK::from(p);
            let q = SKESK::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    /// This sample packet is from RFC9580.
    #[test]
    fn v6skesk_aes128_ocb() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::OCB,
            "crypto-refresh/v6skesk-aes128-ocb.pgp",
            b"\xe8\x0d\xe2\x43\xa3\x62\xd9\x3b\
              \x9d\xc6\x07\xed\xe9\x6a\x73\x56",
            b"\x28\xe7\x9a\xb8\x23\x97\xd3\xc6\
              \x3d\xe2\x4a\xc2\x17\xd7\xb7\x91")
    }

    /// This sample packet is from RFC9580.
    #[test]
    fn v6skesk_aes128_eax() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::EAX,
            "crypto-refresh/v6skesk-aes128-eax.pgp",
            b"\x15\x49\x67\xe5\x90\xaa\x1f\x92\
              \x3e\x1c\x0a\xc6\x4c\x88\xf2\x3d",
            b"\x38\x81\xba\xfe\x98\x54\x12\x45\
              \x9b\x86\xc3\x6f\x98\xcb\x9a\x5e")
    }

    /// This sample packet is from RFC9580.
    #[test]
    fn v6skesk_aes128_gcm() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::GCM,
            "crypto-refresh/v6skesk-aes128-gcm.pgp",
            b"\x25\x02\x81\x71\x5b\xba\x78\x28\
              \xef\x71\xef\x64\xc4\x78\x47\x53",
            b"\x19\x36\xfc\x85\x68\x98\x02\x74\
              \xbb\x90\x0d\x83\x19\x36\x0c\x77")
    }

    fn sample_skesk6_packet(cipher: SymmetricAlgorithm,
                            aead: AEADAlgorithm,
                            name: &str,
                            derived_key: &[u8],
                            session_key: &[u8])
                            -> Result<()> {
        let password: Password = String::from("password").into();
        let packets: Vec<Packet> =
            PacketPile::from_bytes(
                crate::tests::file(name))?
            .into_children().collect();
        assert_eq!(packets.len(), 2);
        if let Packet::SKESK(SKESK::V6(ref s)) = packets[0] {
            let derived = s.s2k().derive_key(
                &password, s.symmetric_algo().key_size()?)?;
            eprintln!("derived: {:x?}", &derived[..]);
            assert_eq!(&derived[..], derived_key);

            use crate::crypto::backend::{Backend, interface::Aead};
            if Backend::supports_algo_with_symmetric(aead, cipher)
            {
                let sk = s.decrypt(&password)?;
                eprintln!("sk: {:x?}", &sk[..]);
                assert_eq!(&sk[..], session_key);
            } else {
                eprintln!("{}-{} is not supported, skipping decryption.",
                          cipher, aead);
            }
        } else {
            panic!("bad packet, expected v6 SKESK: {:?}", packets[0]);
        }

        Ok(())
    }
}
