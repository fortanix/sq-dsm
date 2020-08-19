//! Symmetric-Key Encrypted Session Key Packets.
//!
//! SKESK packets hold symmetrically encrypted session keys.  The
//! session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.3 of RFC 4880] for details.
//!
//! [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3

use std::ops::{Deref, DerefMut};

#[cfg(any(test, feature = "quickcheck"))]
use quickcheck::{Arbitrary, Gen};

use crate::Result;
use crate::crypto;
use crate::crypto::S2K;
use crate::Error;
use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::packet::{self, SKESK};
use crate::Packet;
use crate::crypto::Password;
use crate::crypto::SessionKey;

impl SKESK {
    /// Derives the key inside this SKESK from `password`. Returns a
    /// tuple of the symmetric cipher to use with the key and the key
    /// itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        match self {
            &SKESK::V4(ref s) => s.decrypt(password),
            &SKESK::V5(ref s) => s.decrypt(password),
            SKESK::__Nonexhaustive => unreachable!(),
        }
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for SKESK {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        if bool::arbitrary(g) {
            SKESK::V4(SKESK4::arbitrary(g))
        } else {
            SKESK::V5(SKESK5::arbitrary(g))
        }
    }
}

/// Holds an symmetrically encrypted session key version 4.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SKESK4 {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Packet version. Must be 4 or 5.
    ///
    /// This struct is also used by SKESK5, hence we have a version
    /// field.
    version: u8,
    /// Symmetric algorithm used to encrypt the session key.
    sym_algo: SymmetricAlgorithm,
    /// Key derivation method for the symmetric key.
    s2k: S2K,
    /// The encrypted session key.
    esk: Option<Vec<u8>>,
}

impl SKESK4 {
    /// Creates a new SKESK version 4 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(esk_algo: SymmetricAlgorithm, s2k: S2K,
               esk: Option<Vec<u8>>) -> Result<SKESK4> {
        Ok(SKESK4{
            common: Default::default(),
            version: 4,
            sym_algo: esk_algo,
            s2k,
            esk: esk.and_then(|esk| {
                if esk.len() == 0 { None } else { Some(esk) }
            }),
        })
    }

    /// Creates a new SKESK4 packet with the given password.
    ///
    /// This function takes two [`SymmetricAlgorithm`] arguments: The
    /// first, `payload_algo`, is the algorithm used to encrypt the
    /// message's payload (i.e. the one used in the [`SEIP`] or
    /// [`AED`] packet), and the second, `esk_algo`, is used to
    /// encrypt the session key.  Usually, one should use the same
    /// algorithm, but if they differ, the `esk_algo` should be at
    /// least as strong as the `payload_algo` as not to weaken the
    /// security of the payload encryption.
    ///
    ///   [`SymmetricAlgorithm`]: ../../types/enum.SymmetricAlgorithm.html
    ///   [`SEIP`]: ../enum.SEIP.html
    ///   [`AED`]: ../enum.AED.html
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
        let mut cipher = esk_algo.make_encrypt_cfb(&key[..])?;
        let block_size = esk_algo.block_size()?;
        let mut iv = vec![0u8; block_size];

        // We need to prefix the cipher specifier to the session key.
        let mut psk: SessionKey = vec![0; 1 + session_key.len()].into();
        psk[0] = payload_algo.into();
        psk[1..].copy_from_slice(&session_key);
        let mut esk = vec![0u8; psk.len()];

        for (pt, ct) in psk[..].chunks(block_size)
            .zip(esk.chunks_mut(block_size)) {
                cipher.encrypt(&mut iv[..], ct, pt)?;
        }

        SKESK4::new(esk_algo, s2k, Some(esk))
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
    pub fn esk(&self) -> Option<&[u8]> {
        self.esk.as_ref().map(|esk| esk.as_slice())
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Option<Vec<u8>>) -> Option<Vec<u8>> {
        ::std::mem::replace(
            &mut self.esk,
            esk.and_then(|esk| {
                if esk.len() == 0 { None } else { Some(esk) }
            }))
    }

    /// Derives the key inside this SKESK4 from `password`.
    ///
    /// Returns a tuple of the symmetric cipher to use with the key
    /// and the key itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        let key = self.s2k.derive_key(password, self.sym_algo.key_size()?)?;

        if let Some(ref esk) = self.esk {
            // Use the derived key to decrypt the ESK. Unlike SEP &
            // SEIP we have to use plain CFB here.
            let blk_sz = self.sym_algo.block_size()?;
            let mut iv = vec![0u8; blk_sz];
            let mut dec  = self.sym_algo.make_decrypt_cfb(&key[..])?;
            let mut plain: SessionKey = vec![0u8; esk.len()].into();
            let cipher = &esk[..];

            for (pl, ct)
                in plain[..].chunks_mut(blk_sz).zip(cipher.chunks(blk_sz))
            {
                dec.decrypt(&mut iv[..], pl, ct)?;
            }

            // Get the algorithm from the front.
            let sym = SymmetricAlgorithm::from(plain[0]);
            Ok((sym, plain[1..].into()))
        } else {
            // No ESK, we return the derived key.

            #[allow(deprecated)]
            match self.s2k {
                S2K::Simple{ .. } =>
                    Err(Error::InvalidOperation(
                        "SKESK4: Cannot use Simple S2K without ESK".into())
                        .into()),
                _ => Ok((self.sym_algo, key)),
            }
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

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for SKESK4 {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        SKESK4::new(SymmetricAlgorithm::arbitrary(g),
                    S2K::arbitrary(g),
                    Option::<Vec<u8>>::arbitrary(g))
            .unwrap()
    }
}

/// Holds an symmetrically encrypted session key version 5.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880bis] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.3
///
/// This feature is [experimental](../../index.html#experimental-features).
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct SKESK5 {
    /// Common fields.
    pub(crate) skesk4: SKESK4,
    /// AEAD algorithm.
    aead_algo: AEADAlgorithm,
    /// Initialization vector for the AEAD algorithm.
    aead_iv: Box<[u8]>,
    /// Digest for the AEAD algorithm.
    aead_digest: Box<[u8]>,
}

impl Deref for SKESK5 {
    type Target = SKESK4;

    fn deref(&self) -> &Self::Target {
        &self.skesk4
    }
}

impl DerefMut for SKESK5 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.skesk4
    }
}

impl SKESK5 {
    /// Creates a new SKESK version 5 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(esk_algo: SymmetricAlgorithm, esk_aead: AEADAlgorithm,
               s2k: S2K, iv: Box<[u8]>, esk: Vec<u8>, digest: Box<[u8]>)
               -> Result<Self> {
        Ok(SKESK5{
            skesk4: SKESK4{
                common: Default::default(),
                version: 5,
                sym_algo: esk_algo,
                s2k,
                esk: Some(esk),
            },
            aead_algo: esk_aead,
            aead_iv: iv,
            aead_digest: digest,
        })
    }

    /// Creates a new SKESK version 5 packet with the given password.
    ///
    /// This function takes two [`SymmetricAlgorithm`] arguments: The
    /// first, `payload_algo`, is the algorithm used to encrypt the
    /// message's payload (i.e. the one used in the [`SEIP`] or
    /// [`AED`] packet), and the second, `esk_algo`, is used to
    /// encrypt the session key.  Usually, one should use the same
    /// algorithm, but if they differ, the `esk_algo` should be at
    /// least as strong as the `payload_algo` as not to weaken the
    /// security of the payload encryption.
    ///
    ///   [`SymmetricAlgorithm`]: ../../types/enum.SymmetricAlgorithm.html
    ///   [`SEIP`]: ../enum.SEIP.html
    ///   [`AED`]: ../enum.AED.html
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
        let key = s2k.derive_key(password, esk_algo.key_size()?)?;
        let mut iv = vec![0u8; esk_aead.iv_size()?];
        crypto::random(&mut iv);
        let mut ctx = esk_aead.context(esk_algo, &key, &iv)?;

        // Prepare associated data.
        let ad = [0xc3, 5, esk_algo.into(), esk_aead.into()];
        ctx.update(&ad);

        // We need to prefix the cipher specifier to the session key.
        let mut esk = vec![0u8; session_key.len()];
        ctx.encrypt(&mut esk, &session_key);

        // Digest.
        let mut digest = vec![0u8; esk_aead.digest_size()?];
        ctx.digest(&mut digest);

        SKESK5::new(esk_algo, esk_aead, s2k, iv.into_boxed_slice(), esk,
                    digest.into_boxed_slice())
    }

    /// Derives the key inside this `SKESK5` from `password`.
    ///
    /// Returns a tuple containing a placeholder symmetric cipher and
    /// the key itself.  `SKESK5` packets do not contain the symmetric
    /// cipher algorithm and instead rely on the `AED` packet that
    /// contains it.
    // XXX: This function should return Result<SessionKey>, but then
    // SKESK::decrypt must return an
    // Result<(Option<SymmetricAlgorithm>, _)> and
    // DecryptionHelper::decrypt and PacketParser::decrypt must be
    // adapted as well.
    pub fn decrypt(&self, password: &Password)
                   -> Result<(SymmetricAlgorithm, SessionKey)> {
        let key = self.s2k().derive_key(password,
                                        self.symmetric_algo().key_size()?)?;

        if let Some(ref esk) = self.esk() {
            // Use the derived key to decrypt the ESK.
            let mut cipher = self.aead_algo.context(
                self.symmetric_algo(), &key, &self.aead_iv)?;

            let ad = [0xc3, 5 /* Version.  */, self.symmetric_algo().into(),
                      self.aead_algo.into()];
            cipher.update(&ad);
            let mut plain: SessionKey = vec![0; esk.len()].into();
            let mut digest = vec![0; self.aead_algo.digest_size()?];
            cipher.decrypt(&mut plain, esk);
            cipher.digest(&mut digest);
            if &digest[..] == &self.aead_digest[..] {
                Ok((SymmetricAlgorithm::Unencrypted, plain))
            } else {
                Err(Error::ManipulatedMessage.into())
            }
        } else {
            Err(Error::MalformedPacket(
                "No encrypted session key in v5 SKESK packet".into())
                .into())
        }
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

    /// Gets the AEAD digest.
    pub fn aead_digest(&self) -> &[u8] {
        &self.aead_digest
    }

    /// Sets the AEAD digest.
    pub fn set_aead_digest(&mut self, digest: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.aead_digest, digest)
    }
}

impl From<SKESK5> for super::SKESK {
    fn from(p: SKESK5) -> Self {
        super::SKESK::V5(p)
    }
}

impl From<SKESK5> for Packet {
    fn from(s: SKESK5) -> Self {
        Packet::SKESK(SKESK::V5(s))
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for SKESK5 {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let algo = AEADAlgorithm::EAX;  // The only one we dig.
        let mut iv = vec![0u8; algo.iv_size().unwrap()];
        for b in iv.iter_mut() {
            *b = u8::arbitrary(g);
        }
        let mut digest = vec![0u8; algo.digest_size().unwrap()];
        for b in digest.iter_mut() {
            *b = u8::arbitrary(g);
        }
        SKESK5::new(SymmetricAlgorithm::arbitrary(g),
                    algo,
                    S2K::arbitrary(g),
                    iv.into_boxed_slice(),
                    Vec::<u8>::arbitrary(g),
                    digest.into_boxed_slice())
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PacketPile;
    use crate::parse::Parse;
    use crate::serialize::{Marshal, MarshalInto};

    quickcheck! {
        fn roundtrip(p: SKESK) -> bool {
            let q = SKESK::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn sample_skesk5_packet() {
        // This sample packet is from RFC4880bis-05, section A.3.
        let password: Password = String::from("password").into();
        let raw = [
            // Packet header:
            0xc3, 0x3e,

            // Version, algorithms, S2K fields:
            0x05, 0x07, 0x01, 0x03, 0x08, 0xcd, 0x5a, 0x9f,
            0x70, 0xfb, 0xe0, 0xbc, 0x65, 0x90,

            // AEAD IV:
            0xbc, 0x66, 0x9e, 0x34, 0xe5, 0x00, 0xdc, 0xae,
            0xdc, 0x5b, 0x32, 0xaa, 0x2d, 0xab, 0x02, 0x35,

            // AEAD encrypted CEK:
            0x9d, 0xee, 0x19, 0xd0, 0x7c, 0x34, 0x46, 0xc4,
            0x31, 0x2a, 0x34, 0xae, 0x19, 0x67, 0xa2, 0xfb,

            // Authentication tag:
            0x7e, 0x92, 0x8e, 0xa5, 0xb4, 0xfa, 0x80, 0x12,
            0xbd, 0x45, 0x6d, 0x17, 0x38, 0xc6, 0x3c, 0x36,
        ];
        let packets: Vec<Packet> =
            PacketPile::from_bytes(&raw[..]).unwrap().into_children().collect();
        assert_eq!(packets.len(), 1);
        if let Packet::SKESK(SKESK::V5(ref s)) = packets[0] {
            assert_eq!(&s.s2k().derive_key(
                &password, s.symmetric_algo().key_size().unwrap()).unwrap()[..],
                       &[0xb2, 0x55, 0x69, 0xb9, 0x54, 0x32, 0x45, 0x66,
                         0x45, 0x27, 0xc4, 0x97, 0x6e, 0x7a, 0x5d, 0x6e][..]);

            assert_eq!(&s.decrypt(&password).unwrap().1[..],
                       &[0x86, 0xf1, 0xef, 0xb8, 0x69, 0x52, 0x32, 0x9f,
                         0x24, 0xac, 0xd3, 0xbf, 0xd0, 0xe5, 0x34, 0x6d][..]);
        } else {
            panic!("bad packet");
        }

        let mut serialized = Vec::new();
        packets[0].serialize(&mut serialized).unwrap();
        assert_eq!(&raw[..], &serialized[..]);
    }
}
