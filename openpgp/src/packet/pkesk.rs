//! PublicKey-Encrypted Session Key packets.
//!
//! The session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.1 of RFC 4880] for details.
//!
//!   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1

use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::packet::key;
use crate::packet::Key;
use crate::KeyID;
use crate::crypto::Decryptor;
use crate::crypto::mpis::{self, MPI, Ciphertext};
use crate::Packet;
use crate::PublicKeyAlgorithm;
use crate::Result;
use crate::SymmetricAlgorithm;
use crate::crypto::SessionKey;
use crate::crypto::ecdh;
use nettle::{rsa, Yarrow};
use crate::packet;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Section 5.1 of RFC 4880] for details.
///
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct PKESK3 {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Key ID of the key this is encrypted to.
    recipient: KeyID,
    /// Public key algorithm used to encrypt the session key.
    pk_algo: PublicKeyAlgorithm,
    /// The encrypted session key.
    esk: Ciphertext,
}

impl PKESK3 {
    /// Creates a new PKESK3 packet.
    pub fn new(recipient: KeyID, pk_algo: PublicKeyAlgorithm,
               encrypted_session_key: Ciphertext)
               -> Result<PKESK3> {
        Ok(PKESK3 {
            common: Default::default(),
            recipient: recipient,
            pk_algo: pk_algo,
            esk: encrypted_session_key,
        })
    }

    /// Creates a new PKESK3 packet for the given recipent.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload.
    pub fn for_recipient<R>(algo: SymmetricAlgorithm,
                            session_key: &SessionKey,
                            recipient: &Key<key::PublicParts, R>)
        -> Result<PKESK3>
        where R: key::KeyRole
    {
        use crate::PublicKeyAlgorithm::*;
        let mut rng = Yarrow::default();

        // We need to prefix the cipher specifier to the session key,
        // and a two-octet checksum.
        let mut psk = Vec::with_capacity(1 + session_key.len() + 2);
        psk.push(algo.into());
        psk.extend_from_slice(session_key);

        // Compute the sum modulo 65536.
        let checksum
            = session_key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
        psk.push((checksum >> 8) as u8);
        psk.push((checksum >> 0) as u8);
        let psk: SessionKey = psk.into();

        #[allow(deprecated)]
        let esk = match recipient.pk_algo() {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match recipient.mpis() {
                    &mpis::PublicKey::RSA { ref e, ref n } => {
                        // The ciphertext has the length of the modulus.
                        let mut esk = vec![0u8; n.value().len()];

                        let pk = rsa::PublicKey::new(n.value(), e.value())?;
                        rsa::encrypt_pkcs1(&pk, &mut rng, &psk, &mut esk)?;
                        Ciphertext::RSA {c: MPI::new(&esk)}
                    }

                    pk => {
                        return Err(
                            Error::MalformedPacket(
                                format!(
                                    "Key: Expected RSA public key, got {:?}",
                                    pk)).into());
                    }
                }
            },

            ECDH => ecdh::encrypt(recipient, &psk)?,

            algo =>
                return Err(Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        };

        Ok(PKESK3{
            common: Default::default(),
            recipient: recipient.keyid(),
            pk_algo: recipient.pk_algo(),
            esk: esk,
        })
    }

    /// Gets the recipient.
    pub fn recipient(&self) -> &KeyID {
        &self.recipient
    }

    /// Sets the recipient.
    pub fn set_recipient(&mut self, recipient: KeyID) -> KeyID {
        ::std::mem::replace(&mut self.recipient, recipient)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm) -> PublicKeyAlgorithm {
        ::std::mem::replace(&mut self.pk_algo, algo)
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &Ciphertext {
        &self.esk
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Ciphertext) -> Ciphertext {
        ::std::mem::replace(&mut self.esk, esk)
    }

    /// Decrypts the ESK and returns the session key and symmetric algorithm
    /// used to encrypt the following payload.
    pub fn decrypt<R>(&self, decryptor: &mut dyn Decryptor<R>)
        -> Result<(SymmetricAlgorithm, SessionKey)>
        where R: key::KeyRole
    {
        let plain = decryptor.decrypt(&self.esk)?;
        let key_rgn = 1..(plain.len() - 2);
        let sym_algo: SymmetricAlgorithm = plain[0].into();
        let mut key: SessionKey = vec![0u8; sym_algo.key_size()?].into();

        if key_rgn.len() != sym_algo.key_size()? {
            return Err(Error::MalformedPacket(
                format!("session key has the wrong size")).into());
        }

        key.copy_from_slice(&plain[key_rgn]);

        let our_checksum
            = key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
        let their_checksum = (plain[plain.len() - 2] as usize) << 8
            | (plain[plain.len() - 1] as usize);

        if their_checksum == our_checksum {
            Ok((sym_algo, key))
        } else {
            Err(Error::MalformedPacket(format!("key checksum wrong"))
                .into())
        }
    }
}

impl From<PKESK3> for super::PKESK {
    fn from(p: PKESK3) -> Self {
        super::PKESK::V3(p)
    }
}

impl From<PKESK3> for Packet {
    fn from(p: PKESK3) -> Self {
        Packet::PKESK(p.into())
    }
}

impl Arbitrary for PKESK3 {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let (ciphertext, pk_algo) = loop {
            let ciphertext = Ciphertext::arbitrary(g);
            if let Some(pk_algo) = ciphertext.pk_algo() {
                break (ciphertext, pk_algo);
            }
        };

        PKESK3::new(KeyID::arbitrary(g), pk_algo, ciphertext).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TPK;
    use crate::PacketPile;
    use crate::Packet;
    use crate::parse::Parse;
    use crate::serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: PKESK3) -> bool {
            let q = PKESK3::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn decrypt_rsa() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy.gpg")).unwrap();
        let mut keypair =
            tpk.subkeys().next().unwrap()
            .key().clone().mark_parts_secret().into_keypair().unwrap();

        let pkg = pile.descendants().skip(0).next().clone();

        if let Some(Packet::PKESK(ref pkesk)) = pkg {
            let plain = pkesk.decrypt(&mut keypair).unwrap();

            eprintln!("plain: {:?}", plain);
        } else {
            panic!("message is not a PKESK packet");
        }
    }

    #[test]
    fn decrypt_ecdh_cv25519() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-new-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-new.pgp")).unwrap();
        let mut keypair =
            tpk.subkeys().next().unwrap()
            .key().clone().mark_parts_secret().into_keypair().unwrap();

        let pkg = pile.descendants().skip(0).next().clone();

        if let Some(Packet::PKESK(ref pkesk)) = pkg {
            let plain = pkesk.decrypt(&mut keypair).unwrap();

            eprintln!("plain: {:?}", plain);
        } else {
            panic!("message is not a PKESK packet");
        }
    }

    #[test]
    fn decrypt_ecdh_nistp256() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-nistp256-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp256.pgp")).unwrap();
        let mut keypair =
            tpk.subkeys().next().unwrap()
            .key().clone().mark_parts_secret().into_keypair().unwrap();

        let pkg = pile.descendants().skip(0).next().clone();

        if let Some(Packet::PKESK(ref pkesk)) = pkg {
            let plain = pkesk.decrypt(&mut keypair).unwrap();

            eprintln!("plain: {:?}", plain);
        } else {
            panic!("message is not a PKESK packet");
        }
    }

    #[test]
    fn decrypt_ecdh_nistp384() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-nistp384-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp384.pgp")).unwrap();
        let mut keypair =
            tpk.subkeys().next().unwrap()
            .key().clone().mark_parts_secret().into_keypair().unwrap();

        let pkg = pile.descendants().skip(0).next().clone();

        if let Some(Packet::PKESK(ref pkesk)) = pkg {
            let plain = pkesk.decrypt(&mut keypair).unwrap();

            eprintln!("plain: {:?}", plain);
        } else {
            panic!("message is not a PKESK packet");
        }
    }

    #[test]
    fn decrypt_ecdh_nistp521() {
        let tpk = TPK::from_bytes(
            crate::tests::key("testy-nistp521-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp521.pgp")).unwrap();
        let mut keypair =
            tpk.subkeys().next().unwrap()
            .key().clone().mark_parts_secret().into_keypair().unwrap();

        let pkg = pile.descendants().skip(0).next().clone();

        if let Some(Packet::PKESK(ref pkesk)) = pkg {
            let plain = pkesk.decrypt(&mut keypair).unwrap();

            eprintln!("plain: {:?}", plain);
        } else {
            panic!("message is not a PKESK packet");
        }
    }


    #[test]
    fn decrypt_with_short_cv25519_secret_key() {
        use crate::conversions::Time;
        use super::PKESK3;
        use crate::crypto::SessionKey;
        use crate::crypto::mpis::{self, MPI};
        use crate::PublicKeyAlgorithm;
        use crate::SymmetricAlgorithm;
        use crate::HashAlgorithm;
        use crate::constants::Curve;
        use crate::packet::key;
        use crate::packet::key::Key4;
        use nettle::curve25519;
        use time;

        // 20 byte sec key
        let mut sec = [
            0x0,0x0,
            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x0,0x0
        ];
        let mut pnt = [0x40u8; curve25519::CURVE25519_SIZE + 1];
        curve25519::mul_g(&mut pnt[1..], &sec[..]).unwrap();
        sec.reverse();

        let public_mpis = mpis::PublicKey::ECDH {
            curve: Curve::Cv25519,
            q: MPI::new(&pnt[..]),
            hash: HashAlgorithm::SHA256,
            sym: SymmetricAlgorithm::AES256,
        };
        let private_mpis = mpis::SecretKeyMaterial::ECDH {
            scalar: MPI::new(&sec[..]).into(),
        };
        let mut key: key::UnspecifiedPublic
            = Key4::new(time::now().canonicalize(),
                        PublicKeyAlgorithm::ECDH,
                        public_mpis, None)
                .unwrap().into();
        key.set_secret(Some(private_mpis.into()));
        let sess_key = SessionKey::new(32);
        let pkesk = PKESK3::for_recipient(SymmetricAlgorithm::AES256, &sess_key,
                                          &key).unwrap();
        let mut keypair = key.mark_parts_secret().into_keypair().unwrap();
        pkesk.decrypt(&mut keypair).unwrap();
    }
}
