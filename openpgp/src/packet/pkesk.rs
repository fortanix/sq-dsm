use Error;
use packet::Key;
use KeyID;
use mpis::{self, MPI, Ciphertext};
use Packet;
use PublicKeyAlgorithm;
use Result;
use SymmetricAlgorithm;
use SessionKey;
use crypto::ecdh;
use nettle::{rsa, Yarrow};
use packet;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Section 5.1 of RFC 4880] for details.
///
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct PKESK {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Packet version. Must be 3.
    pub(crate) version: u8,
    /// Key ID of the key this is encrypted to.
    pub(crate) recipient: KeyID,
    /// Public key algorithm used to encrypt the session key.
    pub(crate) pk_algo: PublicKeyAlgorithm,
    /// The encrypted session key.
    pub(crate) esk: Ciphertext,
}

impl PKESK {
    /// Creates a new PKESK packet.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload.
    pub fn new(algo: SymmetricAlgorithm,
               session_key: &SessionKey, recipient: &Key)
               -> Result<PKESK> {
        use PublicKeyAlgorithm::*;
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

        #[allow(deprecated)]
        let esk = match recipient.pk_algo {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match recipient.mpis() {
                    &mpis::PublicKey::RSA { ref e, ref n } => {
                        // The ciphertext has the length of the modulus.
                        let mut esk = vec![0u8; n.value.len()];

                        let pk = rsa::PublicKey::new(&n.value, &e.value)?;
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

            ECDH => {
                ecdh::wrap_session_key(recipient, &psk)?
            }
            algo =>
                return Err(Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        };

        Ok(PKESK{
            common: Default::default(),
            version: 3,
            recipient: recipient.keyid(),
            pk_algo: recipient.pk_algo,
            esk: esk,
        })
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the recipient.
    pub fn recipient(&self) -> &KeyID {
        &self.recipient
    }

    /// Sets the recipient.
    pub fn set_recipient(&mut self, recipient: KeyID) {
        self.recipient = recipient;
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm) {
        self.pk_algo = algo;
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &Ciphertext {
        &self.esk
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Ciphertext) {
        self.esk = esk;
    }

    /// Decrypts the ESK and returns the session key and symmetric algorithm
    /// used to encrypt the following payload.
    pub fn decrypt(&self, recipient: &Key, recipient_sec: &mpis::SecretKey)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        use PublicKeyAlgorithm::*;
        use mpis::PublicKey;
        use nettle::rsa;

        let plain: SessionKey = match
            (self.pk_algo, recipient.mpis(), recipient_sec, &self.esk)
        {
            (RSAEncryptSign,
             &PublicKey::RSA{ ref e, ref n },
             &mpis::SecretKey::RSA{ ref p, ref q, ref d, .. },
             &mpis::Ciphertext::RSA{ ref c }) => {
                let public = rsa::PublicKey::new(&n.value, &e.value)?;
                let secret = rsa::PrivateKey::new(&d.value, &p.value,
                                                  &q.value, Option::None)?;
                let mut rand = Yarrow::default();
                rsa::decrypt_pkcs1(&public, &secret, &mut rand, &c.value)?
            }

            (ElgamalEncrypt,
             &PublicKey::Elgamal{ .. },
             &mpis::SecretKey::Elgamal{ .. },
             &mpis::Ciphertext::Elgamal{ .. }) =>
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(self.pk_algo).into()),

            (ECDH,
             PublicKey::ECDH{ .. },
             mpis::SecretKey::ECDH { .. },
             mpis::Ciphertext::ECDH { .. }) =>
                ecdh::unwrap_session_key(recipient, recipient_sec, &self.esk)?,

            (algo, public, secret, cipher) =>
                return Err(Error::MalformedPacket(format!(
                    "unsupported combination of algorithm {:?}, key pair {:?}/{:?} and ciphertext {:?}",
                    algo, public, secret, cipher)).into()),
        }.into();

        let key_rgn = 1..(plain.len() - 2);
        let symm_algo: SymmetricAlgorithm = plain[0].into();
        let mut key = vec![0u8; symm_algo.key_size()?];

        if key_rgn.len() != symm_algo.key_size()? {
            return Err(Error::MalformedPacket(
                format!("session key has the wrong size")).into());
        }

        key.copy_from_slice(&plain[key_rgn]);

        let our_checksum
            = key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
        let their_checksum = (plain[plain.len() - 2] as usize) << 8
            | (plain[plain.len() - 1] as usize);

        if their_checksum == our_checksum {
            Ok((symm_algo, key.into()))
        } else {
            Err(Error::MalformedPacket(format!("key checksum wrong"))
                .into())
        }
    }

    /// Convert the `PKESK` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::PKESK(self)
    }
}

impl From<PKESK> for Packet {
    fn from(s: PKESK) -> Self {
        s.to_packet()
    }
}

#[cfg(test)]
mod tests {
    use TPK;
    use PacketPile;
    use SecretKey;
    use Packet;
    use std::path::PathBuf;

    fn path_to_key(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "keys", artifact]
            .iter().collect()
    }

    fn path_to_msg(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
            .iter().collect()
    }

    #[test]
    fn decrypt_rsa() {
        let tpk = TPK::from_file(
            path_to_key("testy-private.pgp")).unwrap();
        let pile = PacketPile::from_file(
            path_to_msg("encrypted-to-testy.gpg")).unwrap();
        let pair = tpk.subkeys().next().unwrap().subkey();

        if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = pair.secret {
            let pkg = pile.descendants().skip(0).next().clone();

            if let Some(Packet::PKESK(ref pkesk)) = pkg {
                let plain = pkesk.decrypt(&pair, sec).unwrap();

                eprintln!("plain: {:?}", plain);
            } else {
                panic!("message is not a PKESK packet");
            }
        } else {
            panic!("secret key is encrypted/missing");
        }
    }

    #[test]
    fn decrypt_ecdh_cv25519() {
        let tpk = TPK::from_file(
            path_to_key("testy-new-private.pgp")).unwrap();
        let pile = PacketPile::from_file(
            path_to_msg("encrypted-to-testy-new.pgp")).unwrap();
        let pair = tpk.subkeys().next().unwrap().subkey();

        if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = pair.secret {
            let pkg = pile.descendants().skip(0).next().clone();

            if let Some(Packet::PKESK(ref pkesk)) = pkg {
                let plain = pkesk.decrypt(&pair, sec).unwrap();

                eprintln!("plain: {:?}", plain);
            } else {
                panic!("message is not a PKESK packet");
            }
        } else {
            panic!("secret key is encrypted/missing");
        }
    }
}
