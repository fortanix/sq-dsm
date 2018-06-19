use Error;
use Key;
use KeyID;
use mpis::{MPI, MPIs};
use PublicKeyAlgorithm;
use Result;
use SymmetricAlgorithm;
use ecdh;
use nettle::{rsa, Yarrow};
use packet;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Section 5.1 of RFC 4880] for details.
///
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
#[derive(PartialEq, Clone, Debug)]
pub struct PKESK {
    pub common: packet::Common,
    pub version: u8,
    pub recipient: KeyID,
    pub pk_algo: PublicKeyAlgorithm,
    // The encrypted session key.
    pub esk: MPIs,
}

impl PKESK {
    /// Creates a new PKESK packet.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload.
    pub fn new(algo: SymmetricAlgorithm,
               session_key: &[u8], recipient: &Key)
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

        let esk = match recipient.pk_algo {
            RSAEncryptSign | RSAEncrypt => {
                // Extract the public recipient.
                match &recipient.mpis {
                    &MPIs::RSAPublicKey{ ref e, ref n } => {
                        // The ciphertext has the length of the modulus.
                        let mut esk = vec![0u8; n.value.len()];

                        let pk = rsa::PublicKey::new(&n.value, &e.value)?;
                        rsa::encrypt_pkcs1(&pk, &mut rng, &psk, &mut esk)?;
                        MPIs::RSACiphertext{c: MPI::new(&esk)}
                    }

                    _ => {
                        return Err(
                            Error::MalformedPacket(
                                format!(
                                    "Key: Expected RSA public key, got {:?}",
                                    recipient.mpis)).into());
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

    /// Decrypts the ESK and returns the session key and symmetric algorithm
    /// used to encrypt the following payload.
    pub fn decrypt(&self, recipient: &Key, recipient_sec: &MPIs)
        -> Result<(SymmetricAlgorithm,Box<[u8]>)>
    {
        use PublicKeyAlgorithm::*;
        use mpis::MPIs::*;
        use nettle::rsa;

        let plain = match
            (self.pk_algo, &recipient.mpis, recipient_sec, &self.esk)
        {
            (RSAEncryptSign, &RSAPublicKey{ ref e, ref n },
             &RSASecretKey{ ref p, ref q, ref d,.. },
             &RSACiphertext{ ref c }) => {
                let public = rsa::PublicKey::new(&n.value, &e.value)?;
                let secret = rsa::PrivateKey::new(&d.value, &p.value,
                                                  &q.value, Option::None)?;
                let mut rand = Yarrow::default();
                rsa::decrypt_pkcs1(&public, &secret, &mut rand, &c.value)?
            }

            (ElgamalEncrypt, &ElgamalPublicKey{ .. },
             &ElgamalSecretKey{ .. },
             &ElgamalCiphertext{ .. }) =>
                return Err(
                    Error::UnknownPublicKeyAlgorithm(self.pk_algo).into()),

            (ECDH, ECDHPublicKey{ .. }, ECDHSecretKey{ .. },
             ECDHCiphertext{ .. }) =>
                ecdh::unwrap_session_key(recipient, recipient_sec, &self.esk)?,

            (algo, public, secret, cipher) =>
                return Err(Error::MalformedPacket(format!(
                    "unsupported combination of algorithm {:?}, key pair {:?}/{:?} and ciphertext {:?}",
                    algo, public, secret, cipher)).into()),
        };

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
            Ok((symm_algo, key.into_boxed_slice()))
        } else {
            Err(Error::MalformedPacket(format!("key checksum wrong"))
                .into())
        }
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
