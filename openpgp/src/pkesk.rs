use Error;
use Key;
use KeyID;
use MPIs;
use PublicKeyAlgorithm;
use Result;
use SymmetricAlgorithm;
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
        let mut rng = Yarrow::default();
        let key_mpis = recipient.mpis.values()?;

        // For the encryption operation, we need a buffer of a
        // specific size.
        let buffer_size = match recipient.pk_algo {
            PublicKeyAlgorithm::RsaEncryptSign |
            PublicKeyAlgorithm::RsaEncrypt =>
                // For RSA, use the size of the modulus.
                key_mpis[0].len(),
            algo =>
                return Err(Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        };

        // We need to prefix the cipher specifier to the session key,
        // and a checksum.
        let mut psk = Vec::with_capacity(buffer_size);
        let mut esk = vec![0u8; buffer_size];
        psk.push(algo.into());
        psk.extend_from_slice(session_key);

        // Compute the sum modulo 65536.
        let mut checksum: u32 = 0;
        for b in session_key {
            checksum = (checksum + *b as u32) % ::std::u16::MAX as u32;
        }
        psk.push((checksum >> 8) as u8);
        psk.push((checksum >> 0) as u8);

        match recipient.pk_algo {
            PublicKeyAlgorithm::RsaEncryptSign |
            PublicKeyAlgorithm::RsaEncrypt => {
                // Extract the public recipient.
                if key_mpis.len() != 2 {
                    return Err(
                        Error::MalformedPacket(
                            format!(
                                "Key: Expected 2 MPIs for an RSA key, got {}",
                                key_mpis.len())).into());
                }

                let pk = rsa::PublicKey::new(key_mpis[0], key_mpis[1])?;
                rsa::encrypt_pkcs1(&pk, &mut rng,
                                   &psk, &mut esk)?;

            },
            algo =>
                return Err(Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        }

        Ok(PKESK{
            common: Default::default(),
            version: 3,
            recipient: recipient.keyid(),
            pk_algo: recipient.pk_algo,
            esk: MPIs::new(&[&esk]),
        })
    }
}
