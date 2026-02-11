//! PublicKey-Encrypted Session Key packets.
//!
//! The session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.1 of RFC 9580] for details.
//!
//!   [Section 5.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::KeyHandle;
use crate::packet::key;
use crate::packet::Key;
use crate::packet::Packet;
use crate::crypto::Decryptor;
use crate::crypto::mpi::Ciphertext;
use crate::PublicKeyAlgorithm;
use crate::Result;
use crate::SymmetricAlgorithm;
use crate::crypto::SessionKey;
use crate::packet;

mod v3;
pub use v3::PKESK3;
mod v6;
pub use v6::PKESK6;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is used to decrypt the actual ciphertext, which is
/// typically stored in a [`SEIP`] packet.  See [Section 5.1 of
/// RFC 9580] for details.
///
/// A PKESK packet is not normally instantiated directly.  In most
/// cases, you'll create one as a side effect of encrypting a message
/// using the [streaming serializer], or parsing an encrypted message
/// using the [`PacketParser`].
///
/// [`SEIP`]: crate::packet::SEIP
/// [Section 5.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1
/// [streaming serializer]: crate::serialize::stream
/// [`PacketParser`]: crate::parse::PacketParser
#[non_exhaustive]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum PKESK {
    /// PKESK packet version 3.
    V3(PKESK3),
    /// PKESK packet version 6.
    V6(PKESK6),
}
assert_send_and_sync!(PKESK);

impl PKESK {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            PKESK::V3(_) => 3,
            PKESK::V6(_) => 6,
        }
    }

    /// Gets the recipient.
    pub fn recipient(&self) -> Option<KeyHandle> {
        match self {
            PKESK::V3(p) => p.recipient().map(Into::into),
            PKESK::V6(p) => p.recipient().map(Into::into),
        }
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        match self {
            PKESK::V3(p) => p.pk_algo(),
            PKESK::V6(p) => p.pk_algo(),
        }
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &crate::crypto::mpi::Ciphertext {
        match self {
            PKESK::V3(p) => p.esk(),
            PKESK::V6(p) => p.esk(),
        }
    }

    /// Decrypts the encrypted session key.
    ///
    /// If the symmetric algorithm used to encrypt the message is
    /// known in advance, it should be given as argument.  This allows
    /// us to reduce the side-channel leakage of the decryption
    /// operation for RSA.
    ///
    /// Returns the session key and symmetric algorithm used to
    /// encrypt the following payload.
    ///
    /// Returns `None` on errors.  This prevents leaking information
    /// to an attacker, which could lead to compromise of secret key
    /// material with certain algorithms (RSA).  See [Section 13 of
    /// RFC 9580].
    ///
    ///   [Section 13 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-13
    pub fn decrypt(&self, decryptor: &mut dyn Decryptor,
                   sym_algo_hint: Option<SymmetricAlgorithm>)
        -> Option<(Option<SymmetricAlgorithm>, SessionKey)>
    {
        match self {
            PKESK::V3(p) => p.decrypt(decryptor, sym_algo_hint)
                .map(|(s, k)| (Some(s), k)),
            PKESK::V6(p) => p.decrypt(decryptor, sym_algo_hint)
                .map(|k| (None, k)),
        }
    }
}

impl From<PKESK> for Packet {
    fn from(p: PKESK) -> Self {
        Packet::PKESK(p)
    }
}

/// Returns whether the given `algo` requires checksumming, and
/// whether the cipher octet is prepended to the encrypted session
/// key, or it is prepended to the plain session key and then
/// encrypted.
fn classify_pk_algo(algo: PublicKeyAlgorithm, seipdv1: bool)
                    -> Result<(bool, bool, bool)>
{
    #[allow(deprecated)]
    match algo {
        // Classical encryption: plaintext includes the cipher
        // octet and is checksummed.
        PublicKeyAlgorithm::RSAEncryptSign |
        PublicKeyAlgorithm::RSAEncrypt |
        PublicKeyAlgorithm::ElGamalEncrypt |
        PublicKeyAlgorithm::ElGamalEncryptSign |
        PublicKeyAlgorithm::ECDH =>
            Ok((true, false, seipdv1)),

        // Corner case: for X25519 and X448 we have to prepend
        // the cipher octet to the ciphertext instead of
        // encrypting it.
        PublicKeyAlgorithm::X25519 |
        PublicKeyAlgorithm::X448 =>
            Ok((false, seipdv1, false)),

        a @ PublicKeyAlgorithm::RSASign |
        a @ PublicKeyAlgorithm::DSA |
        a @ PublicKeyAlgorithm::ECDSA |
        a @ PublicKeyAlgorithm::EdDSA |
        a @ PublicKeyAlgorithm::Ed25519 |
        a @ PublicKeyAlgorithm::Ed448 |
        a @ PublicKeyAlgorithm::Private(_) |
        a @ PublicKeyAlgorithm::Unknown(_) =>
            Err(Error::UnsupportedPublicKeyAlgorithm(a).into()),
    }
}


impl packet::PKESK {
    fn encrypt_common(algo: Option<SymmetricAlgorithm>,
                      session_key: &SessionKey,
                      recipient: &Key<key::UnspecifiedParts,
                                      key::UnspecifiedRole>)
                      -> Result<Ciphertext>
    {
        let (checksummed, unencrypted_cipher_octet, encrypted_cipher_octet) =
            classify_pk_algo(recipient.pk_algo(), algo.is_some())?;

        // We may need to prefix the cipher specifier to the session
        // key, and we may add a two-octet checksum.
        let mut psk = Vec::with_capacity(
            encrypted_cipher_octet.then(|| 1).unwrap_or(0)
                + session_key.len()
                + checksummed.then(|| 2).unwrap_or(0));
        if let Some(algo) = algo {
            if encrypted_cipher_octet {
                psk.push(algo.into());
            }
        }
        psk.extend_from_slice(session_key);

        if checksummed {
            // Compute the sum modulo 65536, i.e. as u16.
            let checksum = session_key
                .iter()
                .cloned()
                .map(u16::from)
                .fold(0u16, u16::wrapping_add);

            psk.extend_from_slice(&checksum.to_be_bytes());
        }

        // Make sure it is cleaned up when dropped.
        let psk: SessionKey = psk.into();
        let mut esk = recipient.encrypt(&psk)?;

        if let Some(algo) = algo {
            if unencrypted_cipher_octet {
                match esk {
                    Ciphertext::X25519 { ref mut key, .. } |
                    Ciphertext::X448 { ref mut key, .. } => {
                        let mut new_key = Vec::with_capacity(1 + key.len());
                        new_key.push(algo.into());
                        new_key.extend_from_slice(key);
                        *key = new_key.into();
                    },
                    _ => unreachable!("We only prepend the cipher octet \
                                       for X25519 and X448"),
                };
            }
        }

        Ok(esk)
    }

    fn decrypt_common(ciphertext: &Ciphertext,
                      decryptor: &mut dyn Decryptor,
                      sym_algo_hint: Option<SymmetricAlgorithm>,
                      seipdv1: bool)
                      -> Result<(Option<SymmetricAlgorithm>, SessionKey)>
    {
        let (checksummed, unencrypted_cipher_octet, encrypted_cipher_octet) =
            classify_pk_algo(decryptor.public().pk_algo(), seipdv1)?;

        //dbg!((checksummed, unencrypted_cipher_octet, encrypted_cipher_octet));

        let mut sym_algo: Option<SymmetricAlgorithm> = None;
        let modified_ciphertext;
        let esk;
        if unencrypted_cipher_octet {
            match ciphertext {
                Ciphertext::X25519 { e, key, } => {
                    sym_algo =
                        Some((*key.get(0).ok_or_else(
                            || Error::MalformedPacket("Short ESK".into()))?)
                             .into());
                    modified_ciphertext = Ciphertext::X25519 {
                        e: e.clone(),
                        key: key[1..].into(),
                    };
                    esk = &modified_ciphertext;
                },
                Ciphertext::X448 { e, key, } => {
                    sym_algo =
                        Some((*key.get(0).ok_or_else(
                            || Error::MalformedPacket("Short ESK".into()))?)
                             .into());
                    modified_ciphertext = Ciphertext::X448 {
                        e: e.clone(),
                        key: key[1..].into(),
                    };
                    esk = &modified_ciphertext;
                },

                _ => {
                    // We only prepend the cipher octet for X25519 and
                    // X448, yet we're trying to decrypt a ciphertext
                    // that uses a different algorithm, clearly
                    // something has gone wrong and will fail when we
                    // try to decrypt it downstream.
                    esk = ciphertext;
                },
            }
        } else {
            esk = ciphertext;
        }

        let plaintext_len = if let Some(s) = sym_algo_hint {
            Some(encrypted_cipher_octet.then(|| 1).unwrap_or(0)
                 + s.key_size()?
                 + checksummed.then(|| 2).unwrap_or(0))
        } else {
            None
        };
        let plain = decryptor.decrypt(esk, plaintext_len)?;
        let key_rgn = encrypted_cipher_octet.then(|| 1).unwrap_or(0)
            ..plain.len().saturating_sub(checksummed.then(|| 2).unwrap_or(0));
        if encrypted_cipher_octet {
            sym_algo = Some(plain[0].into());
        }
        let sym_algo = sym_algo.or(sym_algo_hint);

        if let Some(sym_algo) = sym_algo {
            if key_rgn.len() != sym_algo.key_size()? {
                return Err(Error::MalformedPacket(
                    format!("session key has the wrong size (got: {}, expected: {})",
                            key_rgn.len(), sym_algo.key_size()?)).into())
            }
        }

        let mut key: SessionKey = vec![0u8; key_rgn.len()].into();
        key.copy_from_slice(&plain[key_rgn]);

        if checksummed {
            let our_checksum
                = key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
            let their_checksum = (plain[plain.len() - 2] as usize) << 8
                | (plain[plain.len() - 1] as usize);

            if their_checksum != our_checksum {
                return Err(Error::MalformedPacket(
                    "key checksum wrong".to_string()).into());
            }
        }
        Ok((sym_algo, key))
    }
}

#[cfg(test)]
impl Arbitrary for super::PKESK {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            PKESK3::arbitrary(g).into()
        } else {
            PKESK6::arbitrary(g).into()
        }
    }
}
