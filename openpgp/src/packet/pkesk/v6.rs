//! PublicKey-Encrypted Session Key packets version 6.
//!
//! The session key is needed to decrypt the actual ciphertext.  See
//! [Version 6 Public Key Encrypted Session Key Packet Format] for
//! details.
//!
//! [Version 6 Public Key Encrypted Session Key Packet Format]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-key-encryp

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::packet::key;
use crate::packet::Key;
use crate::Fingerprint;
use crate::crypto::Decryptor;
use crate::crypto::mpi::Ciphertext;
use crate::Packet;
use crate::PublicKeyAlgorithm;
use crate::Result;
use crate::SymmetricAlgorithm;
use crate::crypto::SessionKey;
use crate::packet;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Version 6 Public Key Encrypted Session Key Packet Format] for
/// details.
///
/// [Version 6 Public Key Encrypted Session Key Packet Format]: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-key-encryp
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PKESK6 {
    /// CTB header fields.
    pub(crate) common: packet::Common,

    /// Fingerprint of the key this is encrypted to.
    ///
    /// If the value is `None`, the recipient has not been specified
    /// by the sender to decrease metadata leakage.
    recipient: Option<Fingerprint>,

    /// Public key algorithm used to encrypt the session key.
    pk_algo: PublicKeyAlgorithm,

    /// The encrypted session key.
    esk: Ciphertext,
}

assert_send_and_sync!(PKESK6);

impl PKESK6 {
    /// Creates a new PKESK6 packet.
    pub fn new(recipient: Option<Fingerprint>, pk_algo: PublicKeyAlgorithm,
               encrypted_session_key: Ciphertext)
               -> Result<PKESK6>
    {
        Ok(PKESK6 {
            common: Default::default(),
            recipient,
            pk_algo,
            esk: encrypted_session_key,
        })
    }

    /// Creates a new PKESK6 packet for the given recipient.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload.
    pub fn for_recipient<P, R>(session_key: &SessionKey,
                               recipient: &Key<P, R>)
                               -> Result<PKESK6>
    where
        P: key::KeyParts,
        R: key::KeyRole,
    {
        // ElGamal is phased out in RFC 9580.
        #[allow(deprecated)]
        if recipient.pk_algo() == PublicKeyAlgorithm::ElGamalEncrypt
            || recipient.pk_algo() == PublicKeyAlgorithm::ElGamalEncryptSign
        {
            return Err(crate::Error::InvalidOperation(
                "MUST NOT encrypt with version 6 ElGamal keys".into())
                       .into());
        }

        Ok(PKESK6 {
            common: Default::default(),
            recipient: Some(recipient.fingerprint()),
            pk_algo: recipient.pk_algo(),
            esk: packet::PKESK::encrypt_common(
                None, session_key,
                recipient.parts_as_unspecified().role_as_unspecified())?,
        })
    }

    /// Gets the recipient.
    pub fn recipient(&self) -> Option<&Fingerprint> {
        self.recipient.as_ref()
    }

    /// Sets the recipient.
    pub fn set_recipient(&mut self, recipient: Option<Fingerprint>)
                         -> Option<Fingerprint> {
        std::mem::replace(&mut self.recipient, recipient)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm)
                       -> PublicKeyAlgorithm {
        std::mem::replace(&mut self.pk_algo, algo)
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &Ciphertext {
        &self.esk
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Ciphertext) -> Ciphertext {
        std::mem::replace(&mut self.esk, esk)
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
    /// material with certain algorithms (RSA).  See [Avoiding Leaks
    /// from PKCS#1 Errors].
    ///
    /// [Avoiding Leaks from PKCS#1 Errors]: https://www.rfc-editor.org/rfc/rfc9580.html#name-avoiding-leaks-from-pkcs1-e
    pub fn decrypt(&self, decryptor: &mut dyn Decryptor,
                   sym_algo_hint: Option<SymmetricAlgorithm>)
                   -> Option<SessionKey>
    {
        self.decrypt_insecure(decryptor, sym_algo_hint).ok()
    }

    fn decrypt_insecure(&self, decryptor: &mut dyn Decryptor,
                        sym_algo_hint: Option<SymmetricAlgorithm>)
                        -> Result<SessionKey>
    {
        packet::PKESK::decrypt_common(&self.esk, decryptor, sym_algo_hint, false)
            .map(|(_sym_algo, key)| key)
    }
}

impl From<PKESK6> for packet::PKESK {
    fn from(p: PKESK6) -> Self {
        packet::PKESK::V6(p)
    }
}

impl From<PKESK6> for Packet {
    fn from(p: PKESK6) -> Self {
        Packet::PKESK(p.into())
    }
}

#[cfg(test)]
impl Arbitrary for PKESK6 {
    fn arbitrary(g: &mut Gen) -> Self {
        let (ciphertext, pk_algo) = loop {
            let ciphertext = Ciphertext::arbitrary(g);
            if let Some(pk_algo) = ciphertext.pk_algo() {
                break (ciphertext, pk_algo);
            }
        };

        PKESK6::new(bool::arbitrary(g).then(|| Fingerprint::arbitrary_v6(g)),
                    pk_algo, ciphertext).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip(p: PKESK6) -> bool {
            let q = PKESK6::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
