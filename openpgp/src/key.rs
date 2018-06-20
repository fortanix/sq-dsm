use std::fmt;

use mpis::MPIs;
use Tag;
use Key;
use Packet;
use PublicKeyAlgorithm;
use SymmetricAlgorithm;
use s2k::S2K;
use Result;

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &self.fingerprint())
            .field("version", &self.version)
            .field("creation_time", &self.creation_time)
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .field("secret", &self.secret)
            .finish()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl Key {
    /// Returns a new `Key` packet.  This can be used to hold either a
    /// public key, a public key, a private key, or a private subkey.
    pub fn new() -> Self {
        Key {
            common: Default::default(),
            version: 4,
            creation_time: 0,
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            mpis: MPIs::empty(),
            secret: None,
        }
    }

    /// Sets the literal packet's date field using a Unix timestamp.
    ///
    /// A Unix timestamp is the number of seconds since the Unix
    /// epoch.
    pub fn creation_time(mut self, timestamp: u32) -> Self {
        self.creation_time = timestamp;
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, pk_algo: PublicKeyAlgorithm) -> Self {
        self.pk_algo = pk_algo;
        self
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn to_packet(self, tag: Tag) -> Packet {
        match tag {
            Tag::PublicKey => Packet::PublicKey(self),
            Tag::PublicSubkey => Packet::PublicSubkey(self),
            Tag::SecretKey => Packet::SecretKey(self),
            Tag::SecretSubkey => Packet::SecretSubkey(self),
            _ => panic!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag),
        }
    }
}

/// Holds the secret potion of a OpenPGP secret key or secret subkey packet.
///
/// This type allows postponing the decryption of the secret key until we need to use it.
#[derive(PartialEq, Clone, Debug)]
pub enum SecretKey {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted {
        /// MPIs of the secret key. Must be a *SecretKey enum variant.
        mpis: MPIs
    },
    /// The secret key is encrypted with a password.
    Encrypted {
        /// Key derivation mechanism to use.
        s2k: S2K,
        /// Symmetric algorithm used for encryption the secret key.
        algorithm: SymmetricAlgorithm,
        /// Encrypted MPIs prefixed with the IV.
        ciphertext: Box<[u8]>,
    },
}

impl SecretKey {
    /// Decrypts this secret key using `password`. The SecretKey type
    /// does not know what kind of key it is, so `pk_algo` is needed
    /// to parse the correct number of MPIs.
    pub fn decrypt(&mut self, pk_algo: PublicKeyAlgorithm, password: &[u8])
                   -> Result<()> {
        use std::io::{Cursor, Read};
        use symmetric::Decryptor;

        let new = match &*self {
            &SecretKey::Unencrypted { .. } => None,
            &SecretKey::Encrypted { ref s2k, algorithm, ref ciphertext } => {
                let key = s2k.derive_key(password, algorithm.key_size()?)?
                    .into_boxed_slice();
                let mut cur = Cursor::new(ciphertext);
                let mut dec = Decryptor::new(algorithm, &key, cur)?;
                let mut trash = vec![0u8; algorithm.block_size()?];

                dec.read_exact(&mut trash)?;
                let mpis = MPIs::parse_chksumd_secret_key(pk_algo, &mut dec)?;

                Some(SecretKey::Unencrypted{ mpis: mpis })
            }
        };

        if let Some(new) = new {
            *self = new;
        }

        Ok(())
    }

    /// Returns true if this secret key is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            &SecretKey::Encrypted { .. } => true,
            &SecretKey::Unencrypted { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use mpis::MPIs;
    use TPK;
    use SecretKey;
    use std::path::PathBuf;

    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "keys", artifact]
            .iter().collect()
    }

    #[test]
    fn encrypted_rsa_key() {
        let mut tpk = TPK::from_file(
            path_to("testy-new-encrypted-with-123.pgp")).unwrap();
        let pair = tpk.primary_mut();
        let secret = pair.secret.as_mut().unwrap();

        assert!(secret.is_encrypted());
        secret.decrypt(pair.pk_algo, &b"123"[..]).unwrap();
        assert!(!secret.is_encrypted());

        match secret {
            &mut SecretKey::Unencrypted { mpis: MPIs::RSASecretKey { .. } } =>
                {}
            _ => { unreachable!() }
        }
    }
}
