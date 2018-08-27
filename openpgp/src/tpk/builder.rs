use time;
use subpacket::KeyFlags;
use Key;
use tpk::{
    UserIDBinding,
    SubkeyBinding,
};
use Result;
use UserID;
use SymmetricAlgorithm;
use HashAlgorithm;
use Signature;
use TPK;
use PublicKeyAlgorithm;
use Error;

/// Groups symmetric and asymmetric algorithms
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum CipherSuite {
    /// EdDSA and ECDH over Curve25519 with SHA512 and AES256
    Cv25519,
    /// 3072 bit RSA with SHA512 and AES256
    RSA3k,
}

#[derive(Clone, Debug)]
pub struct KeyBlueprint {
    flags: KeyFlags,
}

/// Simplifies generation of Keys.
///
/// Builder to generate complex TPK hierarchies with multiple user IDs.
#[derive(Clone, Debug)]
pub struct TPKBuilder {
    ciphersuite: CipherSuite,
    primary: KeyBlueprint,
    subkeys: Vec<KeyBlueprint>,
    userids: Vec<String>,
}

impl Default for TPKBuilder {
    fn default() -> Self {
        TPKBuilder{
            ciphersuite: CipherSuite::RSA3k,
            primary: KeyBlueprint{
                flags: KeyFlags::default().set_certify(true),
            },
            subkeys: vec![],
            userids: vec!["".into()],
        }
    }
}

impl TPKBuilder {
    /// Generates a key compliant to [Autocrypt Level 1](https://autocrypt.org/level1.html).
    pub fn autocrypt() -> Self {
        TPKBuilder{
            ciphersuite: CipherSuite::RSA3k,
            primary: KeyBlueprint{
                flags: KeyFlags::default()
                    .set_certify(true)
                    .set_sign(true)
            },
            subkeys: vec![
                KeyBlueprint{
                    flags: KeyFlags::default()
                        .set_encrypt_for_transport(true)
                        .set_encrypt_at_rest(true)
                }
            ],
            userids: vec!["".into()],
        }
    }

    /// Sets the encryption and signature algorithms for primary and all subkeys.
    pub fn set_cipher_suite(mut self, cs: CipherSuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    /// Adds a new user ID. The first user ID added replaces the default ID that is just the empty
    /// string.
    pub fn add_userid<'a, U>(mut self, uid: U) -> Self where U: Into<Option<&'a str>> {
        if self.userids.len() == 1 && self.userids[0].len() == 0 {
            self.userids[0] = uid.into().unwrap_or("").to_string();
        } else {
            self.userids.push(uid.into().unwrap_or("").to_string());
        }
        self
    }

    /// Adds a signing capable subkey.
    pub fn add_signing_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_sign(true))
    }

    /// Adds an encryption capable subkey.
    pub fn add_encryption_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default()
                        .set_encrypt_for_transport(true)
                        .set_encrypt_at_rest(true))
    }

    /// Adds an certification capable subkey.
    pub fn add_certification_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_certify(true))
    }

    /// Adds a custom subkey
    pub fn add_subkey(mut self, flags: KeyFlags) -> Self {
        self.subkeys.push(KeyBlueprint{
            flags: flags
        });
        self
    }

    /// Sets the capabilities of the primary key. The function automatically makes the primary key
    /// certification capable if subkeys are added.
    pub fn primary_keyflags(mut self, flags: KeyFlags) -> Self {
        self.primary.flags = flags;
        self
    }

    /// Generates the actual TPK.
    pub fn generate(mut self) -> Result<TPK> {
        use packet::Common;

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certify(true);
        }

        let first_uid = UserID{
            common: Common::default(),
            value: self.userids.remove(0).as_bytes().into(),
        };
        let (primary, uid_sig) = Self::primary_key(self.primary, first_uid, self.ciphersuite)?;
        let mut userids = Vec::with_capacity(self.userids.len() + 1);
        let mut subkeys = Vec::with_capacity(self.subkeys.len());

        for uid in self.userids {
            let uid = UserID{
                common: Common::default(),
                value: uid.as_bytes().into(),
            };
            userids.push(Self::userid(uid, &primary)?);
        }
        userids.push(uid_sig);

        for subkey in self.subkeys {
            subkeys.push(Self::subkey(subkey, &primary, self.ciphersuite)?);
        }

        Ok(TPK{
            primary: primary,
            primary_selfsigs: vec![],
            primary_certifications: vec![],
            userids: userids,
            user_attributes: vec![],
            subkeys: subkeys,
            unknowns: vec![],
            bad: vec![],
        })
    }

    fn primary_key(blueprint: KeyBlueprint, uid: UserID, cs: CipherSuite) -> Result<(Key, UserIDBinding)> {
        use SignatureType;
        use SecretKey;

        let key = Self::fresh_key(cs)?;
        let mut sig = Signature::new(SignatureType::PositiveCertificate);

        sig.set_key_flags(&blueprint.flags)?;
        sig.set_signature_creation_time(time::now())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(key.fingerprint())?;
        sig.set_issuer(key.fingerprint().to_keyid())?;
        sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        key.hash(&mut hash);
        uid.hash(&mut hash);

        match key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(&key, mpis, HashAlgorithm::SHA512, hash)?;
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation("Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation("No secret key".into()).into());
            }
        }

        let bind = UserIDBinding{
            userid: uid,
            selfsigs: vec![sig],
            certifications: vec![],
        };

        Ok((key, bind))
    }

    fn subkey(blueprint: KeyBlueprint, primary_key: &Key, cs: CipherSuite) -> Result<SubkeyBinding> {
        use SignatureType;
        use SecretKey;

        let subkey = Self::fresh_key(cs)?;
        let mut sig = Signature::new(SignatureType::SubkeyBinding);

        sig.set_key_flags(&blueprint.flags)?;
        sig.set_signature_creation_time(time::now())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(primary_key.fingerprint())?;
        sig.set_issuer(primary_key.fingerprint().to_keyid())?;

        if blueprint.flags.can_encrypt_for_transport()
        || blueprint.flags.can_encrypt_at_rest() {
            sig.set_preferred_symmetric_algorithms(vec![SymmetricAlgorithm::AES256])?;
        }

        if blueprint.flags.can_certify()
        || blueprint.flags.can_sign() {
            sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;
        }

        let mut hash = HashAlgorithm::SHA512.context()?;

        primary_key.hash(&mut hash);
        subkey.hash(&mut hash);

        match primary_key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(primary_key, mpis, HashAlgorithm::SHA512, hash)?;
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation("Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation("No secret key".into()).into());
            }
        }

        Ok(SubkeyBinding{
            subkey: subkey,
            selfsigs: vec![sig],
            certifications: vec![],
        })
    }

    fn userid(uid: UserID, key: &Key) -> Result<UserIDBinding> {
        use SignatureType;
        use SecretKey;

        let mut sig = Signature::new(SignatureType::PositiveCertificate);

        sig.set_signature_creation_time(time::now())?;
        sig.set_issuer_fingerprint(key.fingerprint())?;
        sig.set_issuer(key.fingerprint().to_keyid())?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        key.hash(&mut hash);
        uid.hash(&mut hash);

        match key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(key, mpis, HashAlgorithm::SHA512, hash)?;
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation("Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation("No secret key".into()).into());
            }
        }

        let bind = UserIDBinding{
            userid: uid,
            selfsigs: vec![sig],
            certifications: vec![],
        };

        Ok(bind)
    }

    fn fresh_key(cs: CipherSuite) -> Result<Key> {
        match cs {
            CipherSuite::RSA3k => Key::new(PublicKeyAlgorithm::RSAEncryptSign),
            CipherSuite::Cv25519 => Key::new(PublicKeyAlgorithm::EdDSA),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subpacket::{SubpacketTag, Subpacket, SubpacketValue};

    #[test]
    fn all_opts() {
        let tpk = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_signing_subkey()
            .add_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(&u.userid.value[..]).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "test1@example.com",
                      "test2@example.com",
                   ][..]);
        assert_eq!(tpk.subkeys().len(), 3);
    }

    #[test]
    fn setter() {
        let tpk1 = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_cipher_suite(CipherSuite::RSA3k)
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::EdDSA);

        let tpk2 = TPKBuilder::default()
            .add_userid("test2@example.com")
            .add_encryption_subkey()
            .generate().unwrap();
        assert_eq!(tpk2.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk2.subkeys().next().unwrap().subkey().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn defaults() {
        let tpk1 = TPKBuilder::default()
            .add_userid("test2@example.com")
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert!(tpk1.subkeys().next().is_none());
    }

    #[test]
    fn autocrypt() {
        let tpk1 = TPKBuilder::autocrypt()
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk1.subkeys().next().unwrap().subkey().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn always_certify() {
        let tpk1 = TPKBuilder::default()
            .primary_keyflags(KeyFlags::default())
            .add_encryption_subkey()
            .generate().unwrap();
        let sig_pkts = &tpk1.userids().next().unwrap().selfsigs[0].hashed_area;

        match sig_pkts.lookup(SubpacketTag::KeyFlags) {
            Some(Subpacket{ value: SubpacketValue::KeyFlags(ref ks),.. }) => {
                assert!(ks.can_certify());
            }
            _ => {}
        }

        assert_eq!(tpk1.subkeys().len(), 1);
    }

    #[test]
    fn gen_wired_subkeys() {
        let tpk1 = TPKBuilder::default()
            .primary_keyflags(KeyFlags::default())
            .add_subkey(KeyFlags::default().set_encrypt_for_transport(true).set_certify(true))
            .generate().unwrap();
        let sig_pkts = &tpk1.subkeys().next().unwrap().selfsigs[0].hashed_area;

        match sig_pkts.lookup(SubpacketTag::KeyFlags) {
            Some(Subpacket{ value: SubpacketValue::KeyFlags(ref ks),.. }) => {
                assert!(ks.can_certify());
                assert!(ks.can_encrypt_for_transport());
            }
            _ => {}
        }

        assert_eq!(tpk1.subkeys().len(), 1);
    }
}
