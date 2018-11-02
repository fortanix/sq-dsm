use time;
use packet::signature::subpacket::{Features, KeyFlags};
use packet::Key;
use tpk::{
    UserIDBinding,
    SubkeyBinding,
};
use Result;
use packet::UserID;
use SymmetricAlgorithm;
use HashAlgorithm;
use packet::{signature, Signature};
use TPK;
use PublicKeyAlgorithm;
use Error;
use conversions::Time;
use constants::{
    ReasonForRevocation,
    SignatureType,
};
use autocrypt::Autocrypt;

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
            userids: vec![],
        }
    }
}

impl TPKBuilder {
    /// Generates a key compliant to
    /// [Autocrypt](https://autocrypt.org/). If no version is given the latest
    /// one is used.
    pub fn autocrypt<V>(_: V)
        -> Self where V: Into<Option<Autocrypt>>
    {
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

    /// Adds a new user ID. The first user ID added will be the primary user ID.
    pub fn add_userid(mut self, uid: &str) -> Self {
        self.userids.push(uid.to_string());
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

    /// Sets the capabilities of the primary key. The function automatically
    /// makes the primary key certification capable if subkeys are added.
    pub fn primary_keyflags(mut self, flags: KeyFlags) -> Self {
        self.primary.flags = flags;
        self
    }

    /// Generates the actual TPK.
    pub fn generate(mut self) -> Result<(TPK, Signature)> {
        use packet::Common;

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certify(true);
        }

        // select the first UserID as primary, if present
        let maybe_first_uid = self.userids.first().cloned().map(|uid| {
            UserID{
                common: Common::default(),
                value: uid.as_bytes().into(),
            }
        });
        // Generate & and self-sign primary key.
        let (primary, sig) = Self::primary_key(
            self.primary, maybe_first_uid.clone(), self.ciphersuite)?;
        // Sort primary keys self-sig into the right vec.
        let (mut userids, selfsigs) = match maybe_first_uid {
            Some(uid) => {
                // maybe to strict?
                assert_eq!(sig.sigtype(), SignatureType::PositiveCertificate);

                let bind = UserIDBinding{
                    userid: uid,
                    selfsigs: vec![sig],
                    certifications: vec![],
                    self_revocations: vec![],
                    other_revocations: vec![],
                };

                (vec![bind], vec![])
            }
            None => {
                assert_eq!(sig.sigtype(), SignatureType::DirectKey);
                (vec![], vec![sig])
            }
        };
        let mut subkeys = Vec::with_capacity(self.subkeys.len());

        // sign UserIDs. First UID was used as primary keys self-sig
        if !self.userids.is_empty() {
            for uid in self.userids[1..].iter() {
                let uid = UserID{
                    common: Common::default(),
                    value: uid.as_bytes().into(),
                };
                userids.push(Self::userid(uid, &primary)?);
            }
        }

        // sign subkeys
        for subkey in self.subkeys {
            subkeys.push(Self::subkey(subkey, &primary, self.ciphersuite)?);
        }

        let tpk = TPK {
            primary: primary,
            primary_selfsigs: selfsigs,
            primary_certifications: vec![],
            primary_self_revocations: vec![],
            primary_other_revocations: vec![],
            userids: userids,
            user_attributes: vec![],
            subkeys: subkeys,
            unknowns: vec![],
            bad: vec![],
        };

        let revocation = tpk.revoke(ReasonForRevocation::Unspecified,
                                    b"Unspecified")?;

        Ok((tpk, revocation))
    }

    fn primary_key(blueprint: KeyBlueprint, uid: Option<UserID>, cs: CipherSuite)
        -> Result<(Key, Signature)>
    {
        use SignatureType;
        use SecretKey;

        let key = Self::fresh_key(cs)?;
        let mut sig = if uid.is_some() {
            signature::Builder::new(SignatureType::PositiveCertificate)
        } else {
            signature::Builder::new(SignatureType::DirectKey)
        };

        sig.set_features(&Features::sequoia())?;
        sig.set_key_flags(&blueprint.flags)?;
        sig.set_signature_creation_time(time::now().canonicalize())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(key.fingerprint())?;
        sig.set_issuer(key.fingerprint().to_keyid())?;
        sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        key.hash(&mut hash);

        match uid {
            Some(uid) => uid.hash(&mut hash),
            None => {}
        }

        let sig = match key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(&key, mpis, HashAlgorithm::SHA512, hash)?
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation(
                        "Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation(
                        "No secret key".into()).into());
            }
        };

        Ok((key, sig))
    }

    fn subkey(blueprint: KeyBlueprint, primary_key: &Key, cs: CipherSuite)
        -> Result<SubkeyBinding>
    {
        use SignatureType;
        use SecretKey;

        let subkey = Self::fresh_key(cs)?;
        let mut sig = signature::Builder::new(SignatureType::SubkeyBinding);

        sig.set_key_flags(&blueprint.flags)?;
        sig.set_signature_creation_time(time::now().canonicalize())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(primary_key.fingerprint())?;
        sig.set_issuer(primary_key.fingerprint().to_keyid())?;

        if blueprint.flags.can_encrypt_for_transport()
        || blueprint.flags.can_encrypt_at_rest() {
            sig.set_preferred_symmetric_algorithms(
                vec![SymmetricAlgorithm::AES256])?;
        }

        if blueprint.flags.can_certify()
        || blueprint.flags.can_sign() {
            sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;
        }

        let mut hash = HashAlgorithm::SHA512.context()?;

        primary_key.hash(&mut hash);
        subkey.hash(&mut hash);

        let sig = match primary_key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(primary_key, mpis, HashAlgorithm::SHA512, hash)?
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation(
                        "Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation(
                        "No secret key".into()).into());
            }
        };

        Ok(SubkeyBinding{
            subkey: subkey,
            selfsigs: vec![sig],
            certifications: vec![],
            self_revocations: vec![],
            other_revocations: vec![],
        })
    }

    fn userid(uid: UserID, key: &Key) -> Result<UserIDBinding> {
        use SignatureType;
        use SecretKey;

        let mut sig = signature::Builder::new(SignatureType::PositiveCertificate);

        sig.set_signature_creation_time(time::now().canonicalize())?;
        sig.set_issuer_fingerprint(key.fingerprint())?;
        sig.set_issuer(key.fingerprint().to_keyid())?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        key.hash(&mut hash);
        uid.hash(&mut hash);

        let sig = match key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(key, mpis, HashAlgorithm::SHA512, hash)?
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation(
                        "Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation(
                        "No secret key".into()).into());
            }
        };

        let bind = UserIDBinding{
            userid: uid,
            selfsigs: vec![sig],
            certifications: vec![],
            self_revocations: vec![],
            other_revocations: vec![],
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
    use packet::signature::subpacket::{SubpacketTag, Subpacket, SubpacketValue};

    #[test]
    fn all_opts() {
        let (tpk, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
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
        assert_eq!(tpk.subkeys().count(), 3);
    }

    #[test]
    fn direct_key_sig() {
        let (tpk, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        assert_eq!(tpk.userids().count(), 0);
        assert_eq!(tpk.primary_key_signature().unwrap().sigtype(), SignatureType::DirectKey);
        assert_eq!(tpk.subkeys().count(), 3);
        if let Some(sig) = tpk.primary_key_signature() {
            assert!(sig.features().supports_mdc());
            assert!(sig.features().supports_aead());
        } else {
            panic!();
        }
    }

    #[test]
    fn setter() {
        let (tpk1, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_cipher_suite(CipherSuite::RSA3k)
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::EdDSA);

        let (tpk2, _) = TPKBuilder::default()
            .add_userid("test2@example.com")
            .add_encryption_subkey()
            .generate().unwrap();
        assert_eq!(tpk2.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk2.subkeys().next().unwrap().subkey().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn defaults() {
        let (tpk1, _) = TPKBuilder::default()
            .add_userid("test2@example.com")
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert!(tpk1.subkeys().next().is_none());
        if let Some(sig) = tpk1.primary_key_signature() {
            assert!(sig.features().supports_mdc());
            assert!(sig.features().supports_aead());
        } else {
            panic!();
        }
    }

    #[test]
    fn autocrypt() {
        let (tpk1, _) = TPKBuilder::autocrypt(None)
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk1.subkeys().next().unwrap().subkey().pk_algo, PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn always_certify() {
        let (tpk1, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .primary_keyflags(KeyFlags::default())
            .add_encryption_subkey()
            .generate().unwrap();
        let sig_pkts = &tpk1.primary_key_signature().unwrap().hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags) {
            Some(Subpacket{ value: SubpacketValue::KeyFlags(ref ks),.. }) => {
                assert!(ks.can_certify());
            }
            _ => {}
        }

        assert_eq!(tpk1.subkeys().count(), 1);
    }

    #[test]
    fn gen_wired_subkeys() {
        let (tpk1, _) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .primary_keyflags(KeyFlags::default())
            .add_subkey(KeyFlags::default().set_encrypt_for_transport(true).set_certify(true))
            .generate().unwrap();
        let sig_pkts = tpk1.subkeys().next().unwrap().selfsigs[0].hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags) {
            Some(Subpacket{ value: SubpacketValue::KeyFlags(ref ks),.. }) => {
                assert!(ks.can_certify());
                assert!(ks.can_encrypt_for_transport());
            }
            _ => {}
        }

        assert_eq!(tpk1.subkeys().count(), 1);
    }

    #[test]
    fn generate_revocation_certificate() {
        use RevocationStatus;
        let (tpk, revocation) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(tpk.revoked(), RevocationStatus::NotAsFarAsWeKnow);
    }
}
