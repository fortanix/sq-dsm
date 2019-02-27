use std::borrow::Cow;

use time;
use packet::{Features, KeyFlags};
use packet::Key;
use Result;
use packet::UserID;
use crypto::KeyPair;
use HashAlgorithm;
use packet::signature::{self, Signature};
use packet::key::SecretKey;
use TPK;
use Error;
use conversions::Time;
use constants::{
    SignatureType,
};
use crypto::Password;
use autocrypt::Autocrypt;

/// Groups symmetric and asymmetric algorithms
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum CipherSuite {
    /// EdDSA and ECDH over Curve25519 with SHA512 and AES256
    Cv25519,
    /// 3072 bit RSA with SHA512 and AES256
    RSA3k,
    /// EdDSA and ECDH over NIST P-256 with SHA256 and AES256
    P256,
    /// EdDSA and ECDH over NIST P-384 with SHA384 and AES256
    P384,
    /// EdDSA and ECDH over NIST P-521 with SHA512 and AES256
    P521,
}

impl CipherSuite {
    fn generate_key(self, flags: &KeyFlags) -> Result<Key> {
        use constants::Curve;

        match self {
            CipherSuite::RSA3k =>
                Key::generate_rsa(3072),
            CipherSuite::Cv25519 | CipherSuite::P256 |
            CipherSuite::P384 | CipherSuite::P521 => {
                let sign = flags.can_certify() || flags.can_sign();
                let encrypt = flags.can_encrypt_for_transport()
                    || flags.can_encrypt_at_rest();
                let curve = match self {
                    CipherSuite::Cv25519 if sign => Curve::Ed25519,
                    CipherSuite::Cv25519 if encrypt => Curve::Cv25519,
                    CipherSuite::Cv25519 => {
                        return Err(Error::InvalidOperation(
                            "No key flags set".into())
                            .into());
                    }
                    CipherSuite::P256 => Curve::NistP256,
                    CipherSuite::P384 => Curve::NistP384,
                    CipherSuite::P521 => Curve::NistP521,
                    _ => unreachable!(),
                };

                match (sign, encrypt) {
                    (true, false) => Key::generate_ecc(true, curve),
                    (false, true) => Key::generate_ecc(false, curve),
                    (true, true) =>
                        Err(Error::InvalidOperation(
                            "Can't use key for encryption and signing".into())
                            .into()),
                    (false, false) =>
                        Err(Error::InvalidOperation(
                            "No key flags set".into())
                            .into()),
                }
            },
        }
    }
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
    password: Option<Password>,
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
            password: None,
        }
    }
}

impl TPKBuilder {
    /// Generates a key compliant to
    /// [Autocrypt](https://autocrypt.org/).
    ///
    /// If no version is given the latest one is used.
    ///
    /// The autocrypt specification requires a UserID.  However,
    /// because it can be useful to add the UserID later, it is
    /// permitted to be none.
    pub fn autocrypt<'a, V, S>(version: V, userid: S)
        -> Self
        where V: Into<Option<Autocrypt>>,
            S: Into<Option<Cow<'a, str>>>
    {
        let builder = TPKBuilder{
            ciphersuite: match version.into().unwrap_or(Default::default()) {
                Autocrypt::V1 => CipherSuite::RSA3k,
                Autocrypt::V1_1 => CipherSuite::Cv25519,
            },
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
            userids: vec![],
            password: None,
        };

        if let Some(userid) = userid.into() {
            builder.add_userid(userid)
        } else {
            builder
        }
    }

    /// Sets the encryption and signature algorithms for primary and all subkeys.
    pub fn set_cipher_suite(mut self, cs: CipherSuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    /// Adds a new user ID. The first user ID added will be the primary user ID.
    pub fn add_userid<'a, S>(mut self, uid: S) -> Self
        where S: Into<Cow<'a, str>>
    {
        self.userids.push(uid.into().into_owned());
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

    /// Sets a password to encrypt the secret keys with.
    pub fn set_password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }

    /// Generates the actual TPK.
    pub fn generate(mut self) -> Result<(TPK, Signature)> {
        use {PacketPile, Packet, TSK};
        use constants::ReasonForRevocation;

        let mut packets = Vec::<Packet>::with_capacity(
            1 + 1 + self.subkeys.len() + self.userids.len());

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certify(true);
        }

        // select the first UserID as primary, if present
        let maybe_first_uid = self.userids.first().map(|uid| {
            UserID::from(uid.as_str())
        });
        // Generate & and self-sign primary key.
        let (primary, sig) = Self::primary_key(
            self.primary, maybe_first_uid.as_ref(), self.ciphersuite)?;

        packets.push(Packet::PublicKey({
            let mut primary = primary.clone();
            if let Some(ref password) = self.password {
                primary.secret_mut().unwrap().encrypt_in_place(password)?;
            }
            primary
        }));
        packets.push(Packet::Signature(sig.clone()));

        // Sort primary keys self-sig into the right vec.
        match maybe_first_uid {
            Some(uid) => {
                // maybe to strict?
                assert_eq!(sig.sigtype(), SignatureType::PositiveCertificate);

                packets.push(Packet::UserID(uid));
            }
            None => {
                assert_eq!(sig.sigtype(), SignatureType::DirectKey);
            }
        };

        let mut tsk =
            TSK::from_tpk(TPK::from_packet_pile(PacketPile::from(packets))?);

        // sign UserIDs. First UID was used as primary keys self-sig
        if !self.userids.is_empty() {
            for uid in self.userids[1..].iter() {
                let uid = UserID::from(uid.as_str());

                tsk = tsk.with_userid(uid)?;
            }
        }

        // sign subkeys
        for blueprint in self.subkeys {
            let mut subkey = self.ciphersuite.generate_key(&blueprint.flags)?;

            if let Some(ref password) = self.password {
                subkey.secret_mut().unwrap().encrypt_in_place(password)?;
            }

            tsk = tsk.with_subkey(subkey, &blueprint.flags, self.password.as_ref())?;
        }


        let tpk = tsk.into_tpk();
        let sec =
            if let Some(SecretKey::Unencrypted { ref mpis }) = primary.secret() {
                mpis.clone()
            } else {
                unreachable!()
            };
        let revocation = tpk.revoke(&mut KeyPair::new(primary, sec)?,
                                    ReasonForRevocation::Unspecified,
                                    b"Unspecified")?;

        // keys generated by the builder are never invalid
        assert!(tpk.bad.is_empty());
        assert!(tpk.unknowns.is_empty());

        Ok((tpk, revocation))
    }

    fn primary_key(blueprint: KeyBlueprint, uid: Option<&UserID>, cs: CipherSuite)
        -> Result<(Key, Signature)>
    {
        use SignatureType;
        use packet::key::SecretKey;

        let key = cs.generate_key(&KeyFlags::default().set_certify(true))?;
        let sigtype = if uid.is_some() {
            SignatureType::PositiveCertificate
        } else {
            SignatureType::DirectKey
        };

        let sig = signature::Builder::new(sigtype)
            .set_features(&Features::sequoia())?
            .set_key_flags(&blueprint.flags)?
            .set_signature_creation_time(time::now().canonicalize())?
            .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?
            .set_issuer_fingerprint(key.fingerprint())?
            .set_issuer(key.fingerprint().to_keyid())?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let sig = match key.secret() {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                match uid {
                    Some(uid) => sig.sign_userid_binding(
                        &mut KeyPair::new(key.clone(), mpis.clone())?,
                        &key, &uid, HashAlgorithm::SHA512)?,
                    None => sig.sign_primary_key_binding(
                        &mut KeyPair::new(key.clone(), mpis.clone())?,
                        HashAlgorithm::SHA512)?,
                }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::signature::subpacket::{SubpacketTag, Subpacket, SubpacketValue};
    use constants::PublicKeyAlgorithm;

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
            .map(|u| String::from_utf8_lossy(u.userid.userid()).into_owned())
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
        assert_eq!(tpk1.primary().pk_algo(), PublicKeyAlgorithm::EdDSA);

        let (tpk2, _) = TPKBuilder::default()
            .add_userid("test2@example.com")
            .add_encryption_subkey()
            .generate().unwrap();
        assert_eq!(tpk2.primary().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk2.subkeys().next().unwrap().subkey().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn defaults() {
        let (tpk1, _) = TPKBuilder::default()
            .add_userid("test2@example.com")
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert!(tpk1.subkeys().next().is_none());
        if let Some(sig) = tpk1.primary_key_signature() {
            assert!(sig.features().supports_mdc());
            assert!(sig.features().supports_aead());
        } else {
            panic!();
        }
    }

    #[test]
    fn autocrypt_v1() {
        let (tpk1, _) = TPKBuilder::autocrypt(Autocrypt::V1,
                                              Some("Foo".into()))
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk1.subkeys().next().unwrap().subkey().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(tpk1.userids().count(), 1);
    }

    #[test]
    fn autocrypt_v1_1() {
        let (tpk1, _) = TPKBuilder::autocrypt(Autocrypt::V1_1,
                                              Some("Foo".into()))
            .generate().unwrap();
        assert_eq!(tpk1.primary().pk_algo(),
                   PublicKeyAlgorithm::EdDSA);
        assert_eq!(tpk1.subkeys().next().unwrap().subkey().pk_algo(),
                   PublicKeyAlgorithm::ECDH);
        assert_match!(
            ::crypto::mpis::PublicKey::ECDH {
                curve: ::constants::Curve::Cv25519, ..
            } = tpk1.subkeys().next().unwrap().subkey().mpis());
        assert_eq!(tpk1.userids().count(), 1);
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
            .add_subkey(KeyFlags::default().set_certify(true))
            .generate().unwrap();
        let sig_pkts = tpk1.subkeys().next().unwrap().selfsigs[0].hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags) {
            Some(Subpacket{ value: SubpacketValue::KeyFlags(ref ks),.. }) => {
                assert!(ks.can_certify());
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
        assert_eq!(tpk.revoked(None), RevocationStatus::NotAsFarAsWeKnow);

        let tpk = tpk.merge_packets(vec![revocation.clone().into()]).unwrap();
        assert_eq!(tpk.revoked(None), RevocationStatus::Revoked(&[revocation]));
    }

    #[test]
    fn builder_roundtrip() {
        use PacketPile;

        let (tpk,_) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();
        let pile = tpk.clone().into_packet_pile().into_children().collect::<Vec<_>>();
        let exp = TPK::from_packet_pile(PacketPile::from(pile))
            .unwrap();

        assert_eq!(tpk, exp);
    }

    #[test]
    fn encrypted_secrets() {
        let (tpk,_) = TPKBuilder::default()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_password(Some(String::from("streng geheim").into()))
            .generate().unwrap();
        assert!(tpk.primary().secret().unwrap().is_encrypted());
    }

    #[test]
    fn all_ciphersuites() {
        use self::CipherSuite::*;

        for cs in vec![Cv25519, RSA3k, P256, P384, P521] {
            assert!(TPKBuilder::default()
                .set_cipher_suite(cs)
                .generate().is_ok());
        }
    }
}
