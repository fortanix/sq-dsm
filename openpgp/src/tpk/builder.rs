use time;

use packet;
use packet::{Features, KeyFlags};
use packet::Key;
use packet::key::Key4;
use Result;
use packet::Signature;
use packet::signature;
use TPK;
use Error;
use conversions::Time;
use crypto::Password;
use autocrypt::Autocrypt;
use constants::{
    HashAlgorithm,
    SignatureType,
    SymmetricAlgorithm,
};

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
                Key4::generate_rsa(3072),
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
                    (true, false) => Key4::generate_ecc(true, curve),
                    (false, true) => Key4::generate_ecc(false, curve),
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
        }.map(|key| key.into())
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
    userids: Vec<packet::UserID>,
    user_attributes: Vec<packet::UserAttribute>,
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
            user_attributes: vec![],
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
    pub fn autocrypt<'a, V, U>(version: V, userid: Option<U>)
        -> Self
        where V: Into<Option<Autocrypt>>,
              U: Into<packet::UserID>
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
            user_attributes: vec![],
            password: None,
        };

        if let Some(userid) = userid {
            builder.add_userid(userid.into())
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
    pub fn add_userid<'a, U>(mut self, uid: U) -> Self
        where U: Into<packet::UserID>
    {
        self.userids.push(uid.into());
        self
    }

    /// Adds a new user attribute.
    pub fn add_user_attribute<'a, U>(mut self, ua: U) -> Self
        where U: Into<packet::UserAttribute>
    {
        self.user_attributes.push(ua.into());
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
        use {PacketPile, Packet};
        use constants::ReasonForRevocation;

        let mut packets = Vec::<Packet>::with_capacity(
            1 + 1 + self.subkeys.len() + self.userids.len()
                + self.user_attributes.len());

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certify(true);
        }

        // Generate & and self-sign primary key.
        let (primary, sig) = Self::primary_key(self.primary, self.ciphersuite)?;
        let mut signer = primary.clone().into_keypair().unwrap();

        packets.push(Packet::PublicKey({
            let mut primary = primary.clone();
            if let Some(ref password) = self.password {
                primary.secret_mut().unwrap().encrypt_in_place(password)?;
            }
            primary
        }));
        packets.push(sig.clone().into());

        let mut tpk =
            TPK::from_packet_pile(PacketPile::from(packets))?;

        // Sign UserIDs.
        for uid in self.userids.into_iter() {
            let builder = signature::Builder::from(sig.clone())
                .set_sigtype(SignatureType::PositiveCertificate);
            let signature = uid.bind(&mut signer, &tpk, builder, None, None)?;
            tpk = tpk.merge_packets(vec![uid.into(), signature.into()])?;
        }

        // Sign UserAttributes.
        for ua in self.user_attributes.into_iter() {
            let builder = signature::Builder::from(sig.clone())
                .set_sigtype(SignatureType::PositiveCertificate);
            let signature = ua.bind(&mut signer, &tpk, builder, None, None)?;
            tpk = tpk.merge_packets(vec![ua.into(), signature.into()])?;
        }

        // sign subkeys
        for blueprint in self.subkeys {
            let flags = &blueprint.flags;
            let mut subkey = self.ciphersuite.generate_key(flags)?;

            if let Some(ref password) = self.password {
                subkey.secret_mut().unwrap().encrypt_in_place(password)?;
            }

            let mut builder =
                signature::Builder::new(SignatureType::SubkeyBinding)
                .set_features(&Features::sequoia())?
                .set_key_flags(flags)?
                .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;

            if flags.can_encrypt_for_transport() || flags.can_encrypt_at_rest()
            {
                builder = builder.set_preferred_symmetric_algorithms(vec![
                    SymmetricAlgorithm::AES256,
                ])?;
            }

            if flags.can_certify() || flags.can_sign() {
                builder = builder.set_preferred_hash_algorithms(vec![
                    HashAlgorithm::SHA512,
                ])?;

                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair().unwrap();
                let backsig =
                    signature::Builder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(time::now().canonicalize())?
                    .set_issuer_fingerprint(subkey.fingerprint())?
                    .set_issuer(subkey.keyid())?
                    .sign_subkey_binding(&mut subkey_signer, &primary, &subkey,
                                         HashAlgorithm::SHA512)?;
                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature =
                subkey.bind(&mut signer, &tpk, builder, None, None)?;
            tpk = tpk.merge_packets(vec![Packet::SecretSubkey(subkey),
                                         signature.into()])?;
        }

        let revocation = tpk.revoke(&mut signer,
                                    ReasonForRevocation::Unspecified,
                                    b"Unspecified")?;

        // keys generated by the builder are never invalid
        assert!(tpk.bad.is_empty());
        assert!(tpk.unknowns.is_empty());

        Ok((tpk, revocation))
    }

    fn primary_key(blueprint: KeyBlueprint, cs: CipherSuite)
        -> Result<(Key, Signature)>
    {
        use SignatureType;

        let key = cs.generate_key(&KeyFlags::default().set_certify(true))?;
        let sig = signature::Builder::new(SignatureType::DirectKey)
            .set_features(&Features::sequoia())?
            .set_key_flags(&blueprint.flags)?
            .set_signature_creation_time(time::now().canonicalize())?
            .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?
            .set_issuer_fingerprint(key.fingerprint())?
            .set_issuer(key.keyid())?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let mut signer = key.clone().into_keypair()
            .expect("key generated above has a secret");
        let sig = sig.sign_primary_key_binding(&mut signer,
                                               HashAlgorithm::SHA512)?;

        Ok((key, sig.into()))
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
            .map(|u| String::from_utf8_lossy(u.userid.value()).into_owned())
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
        assert_eq!(tpk.primary_key_signature().unwrap().sigtype(),
                   ::constants::SignatureType::DirectKey);
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
                                              Some("Foo"))
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
                                              Some("Foo"))
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
