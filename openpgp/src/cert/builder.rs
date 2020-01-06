use std::time;

use crate::packet;
use crate::packet::{
    key,
    Key,
    key::Key4,
};
use crate::Result;
use crate::packet::Signature;
use crate::packet::signature;
use crate::Cert;
use crate::cert::CertRevocationBuilder;
use crate::Error;
use crate::crypto::Password;
use crate::autocrypt::Autocrypt;
use crate::types::{
    Features,
    HashAlgorithm,
    KeyFlags,
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
    /// 2048 bit RSA with SHA512 and AES256
    RSA2k,
    /// 4096 bit RSA with SHA512 and AES256
    RSA4k,
}

impl Default for CipherSuite {
    fn default() -> Self {
        CipherSuite::Cv25519
    }
}

impl CipherSuite {
    fn generate_key<R>(self, flags: &KeyFlags)
        -> Result<Key<key::SecretParts, R>>
        where R: key::KeyRole
    {
        use crate::types::Curve;

        match self {
            CipherSuite::RSA2k =>
                Key4::generate_rsa(2048),
            CipherSuite::RSA3k =>
                Key4::generate_rsa(3072),
            CipherSuite::RSA4k =>
                Key4::generate_rsa(4096),
            CipherSuite::Cv25519 | CipherSuite::P256 |
            CipherSuite::P384 | CipherSuite::P521 => {
                let sign = flags.for_certification() || flags.for_signing()
                    || flags.for_authentication();
                let encrypt = flags.for_transport_encryption()
                    || flags.for_storage_encryption();
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
    expiration: Option<time::Duration>,
}

/// Simplifies generation of Keys.
///
/// Builder to generate complex Cert hierarchies with multiple user IDs.
#[derive(Clone, Debug)]
pub struct CertBuilder {
    ciphersuite: CipherSuite,
    primary: KeyBlueprint,
    subkeys: Vec<KeyBlueprint>,
    userids: Vec<packet::UserID>,
    user_attributes: Vec<packet::UserAttribute>,
    password: Option<Password>,
}

impl CertBuilder {
    /// Returns a new CertBuilder.
    ///
    /// The returned CertBuilder is setup to only create a
    /// certification-capable primary key using the default cipher
    /// suite.  You'll almost certainly want to add subkeys (using
    /// `CertBuilder::add_signing_subkey`, or
    /// `CertBuilder::add_transport_encryption_subkey`, for instance), and user
    /// ids (using `CertBuilder::add_userid`).
    pub fn new() -> Self {
        CertBuilder{
            ciphersuite: CipherSuite::default(),
            primary: KeyBlueprint{
                flags: KeyFlags::default().set_certification(true),
                expiration: None,
            },
            subkeys: vec![],
            userids: vec![],
            user_attributes: vec![],
            password: None,
        }
    }

    /// Generates a general-purpose key.
    ///
    /// The key's primary key is certification- and signature-capable.
    /// The key has one subkey, an encryption-capable subkey.
    pub fn general_purpose<C, U>(ciphersuite: C, userids: Option<U>) -> Self
        where C: Into<Option<CipherSuite>>,
              U: Into<packet::UserID>
    {
        CertBuilder {
            ciphersuite: ciphersuite.into().unwrap_or(Default::default()),
            primary: KeyBlueprint {
                flags: KeyFlags::default()
                    .set_certification(true)
                    .set_signing(true),
                expiration: Some(
                    time::Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0)),
            },
            subkeys: vec![
                KeyBlueprint {
                    flags: KeyFlags::default()
                        .set_transport_encryption(true)
                        .set_storage_encryption(true),
                    expiration: None,
                }
            ],
            userids: userids.into_iter().map(|x| x.into()).collect(),
            user_attributes: vec![],
            password: None,
        }
    }

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
        let builder = CertBuilder{
            ciphersuite: match version.into().unwrap_or(Default::default()) {
                Autocrypt::V1 => CipherSuite::RSA3k,
                Autocrypt::V1_1 => CipherSuite::Cv25519,
            },
            primary: KeyBlueprint {
                flags: KeyFlags::default()
                    .set_certification(true)
                    .set_signing(true),
                expiration: Some(
                    time::Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0)),
            },
            subkeys: vec![
                KeyBlueprint {
                    flags: KeyFlags::default()
                        .set_transport_encryption(true)
                        .set_storage_encryption(true),
                    expiration: None,
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
        self.add_subkey(KeyFlags::default().set_signing(true), None)
    }

    /// Adds a subkey suitable for transport encryption.
    pub fn add_transport_encryption_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_transport_encryption(true),
                        None)
    }

    /// Adds a subkey suitable for storage encryption.
    pub fn add_storage_encryption_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_storage_encryption(true),
                        None)
    }

    /// Adds an certification capable subkey.
    pub fn add_certification_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_certification(true), None)
    }

    /// Adds an authentication capable subkey.
    pub fn add_authentication_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_authentication(true), None)
    }

    /// Adds a custom subkey.
    ///
    /// If `expiration` is `None`, the subkey uses the same expiration
    /// time as the primary key.
    pub fn add_subkey<T>(mut self, flags: KeyFlags, expiration: T) -> Self
        where T: Into<Option<time::Duration>>
    {
        self.subkeys.push(KeyBlueprint {
            flags: flags,
            expiration: expiration.into(),
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

    /// Sets the expiration time.
    ///
    /// A value of None means never.
    pub fn set_expiration<T>(mut self, expiration: T) -> Self
        where T: Into<Option<time::Duration>>
    {
        self.primary.expiration = expiration.into();
        self
    }

    /// Generates the actual Cert.
    pub fn generate(mut self) -> Result<(Cert, Signature)> {
        use crate::{PacketPile, Packet};
        use crate::types::ReasonForRevocation;

        let mut packets = Vec::<Packet>::with_capacity(
            1 + 1 + self.subkeys.len() + self.userids.len()
                + self.user_attributes.len());

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certification(true);
        }

        // Generate & and self-sign primary key.
        let (primary, sig) = self.primary_key()?;
        let mut signer = primary.clone().mark_parts_secret().unwrap()
            .into_keypair().unwrap();

        packets.push(Packet::PublicKey({
            let mut primary = primary.clone();
            if let Some(ref password) = self.password {
                primary.secret_mut().unwrap().encrypt_in_place(password)?;
            }
            primary
        }));
        packets.push(sig.clone().into());

        let mut cert =
            Cert::from_packet_pile(PacketPile::from(packets))?;

        // Sign UserIDs.
        for uid in self.userids.into_iter() {
            let builder = signature::Builder::from(sig.clone())
                .set_type(SignatureType::PositiveCertification)
                // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512);
            let signature = uid.bind(&mut signer, &cert, builder, None)?;
            cert = cert.merge_packets(vec![uid.into(), signature.into()])?;
        }

        // Sign UserAttributes.
        for ua in self.user_attributes.into_iter() {
            let builder = signature::Builder::from(sig.clone())
                .set_type(SignatureType::PositiveCertification)
            // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512);
            let signature = ua.bind(&mut signer, &cert, builder, None)?;
            cert = cert.merge_packets(vec![ua.into(), signature.into()])?;
        }

        // sign subkeys
        for blueprint in self.subkeys {
            let flags = &blueprint.flags;
            let mut subkey = self.ciphersuite.generate_key(flags)?;

            let mut builder =
                signature::Builder::new(SignatureType::SubkeyBinding)
                // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_features(&Features::sequoia())?
                .set_key_flags(flags)?
                .set_key_expiration_time(
                    blueprint.expiration.or(self.primary.expiration))?;

            if flags.for_transport_encryption() || flags.for_storage_encryption()
            {
                builder = builder.set_preferred_symmetric_algorithms(vec![
                    SymmetricAlgorithm::AES256,
                ])?;
            }

            if flags.for_certification() || flags.for_signing() {
                builder = builder.set_preferred_hash_algorithms(vec![
                    HashAlgorithm::SHA512,
                ])?;

                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair().unwrap();
                let backsig =
                    signature::Builder::new(SignatureType::PrimaryKeyBinding)
                    // GnuPG wants at least a 512-bit hash for P521 keys.
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .set_signature_creation_time(
                        time::SystemTime::now())?
                    .set_issuer_fingerprint(subkey.fingerprint())?
                    .set_issuer(subkey.keyid())?
                    .sign_primary_key_binding(&mut subkey_signer, &primary,
                                              &subkey)?;
                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.mark_parts_public_ref()
                .bind(&mut signer, &cert, builder, None)?;

            if let Some(ref password) = self.password {
                subkey.secret_mut().unwrap().encrypt_in_place(password)?;
            }
            cert = cert.merge_packets(vec![Packet::SecretSubkey(subkey),
                                         signature.into()])?;
        }

        let revocation = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::Unspecified, b"Unspecified")?
            .build(&mut signer, &cert, None)?;

        // keys generated by the builder are never invalid
        assert!(cert.bad.is_empty());
        assert!(cert.unknowns.is_empty());

        Ok((cert, revocation))
    }

    fn primary_key(&self)
        -> Result<(key::PublicKey, Signature)>
    {
        let key = self.ciphersuite.generate_key(
            &KeyFlags::default().set_certification(true))?;
        let sig = signature::Builder::new(SignatureType::DirectKey)
            // GnuPG wants at least a 512-bit hash for P521 keys.
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_features(&Features::sequoia())?
            .set_key_flags(&self.primary.flags)?
            .set_signature_creation_time(
                time::SystemTime::now())?
            .set_key_expiration_time(self.primary.expiration)?
            .set_issuer_fingerprint(key.fingerprint())?
            .set_issuer(key.keyid())?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let mut signer = key.clone().into_keypair()
            .expect("key generated above has a secret");
        let sig = sig.sign_direct_key(&mut signer)?;

        Ok((key.mark_parts_public(), sig.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
    use crate::types::PublicKeyAlgorithm;

    #[test]
    fn all_opts() {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        let mut userids = cert.userids()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "test1@example.com",
                      "test2@example.com",
                   ][..]);
        assert_eq!(cert.subkeys().count(), 3);
    }

    #[test]
    fn direct_key_sig() {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        assert_eq!(cert.userids().count(), 0);
        assert_eq!(cert.primary_key_signature(None).unwrap().typ(),
                   crate::types::SignatureType::DirectKey);
        assert_eq!(cert.subkeys().count(), 3);
        if let Some(sig) = cert.primary_key_signature(None) {
            assert!(sig.features().supports_mdc());
        } else {
            panic!();
        }
    }

    #[test]
    fn setter() {
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_cipher_suite(CipherSuite::RSA3k)
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(cert1.primary().pk_algo(), PublicKeyAlgorithm::EdDSA);

        let (cert2, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA3k)
            .add_userid("test2@example.com")
            .add_transport_encryption_subkey()
            .generate().unwrap();
        assert_eq!(cert2.primary().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert2.subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn defaults() {
        let (cert1, _) = CertBuilder::new()
            .add_userid("test2@example.com")
            .generate().unwrap();
        assert_eq!(cert1.primary().pk_algo(),
                   PublicKeyAlgorithm::EdDSA);
        assert!(cert1.subkeys().next().is_none());
        if let Some(sig) = cert1.primary_key_signature(None) {
            assert!(sig.features().supports_mdc());
        } else {
            panic!();
        }
    }

    #[test]
    fn autocrypt_v1() {
        let (cert1, _) = CertBuilder::autocrypt(Autocrypt::V1,
                                              Some("Foo"))
            .generate().unwrap();
        assert_eq!(cert1.primary().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert1.subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert1.userids().count(), 1);
    }

    #[test]
    fn autocrypt_v1_1() {
        let (cert1, _) = CertBuilder::autocrypt(Autocrypt::V1_1,
                                              Some("Foo"))
            .generate().unwrap();
        assert_eq!(cert1.primary().pk_algo(),
                   PublicKeyAlgorithm::EdDSA);
        assert_eq!(cert1.subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::ECDH);
        assert_match!(
            crate::crypto::mpis::PublicKey::ECDH {
                curve: crate::types::Curve::Cv25519, ..
            } = cert1.subkeys().next().unwrap().key().mpis());
        assert_eq!(cert1.userids().count(), 1);
    }

    #[test]
    fn always_certify() {
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .primary_keyflags(KeyFlags::default())
            .add_transport_encryption_subkey()
            .generate().unwrap();
        let sig_pkts = &cert1.primary_key_signature(None).unwrap().hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags).unwrap().value() {
            SubpacketValue::KeyFlags(ref ks) => assert!(ks.for_certification()),
            v => panic!("Unexpected subpacket: {:?}", v),
        }

        assert_eq!(cert1.subkeys().count(), 1);
    }

    #[test]
    fn gen_wired_subkeys() {
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .primary_keyflags(KeyFlags::default())
            .add_subkey(KeyFlags::default().set_certification(true), None)
            .generate().unwrap();
        let sig_pkts = cert1.subkeys().next().unwrap().self_signatures[0].hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags).unwrap().value() {
            SubpacketValue::KeyFlags(ref ks) => assert!(ks.for_certification()),
            v => panic!("Unexpected subpacket: {:?}", v),
        }

        assert_eq!(cert1.subkeys().count(), 1);
    }

    #[test]
    fn generate_revocation_certificate() {
        use crate::RevocationStatus;
        let (cert, revocation) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(cert.revoked(None),
                   RevocationStatus::NotAsFarAsWeKnow);

        let cert = cert.merge_packets(vec![revocation.clone().into()]).unwrap();
        assert_eq!(cert.revoked(None),
                   RevocationStatus::Revoked(vec![ &revocation ]));
    }

    #[test]
    fn builder_roundtrip() {
        use crate::PacketPile;

        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();
        let pile = cert.clone().into_packet_pile().into_children().collect::<Vec<_>>();
        let exp = Cert::from_packet_pile(PacketPile::from(pile))
            .unwrap();

        assert_eq!(cert, exp);
    }

    #[test]
    fn encrypted_secrets() {
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_password(Some(String::from("streng geheim").into()))
            .generate().unwrap();
        assert!(cert.primary().secret().unwrap().is_encrypted());
    }

    #[test]
    fn all_ciphersuites() {
        use self::CipherSuite::*;

        for cs in vec![Cv25519, RSA3k, P256, P384, P521, RSA2k, RSA4k] {
            assert!(CertBuilder::new()
                .set_cipher_suite(cs)
                .generate().is_ok());
        }
    }

    #[test]
    fn expiration_times() {
        let s = std::time::Duration::new(1, 0);
        let (cert,_) = CertBuilder::new()
            .set_expiration(600 * s)
            .add_subkey(KeyFlags::default().set_signing(true),
                        300 * s)
            .add_subkey(KeyFlags::default().set_authentication(true),
                        None)
            .generate().unwrap();

        let now = cert.primary().creation_time()
            + 5 * s; // The subkeys may be created a tad later.
        let key = cert.primary();
        let sig = cert.primary_key_signature(None).unwrap();
        assert!(sig.key_alive(key, now).is_ok());
        assert!(sig.key_alive(key, now + 590 * s).is_ok());
        assert!(! sig.key_alive(key, now + 610 * s).is_ok());

        let (sig, key) = cert.keys().policy(now).alive().revoked(false)
            .for_signing()
            .nth(0).map(|ka| {
                (ka.binding_signature(now).unwrap(), ka.key())
            }).unwrap();
        assert!(sig.key_alive(key, now).is_ok());
        assert!(sig.key_alive(key, now + 290 * s).is_ok());
        assert!(! sig.key_alive(key, now + 310 * s).is_ok());

        let (sig, key) = cert.keys().policy(now).alive().revoked(false)
            .for_authentication()
            .nth(0).map(|ka| {
                (ka.binding_signature(now).unwrap(), ka.key())
            }).unwrap();
        assert!(sig.key_alive(key, now).is_ok());
        assert!(sig.key_alive(key, now + 590 * s).is_ok());
        assert!(! sig.key_alive(key, now + 610 * s).is_ok());
    }
}
