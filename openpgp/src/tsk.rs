use std::borrow::Cow;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use time;

use {
    Result,
    TPK,
    Error,
    Packet,
    conversions::Time,
};

use crypto::{KeyPair, Password};
use packet::{
    Signature,
    Tag,
    UserID,
    Key,
    UserAttribute,
    KeyFlags,
};
use serialize::{
    Serialize,
    SerializeKey,
};
use parse::{Parse, PacketParserResult};

/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
#[derive(Debug, PartialEq)]
pub struct TSK {
    key: TPK,
}

impl Deref for TSK {
    type Target = TPK;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl DerefMut for TSK {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key
    }
}

impl<'a> Parse<'a, TSK> for TSK {
    /// Initializes a `TSK` from a `Read`er.
    fn from_reader<R: 'a + io::Read>(reader: R) -> Result<Self> {
        TPK::from_reader(reader).map(|tpk| Self::from_tpk(tpk))
    }

    /// Initializes a `TSK` from a `File`.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        TPK::from_file(path).map(|tpk| Self::from_tpk(tpk))
    }

    /// Initializes a `TSK` from a byte string.
    fn from_bytes(data: &'a [u8]) -> Result<Self> {
        TPK::from_bytes(data).map(|tpk| Self::from_tpk(tpk))
    }
}

impl TSK {
    /// Initializes a `TSK` from a `PacketParser`.
    pub fn from_packet_parser<'a>(ppr: PacketParserResult<'a>) -> Result<Self> {
        TPK::from_packet_parser(ppr).map(|tpk| Self::from_tpk(tpk))
    }

    pub(crate) fn from_tpk(tpk: TPK) -> TSK {
        TSK{ key: tpk }
    }

    /// Generates a new key OpenPGP key. The key will be capable of encryption
    /// and signing. If no user id is given the primary self signature will be
    /// a direct key signature.
    pub fn new<'a, O>(primary_uid: O) -> Result<(TSK, Signature)>
        where O: Into<Option<Cow<'a, str>>>
    {
        use tpk::TPKBuilder;

        let key = TPKBuilder::autocrypt(None, primary_uid);
        let (tpk, revocation) = key.generate()?;
        Ok((TSK::from_tpk(tpk), revocation))
    }

    /// Returns a reference to the corresponding TPK.
    pub fn tpk<'a>(&'a self) -> &'a TPK {
        &self.key
    }

    /// Converts to a TPK.
    pub fn into_tpk(self) -> TPK {
        self.key
    }

    /// Signs `key` and `userid` with a 3rd party certification.
    ///
    /// Note: This is a convenience function around
    /// [`signature::Builder::sign_userid_binding()`].  If your TSK
    /// contains encrypted or remote keys, or you want to customize
    /// the signature, use this function instead.
    ///
    /// [`signature::Builder::sign_userid_binding()`]: packet/signature/struct.Builder.html#method.sign_userid_binding
    pub fn certify_userid(&self, key: &Key, userid: &UserID)
                          -> Result<Signature> {
        use packet::signature;
        use constants::{HashAlgorithm, SignatureType};

        // We're willing to use an expired certification key here,
        // because otherwise it is impossible to extend the expiration
        // of an expired TPK.
        //
        // XXX: If there are multiple certification keys, then we
        // should prefer a non-expired one.
        let certification_key = self.key.keys_all()
            .certification_capable()
            .unencrypted_secret(true)
            .nth(0)
            .map(|x| x.2)
            .ok_or(failure::Error::from(Error::InvalidOperation(
                "this key cannot certify keys".into())))?;

        let mut signer = certification_key.clone().into_keypair()
            .expect("filtered for unencrypted secret keys above");
        signature::Builder::new(SignatureType::GenericCertificate)
            .sign_userid_binding(&mut signer, key, userid,
                                 HashAlgorithm::SHA512)
    }

    /// Signs the primary key's self signatures of `key`.
    pub fn certify_key(&self, key: &TPK) -> Result<Signature> {
        match key.primary_key_signature_full() {
            None | Some((None, _)) =>
                Err(Error::InvalidOperation(
                    "this key has nothing to certify".into()).into()),
            Some((Some(uid), _)) =>
                self.certify_userid(key.primary(), uid.userid()),
        }
    }

    /// Signs `userid` with this TSK.
    pub fn sign_userid(&self, userid: &UserID) -> Result<Signature> {
        use packet::{signature, key::SecretKey};
        use constants::{HashAlgorithm, SignatureType};

        let builder =
            if let Some(sig) = self.primary_key_signature() {
                signature::Builder::from(sig.clone())
                    .set_sigtype(SignatureType::PositiveCertificate)
            } else {
                signature::Builder::new(SignatureType::PositiveCertificate)
            }
        .set_signature_creation_time(time::now())?;

        let certification_key = self.key.keys_valid()
            .certification_capable()
            .unencrypted_secret(true)
            .nth(0)
            .map(|x| x.2);

        match certification_key {
            Some(my_key) => {
                match my_key.secret() {
                    Some(&SecretKey::Unencrypted{ ref mpis }) => {
                        builder
                            .set_issuer_fingerprint(my_key.fingerprint())?
                            .set_issuer(my_key.keyid())?
                            .sign_userid_binding(
                                &mut KeyPair::new((*my_key).clone(),
                                mpis.clone())?,
                                my_key, userid, HashAlgorithm::SHA512)
                    }
                    // XXX
                    _ => Err(Error::InvalidOperation(
                            "secret key missing or encrypted".into()).into()),
                }
            }
            None => Err(Error::InvalidOperation(
                        "this key cannot certify keys".into()).into()),
        }
    }

    /// Signs `userattr` with a the primary key.
    pub fn sign_user_attribute(&self, userattr: &UserAttribute) -> Result<Signature> {
        use packet::{signature, key::SecretKey};
        use constants::{HashAlgorithm, SignatureType};

        let certification_key = self.key.keys_valid()
            .certification_capable()
            .unencrypted_secret(true)
            .nth(0)
            .map(|x| x.2);

        match certification_key {
            Some(my_key) => {
                match my_key.secret() {
                    Some(&SecretKey::Unencrypted{ ref mpis }) => {
                        let mut pair =
                            KeyPair::new((*my_key).clone(), mpis.clone())?;

                        signature::Builder::new(SignatureType::GenericCertificate)
                            .set_signature_creation_time(time::now())?
                            .set_issuer_fingerprint(my_key.fingerprint())?
                            .set_issuer(my_key.keyid())?
                            .sign_user_attribute_binding(
                                &mut pair,
                                userattr,
                                HashAlgorithm::SHA512)
                    }
                    // XXX
                    _ => Err(Error::InvalidOperation(
                            "secret key missing or encrypted".into()).into()),
                }
            }
            None => Err(Error::InvalidOperation(
                    "this key cannot certify user attributes".into()).into()),
        }
    }

    /// Create a binding signature between this TSK and `subkey`. Uses the TSKs
    /// primary key to sign the binding. The binding signature will advertise
    /// `flags` key capabilities. If `subkey` is encrypted that caller must
    /// supply the password in `passwd`.
    pub fn sign_subkey(&self, subkey: &Key, flags: &KeyFlags,
                       passwd: Option<&Password>)
        -> Result<Signature>
    {
        use packet::{signature, Features, key::SecretKey};
        use constants::{HashAlgorithm, SignatureType, SymmetricAlgorithm};

        let prim = self.key.primary();
        let mut sig = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_features(&Features::sequoia())?
            .set_key_flags(flags)?
            .set_signature_creation_time(time::now().canonicalize())?
            .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?
            .set_issuer_fingerprint(prim.fingerprint())?
            .set_issuer(prim.keyid())?;

        if flags.can_encrypt_for_transport()
        || flags.can_encrypt_at_rest() {
            sig = sig.set_preferred_symmetric_algorithms(
                vec![SymmetricAlgorithm::AES256])?;
        }

        if flags.can_certify() || flags.can_sign() {
            sig = sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

            let sk = match passwd {
                Some(pwd) => subkey.secret().and_then(|sk| {
                    sk
                        .decrypt(subkey.pk_algo(), pwd)
                        .ok()
                        .map(|mpi| SecretKey::Unencrypted{ mpis: mpi })
                        .or(subkey.secret().cloned())
                }),
                None => subkey.secret().cloned(),
            };

            let backsig = match sk {
                Some(SecretKey::Unencrypted{ ref mpis }) => {
                    signature::Builder::new(SignatureType::PrimaryKeyBinding)
                        .set_signature_creation_time(time::now().canonicalize())?
                        .set_issuer_fingerprint(subkey.fingerprint())?
                        .set_issuer(subkey.keyid())?
                        .sign_subkey_binding(
                            &mut KeyPair::new(subkey.clone(), mpis.clone())?,
                            prim, &subkey, HashAlgorithm::SHA512)?
                }
                // XXX
                Some(SecretKey::Encrypted{ .. }) => {
                    return Err(Error::InvalidOperation(
                            "Secret key is encrypted".into()).into());
                }
                None => {
                    return Err(Error::InvalidOperation(
                            "No secret key".into()).into());
                }
            };
            sig = sig.set_embedded_signature(backsig)?;
        }

        let sig = match prim.secret() {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_subkey_binding(&mut KeyPair::new(prim.clone(),
                                                          mpis.clone())?,
                                        prim, &subkey,
                                        HashAlgorithm::SHA512)?
            }
            // XXX
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation(
                        "Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation(
                        "No secret key".into()).into());
            }
        };

        Ok(sig)
    }

    /// Adds a 3rd party certification by `certifier` of the user ID `userid`.
    /// It's not checked whether `userid` is bound to this TSK.
    pub fn with_userid_certification(self, certifier: &TSK, userid: &UserID)
        -> Result<Self>
    {
        let sig = certifier.certify_userid(self.key.primary(), userid)?;

        Ok(TSK{
            key: self.key.merge_packets(vec![
                Packet::Signature(sig)
            ])?
        })
    }

    /// Adds UserID `userid` to this TSK and bind it to the primary key.
    /// There is no check whether the user ID is already bound to this key.
    pub fn with_userid(self, userid: UserID) -> Result<Self> {
        let sig = self.sign_userid(&userid)?;

        Ok(TSK{
            key: self.key.merge_packets(vec![
                Packet::UserID(userid),
                Packet::Signature(sig)
            ])?
        })
    }

    /// Adds UserID `userid` to this TSK and bind it to the primary key.
    /// There is no check whether the user attribute is already bound to this key.
    pub fn with_user_attribute(self, userattr: UserAttribute) -> Result<Self> {
        let sig = self.sign_user_attribute(&userattr)?;

        Ok(TSK{
            key: self.key.merge_packets(vec![
                Packet::UserAttribute(userattr),
                Packet::Signature(sig)
            ])?
        })
    }

    /// Adds sub key `subkey` to this TSK and bind it. There is no check whether
    /// the subkey is already part of the TSK. The binding signature will advertise
    /// `flags` key capabilities. If `subkey` is encrypted that caller must
    /// supply the password in `passwd`.
    pub fn with_subkey(self, subkey: Key, flags: &KeyFlags, passwd: Option<&Password>) -> Result<Self> {
        let sig = self.sign_subkey(&subkey, flags, passwd)?;
        let pkt = if subkey.secret().is_some() {
            Packet::SecretSubkey(subkey)
        } else {
            Packet::PublicSubkey(subkey)
        };

        Ok(TSK{
            key: self.key.merge_packets(vec![
                pkt,
                Packet::Signature(sig)
            ])?
        })
    }
 }

impl Serialize for TSK {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        self.key.primary.serialize(o, Tag::SecretKey)?;

        for s in self.key.primary_selfsigs.iter() {
            s.serialize(o)?;
        }
        for s in self.key.primary_self_revocations.iter() {
            s.serialize(o)?;
        }
        for s in self.key.primary_certifications.iter() {
            s.serialize(o)?;
        }
        for s in self.key.primary_other_revocations.iter() {
            s.serialize(o)?;
        }

        for u in self.key.userids() {
            u.userid().serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for u in self.key.user_attributes() {
            u.user_attribute().serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for k in self.key.subkeys() {
            k.subkey().serialize(o, Tag::SecretSubkey)?;
            for s in k.self_revocations() {
                s.serialize(o)?;
            }
            for s in k.selfsigs() {
                s.serialize(o)?;
            }
            for s in k.other_revocations() {
                s.serialize(o)?;
            }
            for s in k.certifications() {
                s.serialize(o)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpk::TPKBuilder;

    #[test]
    fn certification_direct_key() {
        let (tpk1, _) = TPKBuilder::default()
            .add_certification_subkey()
            .generate().unwrap();
        let tsk = tpk1.into_tsk();
        let (tpk2, _) = TPKBuilder::default()
            .generate().unwrap();

        assert!(tsk.certify_key(&tpk2).is_err());
    }

    #[test]
    fn certification_user_id() {
        let (tpk1, _) = TPKBuilder::default()
            .add_certification_subkey()
            .generate().unwrap();
        let tsk = tpk1.into_tsk();
        let (tpk2, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .generate().unwrap();

        let sig = tsk.certify_key(&tpk2).unwrap();
        let key = tsk.tpk().keys_all()
            .certification_capable().nth(0).unwrap().2;

        assert_eq!(
            sig.verify_userid_binding(
                key,
                tpk2.primary(),
                tpk2.userids().next().unwrap().userid()).unwrap(),
            true);
    }

    #[test]
    fn add_userid() {
        use std::str;

        let ui1 = b"test1@example.com";
        let ui2 = b"test2@example.com";
        let (tpk, _) = TPKBuilder::default()
            .add_userid(str::from_utf8(ui1).unwrap())
            .generate().unwrap();

        let tsk = TSK::from_tpk(tpk)
            .with_userid(UserID::from(str::from_utf8(ui2).unwrap()))
            .unwrap();
        let userids = tsk
            .userids()
            .map(|binding| binding.userid().value())
            .collect::<Vec<_>>();

        assert_eq!(userids.len(), 2);
        assert!((userids[0] == ui1 && userids[1] == ui2) ^
                (userids[0] == ui2 && userids[1] == ui1));
    }

    #[test]
    fn add_user_attr() {
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .generate().unwrap();

        let tsk = TSK::from_tpk(tpk)
            .with_user_attribute(UserAttribute::from(Vec::from(&b"Hello, World"[..])))
            .unwrap();
        let userattrs = tsk
            .user_attributes()
            .map(|binding| binding.user_attribute().value())
            .collect::<Vec<_>>();

        assert_eq!(userattrs.len(), 1);
    }

    #[test]
    fn add_subkey() {
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .generate().unwrap();

        let key: Key =
            ::packet::key::Key4::generate_ecc(true, ::constants::Curve::Ed25519)
            .unwrap().into();
        let flags = KeyFlags::default().set_sign(true);
        let tsk = TSK::from_tpk(tpk)
            .with_subkey(key, &flags, None)
            .unwrap();
        let subkeys = tsk
            .subkeys()
            .map(|binding| binding.subkey())
            .collect::<Vec<_>>();

        assert_eq!(subkeys.len(), 1);
    }

    #[test]
    fn user_ids() {
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .generate().unwrap();

        let userids = tpk
            .userids()
            .map(|binding| binding.userid().value())
            .collect::<Vec<_>>();
        assert_eq!(userids.len(), 2);
        assert!((userids[0] == b"test1@example.com"
                 && userids[1] == b"test2@example.com")
                || (userids[0] == b"test2@example.com"
                    && userids[1] == b"test1@example.com"),
                "User ids: {:?}", userids);


        let (tpk, _) = TPKBuilder::autocrypt(None, Some("Foo".into()))
            .generate()
            .unwrap();

        let userids = tpk
            .userids()
            .map(|binding| binding.userid().value())
            .collect::<Vec<_>>();
        assert_eq!(userids.len(), 1);
        assert_eq!(userids[0], b"Foo");


        let (tsk, _) = TSK::new(Some("test@example.com".into())).unwrap();
        let tpk = tsk.into_tpk();
        let userids = tpk
            .userids()
            .map(|binding| binding.userid().value())
            .collect::<Vec<_>>();
        assert_eq!(userids.len(), 1);
        assert_eq!(userids[0], b"test@example.com",
                   "User ids: {:?}", userids);
    }
}
