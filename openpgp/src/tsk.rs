use std::borrow::Cow;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use {
    Result,
    TPK,
    Error,
};

use crypto::KeyPair;
use packet::{
    signature::Signature,
    Tag,
    UserID,
    Key,
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
    pub fn certify_userid(&self, key: &Key, userid: &UserID) -> Result<Signature> {
        use packet::{KeyFlags, signature, key::SecretKey};
        use constants::{HashAlgorithm, SignatureType};

        let caps = KeyFlags::default().set_certify(true);
        let keys = self.key.select_keys(caps, None);

        match keys.first() {
            Some(my_key) => {
                match my_key.secret() {
                    Some(&SecretKey::Unencrypted{ ref mpis }) => {
                        signature::Builder::new(SignatureType::GenericCertificate)
                            .sign_userid_binding(
                                &mut KeyPair::new((*my_key).clone(),
                                                  mpis.clone())?,
                                key, userid, HashAlgorithm::SHA512)
                    }
                    _ => Err(Error::InvalidOperation(
                            "secret key missing or encrypted".into()).into()),
                }
            }
            None => Err(Error::InvalidOperation(
                        "this key cannot certify keys".into()).into()),
        }
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
 }

impl Serialize for TSK {
    /// Serializes the TSK.
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
        use packet::KeyFlags;

        let (tpk1, _) = TPKBuilder::default()
            .add_certification_subkey()
            .generate().unwrap();
        let tsk = tpk1.into_tsk();
        let (tpk2, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .generate().unwrap();

        let sig = tsk.certify_key(&tpk2).unwrap();
        let key = tsk.tpk().select_keys(
            KeyFlags::default().set_certify(true),
            None)[0];

        assert_eq!(
            sig.verify_userid_binding(
                key,
                tpk2.primary(),
                tpk2.userids().next().unwrap().userid()).unwrap(),
            true);
    }

    #[test]
    fn user_ids() {
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .generate().unwrap();

        let userids = tpk
            .userids()
            .map(|binding| binding.userid().userid())
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
            .map(|binding| binding.userid().userid())
            .collect::<Vec<_>>();
        assert_eq!(userids.len(), 1);
        assert_eq!(userids[0], b"Foo");


        let (tsk, _) = TSK::new(Some("test@example.com".into())).unwrap();
        let tpk = tsk.into_tpk();
        let userids = tpk
            .userids()
            .map(|binding| binding.userid().userid())
            .collect::<Vec<_>>();
        assert_eq!(userids.len(), 1);
        assert_eq!(userids[0], b"test@example.com",
                   "User ids: {:?}", userids);
    }
}
