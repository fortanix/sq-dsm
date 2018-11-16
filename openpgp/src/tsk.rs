use std::borrow::Cow;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use {
    Result,
    TPK,
    packet::Signature,
    packet::Tag,
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
    pub fn new<'a, O: Into<Option<Cow<'a,str>>>>(primary_uid: O)
                                                 -> Result<(TSK, Signature)> {
        use tpk::TPKBuilder;

        let mut key = TPKBuilder::autocrypt(None);

        match primary_uid.into() {
            Some(uid) => { key = key.add_userid(&uid); }
            None => {}
        }

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
