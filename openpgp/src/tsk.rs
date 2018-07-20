use {
    Result,
    TPK,
    Tag,
};
use serialize::{
    Serialize,
    SerializeKey,
};
use std::io;

pub struct TSK {
    key: TPK,
}

impl TSK {
    pub(crate) fn from_tpk(tpk: TPK) -> TSK {
        TSK{ key: tpk }
    }

    pub fn new(uid: &str) -> Result<TSK> {
        let key = TPK::new(uid)?;

        Ok(TSK::from_tpk(key))
    }

    pub fn public_keys<'a>(&'a self) -> &'a TPK {
        &self.key
    }

    /// Serializes the TSK.
    pub fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        self.key.primary.serialize(o, Tag::SecretKey)?;

        for u in self.key.userids() {
            u.userid().serialize(o)?;
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for u in self.key.user_attributes() {
            u.user_attribute().serialize(o)?;
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for k in self.key.subkeys() {
            k.subkey().serialize(o, Tag::SecretSubkey)?;
            for s in k.selfsigs() {
                s.serialize(o)?;
            }
            for s in k.certifications() {
                s.serialize(o)?;
            }
        }
        Ok(())
    }

    //pub fn decrypt(&self, pkg: &PKESK) -> Result<Box<[u8]>> {
    //    unimplemented!()
    //}

    //pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
    //    unimplemented!()
    //}
}
