use sequoia_openpgp as openpgp;
use openpgp::serialize::Marshal;

use super::{
    AutocryptHeader,
    Error,
    Result,
};

impl openpgp::serialize::Serialize for AutocryptHeader {}

impl Marshal for AutocryptHeader {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        if self.key.is_none() {
            return Err(Error::InvalidOperation("No key".into()).into());
        }

        for attr in self.attributes.iter() {
            write!(o, "{}={}; ", attr.key, attr.value)?;
        }

        let mut buf = Vec::new();
        self.key.as_ref().unwrap().serialize(&mut buf)?;
        write!(o, "keydata={} ", base64::encode(&buf))?;
        Ok(())
    }
}
