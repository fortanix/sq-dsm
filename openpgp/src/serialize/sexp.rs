use crate::Result;
use crate::serialize::{
    Marshal,
    MarshalInto,
    generic_serialize_into,
};

use crate::crypto::sexp::{Sexp, String_};

impl crate::serialize::Serialize for Sexp {}

impl Marshal for Sexp {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        match self {
            Sexp::String(ref s) => s.serialize(o),
            Sexp::List(ref l) => {
                write!(o, "(")?;
                for sexp in l {
                    sexp.serialize(o)?;
                }
                write!(o, ")")?;
                Ok(())
            },
        }
    }
}

impl crate::serialize::SerializeInto for Sexp {}

impl MarshalInto for Sexp {
    fn serialized_len(&self) -> usize {
        match self {
            Sexp::String(ref s) => s.serialized_len(),
            Sexp::List(ref l) =>
                2 + l.iter().map(|s| s.serialized_len()).sum::<usize>(),
        }
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }
}

impl Marshal for String_ {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        if let Some(display) = self.display_hint() {
            write!(o, "[{}:", display.len())?;
            o.write_all(display)?;
            write!(o, "]")?;
        }
        write!(o, "{}:", self.len())?;
        o.write_all(self)?;
        Ok(())
    }
}

/// Computes the length of the size tag for a given string length.
fn size_tag_len(len: usize) -> usize {
    // Compute log10(self.len()).
    let mut l = len;
    let mut digits = 0;
    while l > 0 {
        l /= 10;
        digits += 1;
    }

    std::cmp::max(1, digits) // 0 takes up 1 char, too.
}

impl MarshalInto for String_ {
    fn serialized_len(&self) -> usize {
        self.display_hint()
            .map(|d| size_tag_len(d.len()) + 3 + d.len()).unwrap_or(0)
            + size_tag_len(self.len()) + 1 + self.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sexp() {
        assert_eq!(
            &Sexp::List(vec![]).to_vec().unwrap(),
            b"()");
        assert_eq!(
            &Sexp::List(vec![Sexp::String(b"hi"[..].into()),
                            Sexp::String(b"ho"[..].into()),
            ]).to_vec().unwrap(),
            b"(2:hi2:ho)");
        assert_eq!(
            &Sexp::List(vec![
                Sexp::String(b"hi"[..].into()),
                Sexp::String(String_::with_display_hint(b"ho".to_vec(),
                                                        b"fancy".to_vec())),
            ]).to_vec().unwrap(),
            b"(2:hi[5:fancy]2:ho)");
        assert_eq!(
            &Sexp::List(vec![
                Sexp::String(b"hi"[..].into()),
                Sexp::List(vec![
                    Sexp::String(b"ha"[..].into()),
                    Sexp::String(b"ho"[..].into()),
                ]),
            ]).to_vec().unwrap(),
            b"(2:hi(2:ha2:ho))");
        assert_eq!(
            &Sexp::List(vec![
                Sexp::String(b"sig-val"[..].into()),
                Sexp::List(vec![
                    Sexp::String(b"rsa"[..].into()),
                    Sexp::List(vec![
                        Sexp::String(b"s"[..].into()),
                        Sexp::String(b"abc"[..].into()),
                    ]),
                ]),
            ]).to_vec().unwrap(),
            b"(7:sig-val(3:rsa(1:s3:abc)))");
    }

    #[test]
    fn string() {
        assert_eq!(&String_::new(b"hi".to_vec()).to_vec().unwrap(),
                   b"2:hi");
        assert_eq!(&String_::with_display_hint(b"hi".to_vec(),
                                               b"fancy".to_vec())
                   .to_vec().unwrap(),
                   b"[5:fancy]2:hi");
    }
}
