//! User Attribute packets and subpackets.
//!
//! See [Section 5.12 of RFC 4880] for details.
//!
//!   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12

use std::fmt;
use quickcheck::{Arbitrary, Gen};

use buffered_reader::BufferedReader;

use Error;
use Result;
use packet::{
    self,
    BodyLength,
};
use Packet;

/// Holds a UserAttribute packet.
///
/// See [Section 5.12 of RFC 4880] for details.
///
///   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct UserAttribute {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// The user attribute.
    value: Vec<u8>,
}

impl From<Vec<u8>> for UserAttribute {
    fn from(u: Vec<u8>) -> Self {
        UserAttribute {
            common: Default::default(),
            value: u,
        }
    }
}

impl fmt::Debug for UserAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserAttribute")
            .field("value (bytes)", &self.value.len())
            .finish()
    }
}

impl UserAttribute {
    /// Returns a new `UserAttribute` packet.
    pub fn new() -> UserAttribute {
        UserAttribute {
            common: Default::default(),
            value: Vec::new(),
        }
    }

    /// Gets the user attribute packet's value.
    pub fn user_attribute(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Sets the user attribute packet's value from a byte sequence.
    pub fn set_user_attribute(&mut self, value: &[u8]) -> Vec<u8> {
        ::std::mem::replace(&mut self.value, value.to_vec())
    }

    /// Iterates over the subpackets.
    pub fn subpackets(&self) -> SubpacketIterator {
        SubpacketIterator {
            reader: buffered_reader::Memory::new(&self.value[..]),
        }
    }
}

impl From<UserAttribute> for Packet {
    fn from(s: UserAttribute) -> Self {
        Packet::UserAttribute(s)
    }
}

impl Arbitrary for UserAttribute {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Vec::<u8>::arbitrary(g).into()
    }
}

/// Iterates over subpackets.
pub struct SubpacketIterator<'a> {
    reader: buffered_reader::Memory<'a, ()>,
}

impl<'a> Iterator for SubpacketIterator<'a> {
    type Item = Result<Subpacket>;
    fn next(&mut self) -> Option<Self::Item> {
        let length = match BodyLength::parse_new_format(&mut self.reader) {
            Ok(BodyLength::Full(l)) => l,
            Ok(BodyLength::Partial(_)) | Ok(BodyLength::Indeterminate) =>
                return Some(Err(Error::MalformedPacket(
                    "Partial or Indeterminate length of subpacket".into())
                                .into())),
            Err(e) =>
                if e.kind() == ::std::io::ErrorKind::UnexpectedEof {
                    return None;
                } else {
                    return Some(Err(e.into()));
                },
        };

        let raw = match self.reader.data_consume_hard(length as usize) {
            Ok(r) => &r[..length as usize],
            Err(e) => return Some(Err(e.into())),
        };

        if raw.len() == 0 {
            return Some(Err(Error::MalformedPacket(
                "Subpacket without type octet".into()).into()));
        }

        let typ = raw[0];
        let raw = &raw[1..];
        match typ {
            // Image.
            1 => if raw.len() >= 16 &&
                    &raw[..3] == &[0x10, 0x00, 0x01]
                    && raw[4..16].iter().all(|b| *b == 0)
            {
                let image_kind = raw[3];
                Some(Ok(Subpacket::Image(match image_kind {
                    1 =>
                        Image::JPEG(Vec::from(&raw[16..]).into_boxed_slice()),
                    n @ 100...110 =>
                        Image::Private(
                            n, Vec::from(&raw[16..]).into_boxed_slice()),
                    n =>
                        Image::Unknown(
                            n, Vec::from(&raw[16..]).into_boxed_slice()),
                })))
            } else {
                Some(Err(Error::MalformedPacket(
                    "Malformed image subpacket".into()).into()))
            },
            n =>
                Some(Ok(Subpacket::Unknown(
                    n, Vec::from(raw).into_boxed_slice()))),
        }
    }
}

/// User Attribute subpackets.
///
/// See [Section 5.12 of RFC 4880] for details.
///
///   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subpacket {
    /// Image subpacket.
    ///
    /// See [Section 5.12.1 of RFC 4880] for details.
    ///
    ///   [Section 5.12.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12.1
    Image(Image),
    /// Unknown subpacket.
    Unknown(u8, Box<[u8]>),
}

/// Image subpacket.
///
/// See [Section 5.12.1 of RFC 4880] for details.
///
///   [Section 5.12.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12.1
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Image {
    /// A JPEG image format.
    JPEG(Box<[u8]>),
    /// Private, experimental image format.
    Private(u8, Box<[u8]>),
    /// Unknown image format.
    Unknown(u8, Box<[u8]>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::Parse;
    use serialize::SerializeInto;

    quickcheck! {
        fn roundtrip(p: UserAttribute) -> bool {
            let q = UserAttribute::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn image() {
        let ua = UserAttribute::from_bytes(b"
-----BEGIN PGP ARMORED FILE-----

0cFuwWwBEAABAQAAAAAAAAAAAAAAAP/Y/+AAEEpGSUYAAQEBASwBLAAA//4AE0Ny
ZWF0ZWQgd2l0aCBHSU1Q/9sAQwADAgIDAgIDAwMDBAMDBAUIBQUEBAUKBwcGCAwK
DAwLCgsLDQ4SEA0OEQ4LCxAWEBETFBUVFQwPFxgWFBgSFBUU/9sAQwEDBAQFBAUJ
BQUJFA0LDRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
FBQUFBQUFBQU/8IAEQgAAQABAwERAAIRAQMRAf/EABQAAQAAAAAAAAAAAAAAAAAA
AAj/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAFUn//EABQQAQAA
AAAAAAAAAAAAAAAAAAD/2gAIAQEAAQUCf//EABQRAQAAAAAAAAAAAAAAAAAAAAD/
2gAIAQMBAT8Bf//EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQIBAT8Bf//EABQQ
AQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEABj8Cf//EABQQAQAAAAAAAAAAAAAAAAAA
AAD/2gAIAQEAAT8hf//aAAwDAQACAAMAAAAQn//EABQRAQAAAAAAAAAAAAAAAAAA
AAD/2gAIAQMBAT8Qf//EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQIBAT8Qf//E
ABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAT8Qf//Z
=nUQg
-----END PGP ARMORED FILE-----
").unwrap();
        let subpackets: Vec<_> = ua.subpackets().collect();
        assert_eq!(subpackets.len(), 1);
        if let Ok(Subpacket::Image(Image::JPEG(img))) = &subpackets[0] {
            assert_eq!(img.len(), 539);
            assert_eq!(&img[6..10], b"JFIF");
            assert_eq!(&img[24..41], b"Created with GIMP");
        } else {
            panic!("Expected JPEG, got {:?}", &subpackets[0]);
        }
    }
}
