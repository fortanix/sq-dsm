//! User Attribute packets and subpackets.
//!
//! See [Section 5.12 of RFC 4880] for details.
//!
//!   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12

use std::fmt;
use quickcheck::{Arbitrary, Gen};
use rand::Rng;

use buffered_reader::BufferedReader;

use Error;
use Result;
use packet::{
    self,
    BodyLength,
};
use Packet;
use serialize::Serialize;
use serialize::SerializeInto;

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
    ///
    /// Note: a valid UserAttribute has at least one subpacket.
    pub fn new(subpackets: &[Subpacket]) -> Result<Self> {
        let mut value = Vec::with_capacity(
            subpackets.iter().fold(0, |l, s| l + s.serialized_len()));
        for s in subpackets {
            s.serialize(&mut value)?
        }

        Ok(UserAttribute {
            common: Default::default(),
            value
        })
    }

    /// Gets the user attribute packet's raw, unparsed value.
    ///
    /// Most likely you will want to use [`subpackets()`] to iterate
    /// over the subpackets.
    ///
    /// [`subpackets()`]: #method.subpackets
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Gets a mutable reference to the user attribute packet's raw
    /// value.
    pub fn value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.value
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
        UserAttribute::new(
            &(0..g.gen_range(1, 10))
                .map(|_| Subpacket::arbitrary(g))
                .collect::<Vec<_>>()[..]).unwrap()
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

impl Arbitrary for Subpacket {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 2) {
            0 => Subpacket::Image(Image::arbitrary(g)),
            1 => Subpacket::Unknown(
                g.gen_range(1, 256) as u8,
                Vec::<u8>::arbitrary(g).into_boxed_slice()
            ),
            _ => unreachable!(),
        }
    }
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

impl Arbitrary for Image {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 3) {
            0 =>
                Image::JPEG(
                    Vec::<u8>::arbitrary(g).into_boxed_slice()
                ),
            1 =>
                Image::Unknown(
                    g.gen_range(1, 100),
                    Vec::<u8>::arbitrary(g).into_boxed_slice()
                ),
            2 =>
                Image::Private(
                    g.gen_range(100, 111),
                    Vec::<u8>::arbitrary(g).into_boxed_slice()
                ),
            _ => unreachable!(),
        }
    }
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
        use Packet;
        let p = Packet::from_bytes(b"
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
        let subpackets: Vec<_> = if let Packet::UserAttribute(ua) = p {
            ua.subpackets().collect()
        } else {
            panic!("Expected an UserAttribute, got: {:?}", p);
        };
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
