use quickcheck::{Arbitrary, Gen};

use packet;
use Packet;

/// Holds a Marker packet.
///
/// See [Section 5.8 of RFC 4880] for details.
///
///   [Section 5.8 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.8
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Marker {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
}

impl Marker {
    pub(crate) const BODY: &'static [u8] = &[0x50, 0x47, 0x50];
}

impl Default for Marker {
    fn default() -> Self {
        Self {
            common: Default::default(),
        }
    }
}

impl From<Marker> for Packet {
    fn from(p: Marker) -> Self {
        Packet::Marker(p)
    }
}

impl Arbitrary for Marker {
    fn arbitrary<G: Gen>(_: &mut G) -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parse::Parse;
    use serialize::SerializeInto;

    #[test]
    fn roundtrip() {
        let p = Marker::default();
        let q = Marker::from_bytes(&p.to_vec().unwrap()).unwrap();
        assert_eq!(p, q);
    }
}
