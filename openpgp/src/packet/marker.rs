use quickcheck::{Arbitrary, Gen};

use crate::packet;
use crate::Packet;

/// Holds a Marker packet.
///
/// See [Section 5.8 of RFC 4880] for details.
///
///   [Section 5.8 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.8
#[derive(Clone, Debug)]
pub struct Marker {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
}

impl PartialEq for Marker {
    fn eq(&self, _other: &Marker) -> bool {
        true
    }
}

impl Eq for Marker {}

impl std::hash::Hash for Marker {
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {
    }
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
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    #[test]
    fn roundtrip() {
        let p = Marker::default();
        let q = Marker::from_bytes(&p.to_vec().unwrap()).unwrap();
        assert_eq!(p, q);
    }
}
