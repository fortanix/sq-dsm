use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::{
    Packet,
    Result,
    packet,
};

/// Holds a Padding packet.
///
/// Padding packets are used to obscure the size of cryptographic
/// artifacts.
///
/// See [Padding Packet] for details.
///
///   [Padding Packet]: https://www.rfc-editor.org/rfc/rfc9580.html#padding-packet
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Padding {
    pub(crate) common: packet::Common,
    value: Vec<u8>,
}

assert_send_and_sync!(Padding);

impl From<Vec<u8>> for Padding {
    fn from(u: Vec<u8>) -> Self {
        Padding {
            common: Default::default(),
            value: u,
        }
    }
}

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let padding = String::from_utf8_lossy(&self.value[..]);
        write!(f, "{}", padding)
    }
}

impl fmt::Debug for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Padding {{ {} bytes }}", self.value.len())
    }
}

impl Padding {
    /// Creates a new Padding packet of the given size.
    ///
    /// Note that this is the net size, packet framing (CTB and packet
    /// length) will come on top.
    pub fn new(size: usize) -> Result<Padding> {
        let mut v = vec![0; size];
        crate::crypto::random(&mut v)?;
        Ok(v.into())
    }

    /// Gets the padding packet's value.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl From<Padding> for Packet {
    fn from(s: Padding) -> Self {
        Packet::Padding(s)
    }
}

#[cfg(test)]
impl Arbitrary for Padding {
    fn arbitrary(g: &mut Gen) -> Self {
        Vec::<u8>::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip(p: Padding) -> bool {
            let q = Padding::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }
}
