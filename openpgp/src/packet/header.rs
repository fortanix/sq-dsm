//! OpenPGP Header.

use {
    BodyLength,
};
use packet::ctb::CTB;

/// An OpenPGP packet's header.
#[derive(Clone, Debug)]
pub struct Header {
    /// The packet's CTB.
    pub ctb: CTB,
    /// The packet's length.
    pub length: BodyLength,
}
