//! Test data for Sequoia.
//!
//! This module includes the test data from `openpgp/tests/data` in a
//! structured way.

use std::fmt;

pub struct Test {
    path: &'static str,
    pub bytes: &'static [u8],
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "openpgp/tests/data/{}", self.path)
    }
}

macro_rules! t {
    ( $path: expr ) => {
        &Test {
            path: $path,
            bytes: include_bytes!(concat!("../tests/data/", $path)),
        }
    }
}

pub const TPKS: &[&Test] = &[
    t!("keys/dennis-simon-anton.pgp"),
    t!("keys/dsa2048-elgamal3072.pgp"),
    t!("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp384.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"),
    t!("keys/testy-new.pgp"),
    t!("keys/testy.pgp"),
    t!("keys/neal.pgp"),
    t!("keys/dkg-sigs-out-of-order.pgp"),
];

pub const TSKS: &[&Test] = &[
    t!("keys/dennis-simon-anton-private.pgp"),
    t!("keys/dsa2048-elgamal3072-private.pgp"),
    t!("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp384-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp521-private.pgp"),
    t!("keys/testy-new-private.pgp"),
    t!("keys/testy-nistp256-private.pgp"),
    t!("keys/testy-nistp384-private.pgp"),
    t!("keys/testy-nistp521-private.pgp"),
    t!("keys/testy-private.pgp"),
];
