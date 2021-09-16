//! Test data for Sequoia.
//!
//! This module includes the test data from `ipc/tests/data` in a
//! structured way.

use std::collections::BTreeMap;

/// Returns the content of the given file below `ipc/tests/data`.
pub fn file(name: &str) -> &'static [u8] {
    lazy_static::lazy_static! {
        static ref FILES: BTreeMap<&'static str, &'static [u8]> = {
            let mut m: BTreeMap<&'static str, &'static [u8]> =
                Default::default();

            macro_rules! add {
                ( $key: expr, $path: expr ) => {
                    m.insert($key, include_bytes!($path))
                }
            }
            include!(concat!(env!("OUT_DIR"), "/tests.index.rs.inc"));

            // Sanity checks.
            assert!(m.contains_key("sexp/rsa-signature.sexp"));
            m
        };
    }

    FILES.get(name).unwrap_or_else(|| panic!("No such file {:?}", name))
}

/// Returns the content of the given file below `ipc/tests/data/keys`.
#[allow(dead_code)]
pub fn key(name: &str) -> &'static [u8] {
    file(&format!("keys/{}", name))
}

/// Returns the content of the given file below `ipc/tests/data/keyboxes`.
pub fn keybox(name: &str) -> &'static [u8] {
    file(&format!("keyboxes/{}", name))
}

/// Returns the content of the given file below `ipc/tests/data/messages`.
#[allow(dead_code)]
pub fn message(name: &str) -> &'static [u8] {
    file(&format!("messages/{}", name))
}
