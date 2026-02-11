#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    parse::Parse,
};

fuzz_target!(|data: &[u8]| -> Corpus {
    match Cert::from_bytes(data) {
        Ok(_) => Corpus::Keep,
        Err(_) => Corpus::Reject,
    }
});
