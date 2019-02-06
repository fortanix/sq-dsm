//! https://sequoia-pgp.org/guide/getting-started/

extern crate sequoia_openpgp as openpgp;
use std::io;

fn main() {
    let mut reader = openpgp::armor::Reader::from_bytes(
       b"-----BEGIN PGP ARMORED FILE-----

         SGVsbG8gd29ybGQhCg==
         =XLsG
         -----END PGP ARMORED FILE-----", None);

    io::copy(&mut reader, &mut io::stdout()).unwrap();
}
