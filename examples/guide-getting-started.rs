//! https://sequoia-pgp.org/guide/getting-started/

#[macro_use] // For armored!
extern crate sequoia_openpgp as openpgp;
use std::io;

fn main() {
    let mut reader = armored!(
        "-----BEGIN PGP ARMORED FILE-----

         SGVsbG8gd29ybGQhCg==
         =XLsG
         -----END PGP ARMORED FILE-----"
    );

    io::copy(&mut reader, &mut io::stdout()).unwrap();
}
