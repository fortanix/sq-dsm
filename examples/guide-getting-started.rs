//! https://preview.sequoia-pgp.org/guide/getting-started/

#[macro_use] extern crate openpgp;	// For armored!
use openpgp::armor;			// For armored!
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
