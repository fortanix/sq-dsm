How to update the MSRV

1. set the new `rust-version` in `<crate>/Cargo.toml` (or all `<crate>/Cargo.toml`s)
1. set the new version in `clippy.toml`
1. run `cargo build` and check if everything still works
1. run `cargo clippy` and apply the new lints, or ignore them in `.cargo/config`
1. update the readmes
  - README.md and openpgp/README.md, possibly more in the future
  - grep for the version number, e.g. "1.60.0"
1. update CI
  - some jobs require explicit installation of the correct toolchain, grep for
    the version number to find them.
