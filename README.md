# sq-sdkms

This crate leverages [sdkms-client-rust][sdkms-client-rust] and
[Sequoia-PGP][Sequoia] to perform sensitive OpenPGP operations with keys stored
in the [Fortanix Self-Defending Key-Management System][SDKMS].

## Motivation

Sequoia-PGP defines the [Signer][sequoia::Signer] and
[Decryptor][sequoia::Decryptor] traits for low-level cryptographic operations
with secret key material, and abstracts over these traits for PGP operations.
This crate implements these traits for key material stored inside Fortanix
SDKMS, enabling the production of PGP material and decryption of ciphertexts
without the need to export any secrets.

## CLI

The convenient command-line interface `sq-sdkms` is provided in the
spirit of Sequoia's `sq` and `sqv`. It can be used in combination with
other PGP implementations. For instance, a file can be
encrypted with `gpg` and decrypted with `sq-sdkms`, or signed with `sq-sdkms`
and verified with `sqv` (see [Example usage](#example-usage) below).

The following subcommands are supported. Run `sq-sdkms help` for all possible
commands, flags, and options.

- `sq-sdkms generate-key`: Automatically create secrets with sensible defaults
  inside SDKMS (signing primary and encryption subkey) and form the PGP key
- `sq-sdkms certificate`: For a key created with `sq-sdkms`, retrieve the
  corresponding Transferable Public Key
- `sq-sdkms sign-detached`: Given a file, create a detached signature with the
  PGP key
- `sq-sdkms decrypt`: Decrypt the given PGP message encrypted to this key

PGP operations that do not require secrets (such as verifying a signature) can
be performed with any other PGP implementation, such as `sqv`.

## Building

First, install Sequoia-PGP ([instructions][instructions-sequoia]) and
[rust-mbedtls][rust-mbedtls].

Clone and `cd` to this repository, and build with `cargo build
--release`. This will create the `sq-sdkms` binary in the `target/release`
directory.

### Env variables

The following variables need to be set

- `FORTANIX_API_ENDPOINT`, your SDKMS API endpoint,
- `FORTANIX_API_KEY`, your app's API key.

These variables can also be configured in a .env file and `sq-sdkms` can be ran with the option `--env-file <my .env file>`.

### Example usage

`sq-sdkms` uses `sq`-style subcommands, and is designed to be used in
combination with `sq`, `sqv`, or `gpg`.

First, create a PGP key and store the public certificate in `alice.asc`
```
$ ./sq-sdkms generate-key --key-name="My PGP key" --user-id="Alice Lovelace <alice@fortanix.com>" --armor --output-file="alice.asc"
```
Sign a file with this key
```
$ echo "Hello, World!" > msg.txt
$ ./sq-sdkms sign-detached --key-name="My PGP key" --armor msg.txt > msg.txt.asc
```
Import Alice's key into your `gpg` keyring (optionally, ultimately trust this
key with `gpg --edit-key alice` followed by `trust`)
```
$ gpg --import alice.asc
gpg: key 04F593070A9B5600: public key "Alice Lovelace <alice@fortanix.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Verify the detached signature with `sqv` and `gpg`
```
$ sqv --verbose --keyring alice.asc msg.txt.asc msg.txt
63A0B7D62786CC87DE913A6804F593070A9B5600
1 of 1 signatures are valid (threshold is: 1).

$ gpg --verify msg.txt.asc msg.txt
gpg: Signature made Mon Apr 26 13:38:30 2021 UTC
gpg:                using RSA key 63A0B7D62786CC87DE913A6804F593070A9B5600
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: Good signature from "Alice Lovelace <alice@fortanix.com>" [ultimate]
```

Encrypt the file with `gpg`
```
$ gpg --encrypt -r alice msg.txt
```

Decrypt the file created by `gpg` with `sq-sdkms`:
```
$ ./sq-sdkms decrypt --key-name="My PGP key" msg.txt.gpg
Hello, World!
```

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.

[instructions-sequoia]: https://docs.sequoia-pgp.org/sequoia_guide/chapter_00/index.html
[rust-mbedtls]: https://github.com/fortanix/rust-mbedtls
[Sequoia]: https://sequoia-pgp.org/
[sequoia::Signer]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/trait.Signer.html
[sequoia::Decryptor]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/trait.Decryptor.html
[sdkms-client-rust]: https://github.com/fortanix/sdkms-client-rust
[SDKMS]: https://fortanix.com/products/data-security-manager/sdkms
