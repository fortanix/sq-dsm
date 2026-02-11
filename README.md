sq-dsm
======

This fork of [Sequoia-PGP][Sequoia] leverages
[sdkms-client-rust][sdkms-client-rust] to perform OpenPGP operations with keys
stored in the [Fortanix Data Security Manager][DSM], adding options to the
existing CLI Sequoia frontend, `sq`.

### Motivation

Sequoia-PGP defines the [Decryptor][sequoia::Decryptor] and
[Signer][sequoia::Signer] traits for low-level cryptographic operations
with secret key material, and abstracts over these traits for PGP formatting.
This fork implements Decryptor and Signer for secrets stored inside
Fortanix DSM, enabling the production of PGP material without the need to
export private keys.

### Additional requirements

Install requirements for [rust-mbedtls][rust-mbedtls]. The following
variables need to be set in order to communicate with DSM.

- `FORTANIX_API_ENDPOINT`, your DSM API endpoint,
- `FORTANIX_API_KEY`, your app's API key. It overrides `FORTANIX_PKCS12_ID`.
- `FORTANIX_PKCS12_ID`, the absolute path of a PKCS12 identity file, for
  certificate-based authentication. Given a PKCS8 pair `private.key` and
  `public.crt`, the public certificate needs to be configured in DSM for your
  app, and the PKCS12 file can be generated with e.g.
  ```
  openssl pkcs12 -export -out identity.pfx -inkey private.key -in public.crt
  ```
  If a password is set for the PKCS12 file, then `sq-dsm` will ask for it on
  each key usage (which can happen several times on one PGP operation), unless
  the `FORTANIX_PKCS12_PASSPHRASE` environment variable is set (see below).
- `FORTANIX_PKCS12_PASSPHRASE`, the passphrase to unlock the identity file
  generated above. If the password is incorrect, `sq-dsm` will ask for it on
  each operation.
- `FORTANIX_APP_UUID`, the UUID of your DSM app, for certificate-based
  authentication (e.g., this environment variable is used together with
  `FORTANIX_PKCS12_ID`).

### Example usage of added options

In the following example, Alice holds a PGP key whose secrets are stored in
DSM, and Bob and Charlie hold regular PGP keys.

1. Generate a DSM key for Alice, and local keys for Bob and Charlie
```
$  sq key generate --dsm-key="alice" --cipher-suite="nistp521" --userid="Alice <alice@example.com>"
$  sq key generate --cipher-suite="rsa3k" --userid="Bob <bob@example.com>" --export="bob.asc"
$  sq key generate --userid="Charlie <charlie@example.com>" --export="charlie.asc"
```

2. Recover Alice's Transferable Public Key (TPK)
```
$ sq key extract-cert --dsm-key="alice" > alice.asc
```

3. Create a file, sign it with Alices's key, and verify it
```
$ echo "Hello, World!" > msg.txt

$ sq sign --dsm-key="alice" msg.txt > msg.txt.signed

$ sq verify --signer-cert=alice.asc msg.txt.signed
Good signature from B4C961DE2204FD02
Hello, World!
1 good signature.
```

4. Encrypt a file to Alice, signed by Bob, and decrypt it
```
$ sq encrypt --recipient-cert=alice.asc --signer-key=bob.asc msg.txt > to_alice.asc
$ sq decrypt --dsm-key="alice" --signer-cert=bob.asc to_alice.asc
Encrypted using AES with 256-bit key
Compressed using ZIP
Good signature from DC4358B3EA20F2C6
Hello, World!
1 good signature.
```

5. Encrypt a file to Charlie, signed by both Alice and Bob, and decrypt it
```
$ sq encrypt --recipient-cert=charlie.asc --signer-dsm-key=alice --signer-key=bob.asc msg.txt > to_charlie.asc
$ sq decrypt --recipient-key=charlie.asc --signer-cert=alice.asc --signer-cert=bob.asc to_charlie.asc
Encrypted using AES with 256-bit key
Compressed using ZIP
Good signature from B4C961DE2204FD02
Good signature from DC4358B3EA20F2C6
Hello, World!
2 good signatures.
```


[rust-mbedtls]: https://github.com/fortanix/rust-mbedtls
[Sequoia]: https://sequoia-pgp.org/
[sequoia::Signer]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/trait.Signer.html
[sequoia::Decryptor]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/trait.Decryptor.html
[sdkms-client-rust]: https://github.com/fortanix/sdkms-client-rust
[DSM]: https://fortanix.com/products/data-security-manager

--------------

Sequoia PGP
===========

Sequoia is a complete implementation of OpenPGP as defined by [RFC
9580] as well as the deprecated OpenPGP as defined by [RFC 4880], and
various related standards.

OpenPGP is a standard by the IETF.  It was derived from the PGP
software, which was created by Phil Zimmermann in 1991.

[RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
[RFC 4880]: https://tools.ietf.org/html/rfc4880

Sequoia consists of several crates, providing both a low-level and a
high-level API for dealing with OpenPGP data.

Low-level API
-------------

The low-level API can be found in the [openpgp](./openpgp) crate.
This crate aims to provide a complete implementation of OpenPGP as
defined by [RFC 9580] as well as the deprecated OpenPGP as defined by
[RFC 4880].  This includes support for unbuffered message processing.

The [openpgp](./openpgp) crate tries hard to avoid dictating how
OpenPGP should be used.  This doesn't mean that we don't have opinions
about how OpenPGP should be used in a number of common scenarios (for
instance, message validation).

Mid-level API
-------------

Sequoia's mid-level API is implemented in various crates.  For
historical reasons, some are maintained in this repository, and some
are maintained outside of this repository.  These are the most
important crates:

  - [sequoia-cert-store](http://docs.rs/sequoia-cert-store): A store
    for certificates.
  - [sequoia-keystore](http://docs.rs/sequoia-keystore): A store for
    secret keys.
  - [sequoia-wot](http://docs.rs/sequoia-wot): An implementation of
    the Web-of-Trust, a PKI engine.
  - [sequoia-policy-config](http://docs.rs/sequoia-policy-config):
    Loads cryptographic policies from files.
  - [sequoia-net](./net): Network services for OpenPGP.
  - [sequoia-ipc](./ipc): Low-level IPC services for Sequoia and
    GnuPG.
  - [sequoia-autocrypt](./autocrypt): Low-level Autocrypt support.

High-level API
--------------

As of this writing, we still don't have a single, simple, easy to use
interface for Sequoia.  This is something we want to work on in the
near term.  The plan is to extract the functionality from `sq` and put
it into a crate which will become the high-level interface.

We maintain a [SOP] implementation called [sequoia-sop].  SOP is a
high level interface, but has a very narrow scope.

[SOP]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/
[sequoia-sop]: http://docs.rs/sequoia-sop

Command line interface
----------------------

We maintain `sq`, a command line interface use OpenPGP conveniently
from the command line.  See the [sq user documentation] for
instructions, or browse the [manual pages].  `sq` is packaged for most
Linux distributions and should be easy to install.

[sq user documentation]: https://book.sequoia-pgp.org
[manual pages]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/

We also maintain a minimalist command-line verification tool for
detached signatures called ['sqv'].

['sqv']: https://gitlab.com/sequoia-pgp/sequoia-sqv
 The foreign function interface provides a C API for some of Sequoia's
low- and high-level interfaces, but it is incomplete.

Sequoia for GnuPG users
-----------------------

The Sequoia crates and `sq` provide good compatibility with existing
GnuPG installations.  For example, `sq` will discover all certificates
in GnuPG's keyrings, and can make of secret keys managed by
`gpg-agent`, all without additional configuration.

For anyone directly or indirectly using GnuPG who wants to migrate to
Sequoia, there is a re-implementation and drop-in replacement of `gpg`
and `gpgv` called the [Sequoia Chameleon] (or just `gpg-sq` and
`gpgv-sq`).

[Sequoia Chameleon]: https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg

LICENSE
=======

Sequoia is licensed under the GNU Library General Public License
version 2 or any later version.  See the file
[LICENSE.txt](LICENSE.txt) or visit
https://www.gnu.org/licenses/lgpl-2.0.html for details.

Using Sequoia
=============

If you want to use Sequoia from Rust in a binary crate, you can simply
register the dependency in your `Cargo.toml` file as with any other
project.  Please see [this guide] on how to use Sequoia in a library
crate, or how to control the cryptographic backend used by Sequoia.

```toml
sequoia-openpgp = "*"
```

Note that we depend on a number of C libraries, which must be present
along with their development packages. See **Requirements** section
below.

Besides being a Rust crate, we also provide a C API, and bindings to
other languages, see **Bindings**.

[this guide]: openpgp/README.md#feature-flags

Features
--------

Sequoia is currently supported on a variety of platforms.

### Cryptography

By default it uses the Nettle cryptographic library (version 3.9.1 or
up) but it can be used with different cryptographic backends. At the
time of writing, it also supports the native Windows [Cryptographic
API: Next Generation (CNG)].

Various backends can be enabled via Cargo features,
e.g. `crypto-nettle` or `crypto-cng` and exactly one can be enabled at
a time.

Currently, the `crypto-nettle` feature is enabled by default -
regardless of the operating system used. If you choose to enable a
different backend, please make sure to disable the default first.

See [openpgp/README.md#features-flags] for more information.

Building Sequoia
================

Using Cargo
-----------

To build all Sequoia components, simply execute `cargo build
[--release] --all`.  Individual components may be built independently,
e.g. to build `sq`, run `cargo build [--release] -p sequoia-sq`, or
build `sequoia-openpgp-ffi` to build a shared object with the C API.

## Requirements and MSRV

The minimum supported Rust version (MSRV) is 1.67.  Sequoia aims to always be
compatible with the version included in [Debian testing], the MSRV follows what
is available there.  Increasing the MSRV will be accompanied by a raise in
the minor version of all crates.

[Debian testing]: https://tracker.debian.org/pkg/rustc

Building Sequoia requires a few libraries, notably the Nettle cryptographic library
version 3.9.1 or up.  Please see below for OS-specific commands to install the
needed libraries:

### Debian

```shell
# apt install cargo clang git nettle-dev pkg-config libssl-dev
```

Notes:

  - You need at least `rustc` version 1.79.  The version of Rust
    included in Debian 13 (trixie) is fine.  You can use [rustup] if
    your distribution only includes an older Rust version.
  - You need at least Nettle 3.9.1.  Debian 13 (trixie) and up is
    fine.
  - `libssl-dev` is only required by the `sequoia-net` crate and
    crates depending on it (`sq`).

[rustup]: https://rustup.rs/

### Arch Linux

```shell
# pacman -S clang git pkgconf rustup --needed
```

### Fedora

```shell
# dnf install cargo clang git nettle-devel openssl-devel
```

Notes:

  - `openssl-devel` is only required by the `sequoia-net` crate and
    crates depending on it (`sq`).

### NixOS

Development environment for use with `nix-shell` or `direnv`:
<details>
  <summary>
    `shell.nix`
  </summary>

```nix
let
  oxalica_overlay = import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
  nixpkgs = import <nixpkgs> { overlays = [ oxalica_overlay ]; };
  rust_channel = nixpkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain;
in with nixpkgs;
pkgs.mkShell {
  buildInputs = [
    nettle
    openssl
  ];

  nativeBuildInputs = [
    (rust_channel.override{
        extensions = [ "rust-src" "rust-std" ];
    })

    llvmPackages.clang
    pkgconfig

    # tools
    codespell
  ];

  RUST_BACKTRACE = 1;

  # compilation of -sys packages requires manually setting LIBCLANG_PATH
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
```

</details>


### macOS

#### MacPorts

```shell
$ sudo port install cargo nettle pkgconfig
```

#### Brew

```shell
$ brew install rust nettle
```

### Windows

Please make sure to preserve line-endings when cloning the Sequoia
repository.  The relevant git option is `core.autocrlf` which must be
set to `false`.

Due to Windows Runners being somewhat slow, we only run them
automatically for MRs, which contain `windows` in the branch
name. Please name your branch accordingly when contributing a patch
which might affect Windows.

#### CNG

On Windows Sequoia PGP can use one of several cryptographic backends.
The recommended one is Windows Cryptography API (CNG) as it doesn't
require any additional dependencies.  The standard tooling required to
build native dependencies ([Visual Studio Build Tools][]) is still
needed.

[Visual Studio Build Tools]: https://visualstudio.microsoft.com/downloads?q=build+tools

When building, make sure to disable default features (to disable
Nettle) and enable the CNG via `crypto-cng` Cargo feature:

```bash
$ cargo build --no-default-features --features net,crypto-cng,compression
```

#### Nettle

It is also possible to use Sequoia's default backend (Nettle) on
Windows through [MSYS2][].

[MSYS2]: https://www.msys2.org

You can install the needed libraries with the following command:

```shell
$ pacman -S mingw-w64-x86_64-{bzip2,clang,gcc,pkg-config,nettle}
```

#### Other

MSYS2 can also be used to build Sequoia with the Windows-native CNG
backend.  The list of packages is the same as for Nettle with the
exception of `mingw-w64-x86_64-nettle` which is not needed.  Build
command is the same as for the CNG backend.

Sequoia PGP can also be built for 32-bit Windows.  See
`.gitlab-ci.yml` for detailed example.

Additionally, the experimental Rust backend can also be used on
Windows. See the `sequoia-openpgp` crate's documentation for details.

Getting help
============

Sequoia's documentation is hosted here: https://docs.sequoia-pgp.org/

You can join our mailing list by sending a mail to
devel-subscribe@lists.sequoia-pgp.org.

You can talk to us using IRC on [OFTC](https://www.oftc.net/) in `#sequoia`.

Reporting bugs
==============

Please report bug and feature requests to [our bugtracker].  If you
find a security vulnerability, please refer to our [security
vulnerability guide].

  [our bugtracker]: https://gitlab.com/sequoia-pgp/sequoia/issues
  [security vulnerability guide]: https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/doc/security-vulnerabilities.md
