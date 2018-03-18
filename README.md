Sequoia PGP
===========

Sequoia is a cool new OpenPGP implementation.  It consists of several
crates, providing both a low-level and a high-level API for dealing
with OpenPGP data.

Building Sequoia
================

If you want to use Sequoia from Rust, you can simply register the
dependency in your `Cargo.toml` file as with any other project.  Note
that we depend on a number of C libraries, which must be present along
with their development packages.

To build Sequoia, you need a Rust toolchain and a few libraries. You can install
the needed libraries with one of the following commands:

Debian:

    ```
    $ sudo apt install git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
    ```

Arch Linux:

    ```
    $ sudo pacman -S git cargo clang make pkg-config nettle openssl capnproto sqlite3 --needed
    ```

Furthermore, we also provide a C API, and bindings to other languages.
We also consider the needs of packagers in times where distribution
support for packaging Rust projects is not yet mature enough to handle
a project like Sequoia.  Therefore, we provide a `Makefile` to
simplify building, testing, and installing Sequoia.

To build Sequoia, simply execute `make`.  To run the test suites,
execute `make test` (or use the `check` alias).  To install Sequoia,
use `make install`.  The latter target honors `PREFIX` and `DESTDIR`.
Finally, to return your source tree to its pristine state, run `make
clean`.
