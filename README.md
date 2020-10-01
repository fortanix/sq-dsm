Sequoia PGP
===========

Sequoia is a cool new OpenPGP implementation.  It consists of several
crates, providing both a low-level and a high-level API for dealing
with OpenPGP data.

Low-level API
-------------

The low-level API can be found in the [openpgp](./openpgp) crate.
This crate
aims to provide a complete implementation of OpenPGP as defined by RFC
4880 as well as several extensions (e.g., RFC 6637, which describes
ECC cryptography for OpenPGP, and RFC 4880bis, the draft of the next
OpenPGP standard).  This includes support for unbuffered message
processing.

The [openpgp](./openpgp) crate tries hard to avoid dictating how
OpenPGP should
be used.  This doesn't mean that we don't have opinions about how
OpenPGP should be used in a number of common scenarios (for instance,
message validation).  But, in this crate, we refrain from expressing
those opinions; we expose an opinionated, high-level interface in the
sequoia-core and related crates.  In our opinion, you should generally
use those crates instead of this one.

High-level API
--------------

The high-level API can be found in the [sequoia](.) crate, which
conveniently includes all the other crates.  The high-level API
include a public key store, and network access routines.

Please note that as of this writing the high-level API is very
incomplete.

Command line interface
----------------------

Sequoia includes a simple frontend `sq` (crate [tool](./tool)) that
can be used to experiment with Sequoia and OpenPGP. It is also an
example of how to use various aspects of Sequoia.


Foreign Function Interface
--------------------------

Sequoia provides a C API for use in languages other than Rust.  The
glue code for the low-level interface can be found in the
'sequoia-openpgp-ffi' crate, glue for the high-level interface in the
'sequoia-ffi' crate.

Project status
==============

The low-level API is quite feature-complete and can be used encrypt,
decrypt, sign, and verify messages.  It can create, inspect, and
manipulate OpenPGP data on a very low-level.

The high-level API is effectively non-existent, though there is some
functionality related to key servers and key stores.

The foreign function interface provides a C API for some of Sequoia's
low- and high-level interfaces, but it is incomplete.

There is a mostly feature-complete command-line verification tool for
detached messages called 'sqv'.

LICENSE
=======

Sequoia is licensed under the GNU General Public License version 2 or
any later version.  See the file [LICENSE.txt](LICENSE.txt) or visit
https://www.gnu.org/licenses/gpl-2.0.html for details.

Using Sequoia
=============

If you want to use Sequoia from Rust, you can simply register the
dependency in your `Cargo.toml` file as with any other project.  Note
that we depend on a number of C libraries, which must be present along
with their development packages.

Besides being a Rust crate, we also provide a C API, and bindings to
other languages.

Building Sequoia
================

Using cargo
-----------

To build all Sequoia components, simply execute `cargo build
[--release] --all`.  Individual components may be built independently,
e.g. to build `sq`, run `cargo build [--release] -p sequoia-tool`, or
build `sequoia-openpgp-ffi` to build a shared object with the C API.

Using the Makefile
------------------

We also consider the needs of packagers in times
where distribution support for packaging Rust projects is not yet
mature enough to handle a project like Sequoia.  Therefore, we provide
a `Makefile` to simplify building, testing, and installing Sequoia.

To build Sequoia, simply execute `make`.  To run the test suites,
execute `make test` (or use the `check` alias).  To install Sequoia,
use `make install`.  The latter target honors `PREFIX` and `DESTDIR`.
Finally, to return your source tree to its pristine state, run `make
clean`.

You can specify subdirectories to build individual modules, e.g. use
`make -Copenpgp-ffi install` to only install the shared object with
the C API.

**Note:** By default the Python FFI bindings are also built. To skip
these add `PYTHON=disable` to all `make` invocations. E.g. `make
PYTHON=disable`.

To build Sequoia, you need at least Rust 1.34 and a few libraries,
notably the Nettle cryptographic library version 3.4.1 or up.  Please
see below for OS-specific commands to install the needed libraries:

### Debian

```shell
$ sudo apt install git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
```

Notes:

  - You need at least rustc version 1.34.  The version in Debian 9
    (Stretch) is too old.  The version from Debian 10 (Buster) works
    fine.
  - The version of Nettle in Debian 9 (Stretch), is too old.  Instead,
    you need at least version 3.4.1, which is available from Debian 10
    (Buster).

### Arch Linux

```shell
$ sudo pacman -S git cargo clang make pkg-config nettle openssl capnproto sqlite3 --needed
```

### Fedora

```shell
$ sudo dnf install git rustc cargo clang make pkg-config nettle-devel openssl-devel capnproto sqlite-devel
```

### macOS (Mojave), using MacPorts

```shell
$ sudo port install cargo rust capnproto nettle pkgconfig coreutils
```

### Windows

Please make sure to preserve line-endings when cloning the Sequoia
repository.  The relevant git option is `core.autocrlf` which must be
set to `false`.

#### MSYS2
You can install the needed libraries with the following command:
```shell
$ pacboy -S base-devel toolchain:x clang:x bzip2:x nettle:x sqlite3:x capnproto:x
```

Due to Gitlab's Windows Shared Runners being somewhat slow, we only run them
automatically for MRs, which contain `windows` in the branch name. Please name
your branch accordingly when contributing a patch which might affect Windows.

Bindings
--------

### Python

The FFI crate contains Python bindings.  To disable building, testing,
and installing the Python bindings, use `make PYTHON=disable`.

To build the Python bindings, you will need the Python headers,
setuptools, cffi, and pytest for Python3.

#### Debian

```shell
$ sudo apt install python3-dev python3-setuptools python3-cffi python3-pytest
```

#### Fedora

```shell
$ sudo dnf install python3-devel python3-setuptools python3-cffi python3-pytest
```

#### macOS (Mojave), using MacPorts

```shell
$ sudo port install py37-setuptools
```

Getting help
============

Sequoia's documentation is hosted here: https://docs.sequoia-pgp.org/

The [guide](./guide) is hosted here: https://sequoia-pgp.org/guide/

You can join our mailing list by sending a mail to
devel-subscribe@sequoia-pgp.org.

You can talk to us using IRC on freenode in #sequoia.
