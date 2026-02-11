This crate aims to provide a complete implementation of OpenPGP as
defined by [RFC 9580] as well as the deprecated OpenPGP as defined
by [RFC 4880].  OpenPGP is a standard by the IETF.  It was derived
from the PGP software, which was created by Phil Zimmermann in
1991.

This crate also includes support for unbuffered message
processing.

A few features that the OpenPGP community considers to be
deprecated (e.g., version 3 compatibility) have been left out.  We
have also updated some OpenPGP defaults to avoid foot guns (e.g.,
we selected modern algorithm defaults).  If some functionality is
missing, please file a bug report.

A non-goal of this crate is support for any sort of high-level,
bolted-on functionality.  For instance, [RFC 9580] does not define
trust models, such as the web of trust, direct trust, or TOFU.
Neither does this crate.  [RFC 9580] does provide some mechanisms
for creating trust models (specifically, UserID certifications),
and this crate does expose those mechanisms.

We also try hard to avoid dictating how OpenPGP should be used.
This doesn't mean that we don't have opinions about how OpenPGP
should be used in a number of common scenarios (for instance,
message validation).  But, in this crate, we refrain from
expressing those opinions; we will expose an opinionated,
high-level interface in the future.  In order to figure out the
most appropriate high-level interfaces, we look at existing users.
If you are using Sequoia, please get in contact so that we can
learn from your use cases, discuss your opinions, and develop a
high-level interface based on these experiences in the future.

Despite —or maybe because of— its unopinionated nature we found
it easy to develop opinionated OpenPGP software based on Sequoia.

[RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
[RFC 4880]: https://tools.ietf.org/html/rfc4880

# Experimental Features

This crate may implement extensions where the standardization
effort is still ongoing.  These experimental features are marked
as such in the documentation.  We invite you to experiment with
them, but please do expect the semantics and possibly even the
wire format to evolve.

# Security Notes

## Secrets Leaked to the Heap or Stack

Sequoia makes a best effort to ensure that secrets are wiped when they
are freed.  This is not easy as data is often copied by helper
functions, the crypto library, or the compiler, and those copies are
not wiped when freed.

Sequoia includes some tests to detect leaks.  You can run these as
follows:

```
cargo test --no-default-features --features sequoia-openpgp/crypto-openssl -- leak_tests
```

We consider these leaks to be a low severity security issue, because
they are hard to exploit in practice.  Specifically, they rely on a
[heartbleed-style attack](https://en.wikipedia.org/wiki/Heartbleed).

Leaks are also time intensive to debug.  And, they are often
non-deterministic, depend on the version of the Rust compiler that you
use, the version of the crypto library that you are using, and how it
was compiled.  As such, we are unlikely to actively fix them.  That
said, we appreciate reports with a test similar to the ones already
present in the leak detector to help catalog the leaks.  See
[`openpgp/tests/secret-leak-dector.rs`] for details.  We are even more
thankful for fixes.  That file also contains instructions how to get
started debugging leaks.

  [`openpgp/tests/secret-leak-dector.rs`]: https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/openpgp/tests/secret-leak-detector.rs

If you are worried about secrets being leaks to your process's heap,
one option is to change your program's architecture.  Instead of
having a single protection domain, run the sensitive operation in a
separate process and use RPC mechanism to communicate.  This will
prevent a heartbleed-style bug in the primary process from reading out
any secrets.  Further, you can periodically restart the child process
to force the operating system to wipe any secret's in that process's
memory.

# Feature flags

This crate uses *features* to enable or disable optional
functionality.  You can tweak the features in your `Cargo.toml` file,
like so:

```toml
sequoia-openpgp = { version = "*", default-features = false, features = ["compression", ...] }
```

By default, Sequoia is built using Nettle as cryptographic backend
with all compression algorithms enabled.  Using the default features
is only appropriate for leaf crates, see [this section].

[this section]: #how-to-select-crypto-backends-in-crates

Note that if you use `default-features = false`, you need to
explicitly enable a crypto backend, and also enable compression
features.

## Crypto backends

Sequoia supports multiple cryptographic libraries that can be selected
at compile time.  Currently, these libraries are available:

  - The Nettle cryptographic library.  This is the default backend,
    and is selected by the default feature set.  If you use
    `default-features = false`, you need to explicitly include
    the `crypto-nettle` feature to enable it.

  - The OpenSSL backend.  To select this backend, use
    `default-features = false`, and explicitly include the
    `crypto-openssl` feature to enable it.

  - The Botan backend.  To select this backend, use
    `default-features = false`, and explicitly include the
    `crypto-botan` feature to enable it.  `crypto-botan` defaults to
    Botan v3, which was release in April 2023.  Use `crypto-botan2` to
    use v2.

  - The Windows Cryptography API: Next Generation (CNG).  To select
    this backend, use `default-features = false`, and explicitly
    include the `crypto-cng` feature to enable it.  Currently, the CNG
    backend requires at least Windows 10.

  - The RustCrypto crates.  To select this backend, use
    `default-features = false`, and explicitly include the
    `crypto-rust` feature to enable it.  As of this writing, the
    RustCrypto crates are not recommended for general use as they
    cannot offer the same security guarantees as more mature
    cryptographic libraries.

### Experimental and variable-time cryptographic backends

Some cryptographic backends are not yet considered mature enough for
general consumption.  The use of such backends requires explicit
opt-in using the feature flag `allow-experimental-crypto`.

Some cryptographic backends can not guarantee that cryptographic
operations require a constant amount of time.  This may leak secret
keys in some settings.  The use of such backends requires explicit
opt-in using the feature flag `allow-variable-time-crypto`.

### How to select crypto backends in crates

In Rust, [features are unified], and consequently features should be
additive, i.e. it should be safe to enable any combination of
features.  But, this does not hold for crypto backends, because
exactly one cryptographic backend has to be selected in order to
compile Sequoia.

[features are unified]: https://doc.rust-lang.org/cargo/reference/features.html#feature-unification

To accommodate this, we came up with the following rule: in any
project using Sequoia, exactly one crate may select the cryptographic
backend, and that crate is the leaf crate (i.e. the binary or cdylib
crate).  Any non-leaf, library crate must refrain from selecting a
crypto backend, including the default one, by disabling the default
features.

To recap, follow these rules depending on what kind of crate you are
developing:

#### Leaf crate

The leaf crate should pick a default backend (you may defer to Sequoia
to pick the default one), but should allow your downstream users to
switch backends:

```toml
# Cargo.toml
[dependencies]
sequoia-openpgp = { version = "*", default-features = false }
# If you need compression features, enable them here:
# sequoia-openpgp = { version = "*", default-features = false, features = ["compression"] }

[features]
# Pick a crypto backend enabled by default (here we defer to Sequoia
# to pick the default):
default = ["sequoia-openpgp/default"]

# .. but allow others to select a different backend, as well
crypto-nettle = ["sequoia-openpgp/crypto-nettle"]
crypto-openssl = ["sequoia-openpgp/crypto-openssl"]
crypto-botan = ["sequoia-openpgp/crypto-botan"]
crypto-botan2 = ["sequoia-openpgp/crypto-botan2"]
crypto-rust = ["sequoia-openpgp/crypto-rust"]
crypto-cng = ["sequoia-openpgp/crypto-cng"]

# Experimental and variable-time cryptographic backend opt-ins
allow-experimental-crypto = ["sequoia-openpgp/allow-experimental-crypto"]
allow-variable-time-crypto = ["sequoia-openpgp/allow-variable-time-crypto"]
```

#### Intermediate crate

Non-leaf crates must not select a cryptographic backend, and must
disable the default features.  Additionally, to make `cargo test` work
without having to select a crypto backend, and to enable `docs.rs` to
build your documentation, do selectively enable crypto backends for
those cases:

```toml
# Cargo.toml
[dependencies]
sequoia-openpgp = { version = "*", default-features = false }
# If you need compression features, enable them here:
# sequoia-openpgp = { version = "*", default-features = false, features = ["compression"] }

# Enables a crypto backend for the tests:
[target.'cfg(not(windows))'.dev-dependencies]
sequoia-openpgp = { version = "1", default-features = false, features = ["crypto-nettle", "__implicit-crypto-backend-for-tests"]  }

# Enables a crypto backend for the tests:
[target.'cfg(windows)'.dev-dependencies]
sequoia-openpgp = { version = "1", default-features = false, features = ["crypto-cng", "__implicit-crypto-backend-for-tests"] }

# Enables a crypto backend for the docs.rs generation:
[package.metadata.docs.rs]
features = ["sequoia-openpgp/default"]
```

## Compression algorithms

Use the `compression` flag to enable support for all compression
algorithms, `compression-deflate` to enable *DEFLATE* and *zlib*
compression support, and `compression-bzip2` to enable *bzip2*
support.

# Compiling to WASM

With the right feature flags, Sequoia can be compiled to WASM.  To do
that, enable the RustCrypto backend, and make sure not to enable
*bzip2* compression support:

```toml
sequoia-openpgp = { version = "*", default-features = false, features = ["crypto-rust", "allow-experimental-crypto", "allow-variable-time-crypto"] }
```

Or, with `compression-deflate` support:

```toml
sequoia-openpgp = { version = "*", default-features = false, features = ["crypto-rust", "allow-experimental-crypto", "allow-variable-time-crypto", "compression-deflate"] }
```

# Minimum Supported Rust Version (MSRV)

`sequoia-openpgp` requires Rust 1.67.
