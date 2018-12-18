Describes how to create a simple Rust application using Sequoia.

# Build dependencies

First of all, you need Rust, and a few libraries that we depend upon.
On Debian-like systems, the required packages can be installed using
the following command.  As of this writing, this works fine on Debian
10 (Buster).  You can use Debian 9 (Stretch), but you need to pull
`rustc`, `cargo`, and `nettle-dev` from testing.

```text
# apt install git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
```

# Creating a new project

If are starting from scratch, you need to create a new crate:

```text
$ cargo new --bin example
     Created binary (application) `example` project
$ cd example
```

Now add Sequoia to the `[dependencies]` section in `Cargo.toml`:

```toml
sequoia-openpgp = "0.3"
```

If you want to use the bleeding edge, you can instead refer to the
version in git:

```toml
sequoia-openpgp = { git = "https://gitlab.com/sequoia-pgp/sequoia.git" }
```

To build and run your application, do:

```sh
$ cargo run
```

On the first run, cargo will download and build Sequoia and all
dependencies.  When finished, nothing really happens because we have
not populated `main` yet.  Let's do that!  Open `src/main.rs` with
your favorite editor, and enter:

```
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
```

Running the application now prints a friendly message to stdout.

A word on the `armored` macro.  We will use this macro in this guide
to inline OpenPGP data into the source code.  Sequoia includes filters
for ASCII armored data.  You can use these filters to read armored
data from any `Read`er, or write armored data to any `Write`r.  The
`armored` macro does the same for string literals.  In order to use
this macro, you need to use `#[macro_use]` when importing the
`openpgp` crate.

# Building the Sequoia tool

Sequoia includes a simple frontend `sq` that can be used to experiment
with Sequoia and OpenPGP.  The documentation for this tool is
[here](../../sq/index.html).  It is also an example of
how to use various aspects of Sequoia.  Clone Sequoia and build the
tool:

```sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia.git
...
$ cd sequoia
$ cargo build -p sequoia-tool
...
$ target/debug/sq
sq 0.1.0
Sequoia is an implementation of OpenPGP.  This is a command-line frontend.
...
```
