---
title: "Sequoia-PGP sq"
subtitle: "integration tests, requirements, acceptance criteria"
author: "The Sequoia-PGP project"
template: rust
bindings:
- subplot/sq-subplot.yaml
- lib/files.yaml
- lib/runcmd.yaml
functions:
- subplot/sq-subplot.rs
...

# Introduction

The [Sequoia-PGP][] project is an implementation of the [OpenPGP][]
standard for encryption and digital signatures. Sequoia itself is a
library for the Rust programming language, as well as the `sq` command
line tool for people to use directly. This document captures the
requirements and acceptance criteria for the `sq` tool and how they
are verified, and at the same time acts as an integration test for the
tool.

[Sequoia-PGP]: https://sequoia-pgp.org/
[OpenPGP]: https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP

## Using Subplot and this document

The acceptance criteria and requirements are explained in prose and
when they can be verified in an automated way, that is done using
_test scenarios_. Both the prose and the scenarios are meant to be
understood and agreed to by all stakeholders in the project.

The [Subplot][] tool is used to render this document into
human-readable form (HTML or PDF), and to generate a test program that
executes the scenarios and checks they all pass.

To achieve this, run the following commands:

~~~sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia.git
$ cd sequoia/sq
$ subplot docgen sq-subplot.md -o sq-subplot.html
$ subplot docgen sq-subplot.md -o sq-subplot.pdf
$ cargo test
~~~

If you only care about generating and running tests, you only need to
run `cargo test`. All the dependencies for that are automatically
handled via `Cargo.toml`.

To generate typeset documents (HTML and PDF), you need the following
software installed:

* [Subplot][], via cargo install or a Debian package (see its website)
* Pandoc
* Parts of TeX Live (for PDF)
* Graphviz

On a Debian system, that means the following packages:

> `subplot pandoc pandoc-citeproc lmodern librsvg2-bin graphviz
> texlive-latex-base texlive-latex-recommended
> texlive-fonts-recommended plantuml`

[Subplot]: https://subplot.liw.fi/

# Smoke test

_Requirement: We must be able to invoke `sq` at all._

This scenario verifies that we can run `sq` in the simplest possible
case: we ask the program for its version. If this works, then we know
that the executable program exists, can be invoked, and at least some
of its command line parsing code works. If this scenario doesn't work,
then we can't expect anything else to work either.

~~~scenario
given an installed sq
when I run sq --version
then exit code is 0
then stdout matches regex ^sq \d+\.\d+\.\d+ .*$
~~~

# Generate a key

_Requirement: We must be able to generate new encryption keys and
corresponding certificates._

This scenario generates a new key with `sq` and inspects it to see if
it looks at least vaguely correct. Note that in this scenario we don't
verify that the key works, other scenarios take care of that.

~~~scenario
given an installed sq
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq inspect tomjon.pgp
then stdout contains "Tomjon"
~~~

We also extract a certificate ("public key") from the key, to be
shared with others.

~~~scenario
when I run sq key extract-cert -o cert.pgp tomjon.pgp
then file cert.pgp contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file cert.pgp contains "Comment: Tomjon"
then file cert.pgp contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~

# Encrypt and decrypt a file using public keys

_Requirement: We must be able to encrypt a file using a certificate,
and then decrypt it using the corresponding key._

This scenario creates a plain text file, generates a key, encrypts and
then decrypts the file. The resulting output must be identical to the
original plain text input file. This is a very simplistic scenario and
does not even try to test harder cases (binary files, very large
files, etc).

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq key extract-cert -o cert.pgp tomjon.pgp
when I run sq encrypt -o e.pgp --recipient-cert cert.pgp hello.txt
when I run sq decrypt -o output.txt --recipient-key tomjon.pgp e.pgp
then files hello.txt and output.txt match
~~~

# Sign a document and verify the signature

_Requirement: We must be able to sign a document, to prove it comes
from us. We must be able to verify a signature on a document._

We break this into three scenarios. One that uses a binary signature,
one with textual cleartext signature, and one with a detached
signature.

## Binary signature

This scenario creates a small text file, and signs it, and checks that
the signature is OK.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq sign -o s.pgp --signer-key tomjon.pgp hello.txt
then file s.pgp contains "-----BEGIN PGP MESSAGE-----"
then file s.pgp contains "-----END PGP MESSAGE-----"
when I run sq verify -o output.txt --signer-cert tomjon.pgp s.pgp
then files hello.txt and output.txt match
then file output.txt contains "hello, world"
~~~

However, if the signed file is modified, verification must fail. We
check this by removing a line from the signed file, which is a crude
way of making sure the signature doesn't match.

Further, the output must not contain the input if the verification
fails. This is to prevent accidents where the user is shown unverified
text, and possibly a warning that it's not to be trusted, but they
make use of the text anyway.

~~~scenario
when I run sed -i 3d s.pgp
when I try to run sq verify --signer-cert tomjon.pgp s.pgp
then exit code is not 0
then stdout doesn't contain "hello, world"
~~~


## Cleartext signature

This scenario is essentially the same, but uses a cleartext signature,
and the way the signed file is mangled is different.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq sign --cleartext-signature -o s.pgp --signer-key tomjon.pgp hello.txt
then file s.pgp contains "hello, world"
when I run sq verify -o output.txt --signer-cert tomjon.pgp s.pgp
then files hello.txt and output.txt match
then file output.txt contains "hello, world"
~~~

We modify the signed file by converting the actual message embedded in
the signed file to upper case, which is easy to do, as it's in cleartext.

~~~scenario
when I run sed -i 's/^hello, world/HELLO, WORLD/' s.pgp
when I try to run sq verify --signer-cert tomjon.pgp s.pgp
then exit code is 1
then stdout doesn't contain "hello, world"
then stdout doesn't contain "HELLO, WORLD"
~~~

## Detached signature

This scenario is essentially the same as the previous ones, but uses a
detached signature.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export k.pgp
when I run sq sign --detached -o s.pgp --signer-key k.pgp hello.txt
when I run sq verify -o o.txt --signer-cert k.pgp --detached s.pgp hello.txt
~~~

We modify the original file so that the signature doesn't match.

~~~scenario
when I run sed -i 's/^hello, world/HELLO, WORLD/' hello.txt
when I try to run sq verify --signer-cert k.pgp --detached s.pgp hello.txt
then exit code is 1
then stdout doesn't contain "hello, world"
then stdout doesn't contain "HELLO, WORLD"
~~~

# Test data file

We use this file as an input file in the tests. It is a very short
file, and a text file, but this is enough for the current set of
requirements and scenarios.

~~~{#hello.txt .file}
hello, world
~~~
