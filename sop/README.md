An implementation of the Stateless OpenPGP Command Line Interface
using Sequoia.

This implements a subset of the [Stateless OpenPGP Command Line
Interface] (SOP) using the Sequoia OpenPGP implementation.  While SOP
is not intended for daily use, it is a good way to interact with and
explore OpenPGP implementations.  SOP is primarily used as abstraction
in the [OpenPGP interoperability test suite].

  [Stateless OpenPGP Command Line Interface]: https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/
  [OpenPGP interoperability test suite]: https://tests.sequoia-pgp.org/

# SOP primer

To demonstrate SOP, let's generate a key, and encrypt and decrypt a
message:

```sh
$ sqop generate-key julia@example.org > julia.secret.pgp
$ sqop extract-cert < julia.secret.pgp > julia.public.pgp
```

First, we generate a key for `julia@example.org`.  Next, we extract
the certificate, i.e. the key without the secret key material.

```sh
$ echo "a message" | sqop encrypt julia.public.pgp > message.pgp
$ sqop decrypt julia.secret.pgp < message.pgp
a message
```

Here, we encrypt a message with Julia's certificate, and decrypt it
with her key.
