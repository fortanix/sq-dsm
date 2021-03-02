Describes how to use some of Sequoia's parsers.

Sequoia contains and exposes several parsers.  In this chapter, we
will cover some of them, starting from a high level parser, the
[`CertParser`] that parses OpenPGP Certificates ([`Cert`]s), all
down to the actual OpenPGP [`PacketParser`].

[`CertParser`]: ../../sequoia_openpgp/cert/struct.CertParser.html
[`Cert`]: ../../sequoia_openpgp/cert/struct.Cert.html
[`PacketParser`]: ../../sequoia_openpgp/parse/struct.PacketParser.html

# Parsing Certs

First, we will start with a string that presumably contains a
OpenPGP Certificate, and feed it into the [`CertParser`].  On
success, we can use or examine the resulting [`Cert`]:

```rust
extern crate sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

const KEY: &str =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----

     xjMEXAfmvxYJKwYBBAHaRw8BAQdAVNM03IK1KDgDNCbf4XcARhfqzyx425FEJMQ5
     qF+DrwHNF+G8iM+BzrnPg8+Ezr/PhM6tzrvOt8+CwoQEExYKADYCHgMCmwEFglwH
     5r8FiQWfpgAWIQTAh0R4plxUCh9zcrSiLq1hTRF0SgkQoi6tYU0RdEoCFQoAALip
     AP4sSVgNJogb/v0Qst0+WlmrJ6upG8Ynao5mnRFmfx2LjAEAyGJJBaEBB+x4kOse
     9uACwAXFhBRLN9zGgbyySQ3fRwjOMwRcB+a/FgkrBgEEAdpHDwEBB0BXBFWMeVd1
     nNn/VqTVEgY3wknX/KkKfMWhslFJoyZ4L8LAOAQYFgoAMwKbAgWCXAfmvwWJBZ+m
     ABYhBMCHRHimXFQKH3NytKIurWFNEXRKCRCiLq1hTRF0SgIVCgB3dqAEGRYKACcF
     glwH5r8WIQRnpIdTo4Cms7fffcXmxol6TO+JJAkQ5saJekzviSQAAMuvAQDdRfbM
     u2bDtVqNLIP/0WD/5X0us49r1yXMH+Ilg5NEEQEAuSQ1pY+reS62ETUS0uKYhxxv
     7OOsr8YM/ZMQ0exZsw/u+QEAuakAXrR7uFmWyigopQ7qMYfnK5zNfQNykvony5tS
     HpEBAJs3ZwHq+Q0ziAZNgcvdp0mklx8IXd8x59NjiP1t3mUBzjgEXAfmvxIKKwYB
     BAGXVQEFAQEHQJuIvcDm3Sh0+ZOE5hj7jCBas2xOCqYiG6+bWWieoxRrAwEICcKB
     BBgWCgAzApsMBYJcB+a/BYkFn6YAFiEEwIdEeKZcVAofc3K0oi6tYU0RdEoJEKIu
     rWFNEXRKAgsJAADx4wD/VrXZ7I/hBC37lzhyVEcCaHcorVXVn8ACCiyRmgmNbY4A
     /1lJmQJoDlpYlx3BAJ6RYuXRJoyU5KpcBf5afBPn8ncB
     =MHBq
     -----END PGP PUBLIC KEY BLOCK-----";

fn main() -> openpgp::Result<()> {
    let cert = openpgp::Cert::from_bytes(KEY.as_bytes())?;

    assert_eq!(cert.fingerprint().to_hex(),
               "C0874478A65C540A1F7372B4A22EAD614D11744A");

    // Iterate over UserIDs.
    assert_eq!(cert.userids().count(), 1);
    assert_eq!(cert.userids().nth(0).unwrap().to_string(), "Ἀριστοτέλης");

    // Iterate over subkeys.
    assert_eq!(cert.keys().subkeys().count(), 2);
    assert_eq!(cert.keys().subkeys().nth(0).unwrap().key().fingerprint().to_hex(),
               "67A48753A380A6B3B7DF7DC5E6C6897A4CEF8924");
    assert_eq!(cert.keys().subkeys().nth(1).unwrap().key().fingerprint().to_hex(),
               "185CDAA12723042319E47F67108F2CAF9034356D");

    Ok(())
}
```

# Parsing OpenPGP messages

Not all sequences of OpenPGP packets are in valid OpenPGP
[`Message`]s, only those accepted by [this grammar] are.  Sequoia
contains a parser that parses packets and verifies the message
structure using this grammar:

[this grammar]: https://tools.ietf.org/html/rfc4880#section-11.3
[`Message`]: ../../sequoia_openpgp/struct.Message.html

```rust
extern crate sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

const MESSAGE: &str =
    "-----BEGIN PGP MESSAGE-----

     xA0DAAoW5saJekzviSQByxBiAAAAAADYtdiv2KfZgtipwnUEABYKACcFglwJHYoW
     IQRnpIdTo4Cms7fffcXmxol6TO+JJAkQ5saJekzviSQAAIJ6APwK6FxtHXn8txDl
     tBFsIXlOSLOs4BvArlZzZSMomIyFLAEAwCLJUChMICDxWXRlHxORqU5x6hlO3DdW
     sl/1DAbnRgI=
     =AqoO
     -----END PGP MESSAGE-----";

fn main() -> openpgp::Result<()> {
    let message = openpgp::Message::from_bytes(MESSAGE.as_bytes())?;

    assert_eq!(message.body().unwrap().body(), "صداقة".as_bytes());

    Ok(())
}
```

# Parsing packets into packet piles

[`PacketPile`]s are unstructured sequences of OpenPGP packets.  Packet
piles can be inspected, manipulated, validated using a formal grammar
and thereby turned into [`Message`]s or [`Cert`]s using
[`Message::try_from`] or [`Cert::try_from`], or just
turned into a vector of [`Packet`]s:

[`PacketPile`]: ../../sequoia_openpgp/struct.PacketPile.html
[`Packet`]: ../../sequoia_openpgp/enum.Packet.html
[`Cert::try_from`]: ../../sequoia_openpgp/cert/struct.Cert.html#method.try_from
[`Message::try_from`]: ../../sequoia_openpgp/struct.Message.html#method.try_from

```rust
extern crate sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

const MESSAGE: &str =
    "-----BEGIN PGP MESSAGE-----

     xA0DAAoW5saJekzviSQByxBiAAAAAADYtdiv2KfZgtipwnUEABYKACcFglwJHYoW
     IQRnpIdTo4Cms7fffcXmxol6TO+JJAkQ5saJekzviSQAAIJ6APwK6FxtHXn8txDl
     tBFsIXlOSLOs4BvArlZzZSMomIyFLAEAwCLJUChMICDxWXRlHxORqU5x6hlO3DdW
     sl/1DAbnRgI=
     =AqoO
     -----END PGP MESSAGE-----";

fn main() -> openpgp::Result<()> {
    let pile = openpgp::PacketPile::from_bytes(MESSAGE.as_bytes())?;

    // For simplicity, turn the pile into a vector of packets.
    let packets: Vec<openpgp::Packet> = pile.into_children().collect();

    // There are three packets in that message.
    assert_eq!(packets.len(), 3);

    // First, we expect an one pass signature packet.
    if let openpgp::Packet::OnePassSig(ref ops) = packets[0] {
        assert_eq!(ops.issuer().to_hex(), "E6C6897A4CEF8924");
    } else {
        panic!("expected one pass signature packet");
    }

    // The second packet is the literal data packet.
    if let openpgp::Packet::Literal(ref literal) = packets[1] {
        assert_eq!(literal.body(), "صداقة".as_bytes());
    } else {
        panic!("expected literal data packet");
    }

    // Finally, we expect the signature itself.
    if let openpgp::Packet::Signature(ref signature) = packets[2] {
        assert_eq!(signature.issuer_fingerprints().nth(0).unwrap().to_hex(),
                   "67A48753A380A6B3B7DF7DC5E6C6897A4CEF8924");
    } else {
        panic!("expected signature packet");
    }

    Ok(())
}
```

# Streaming packet parsing

Both the [`Message`]parser and the [`PacketPile`]parser build a tree
structure in memory, and more importantly, they buffer the bodies of
literal data packets.  Both properties can be undesirable if a large
number of packets is parsed, or the data contained in the message
large.  This problem is exacerbated by the fact that OpenPGP messages
can be compressed, so that processing even small messages can lead to
an unbounded amount of memory being allocated.

To alleviate this problem, Sequoia features streaming interfaces that
implement [`io::Read`] and [`io::Write`].  These interfaces allow
processing of OpenPGP packets in constant space.

[`io::Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
[`io::Write`]: https://doc.rust-lang.org/std/io/trait.Write.html

The core of Sequoia is our [`PacketParser`], upon which all higher
level interfaces are built.  It is the most flexible interface for
processing OpenPGP packets, and it is the foundation for our streaming
interfaces.  Most of the time, it is not necessary to use this
interface, but nevertheless, our parser is exposed as part of our API
and can be used to quickly process large amounts of OpenPGP packets,
e.g. for collecting statistics about the SKS keyserver dump.  For a
complete example, see [`openpgp/examples/statistics.rs`].

[`PacketParser`]: ../../sequoia_openpgp/parse/struct.PacketParser.html
[`openpgp/examples/statistics.rs`]: https://gitlab.com/sequoia-pgp/sequoia/blob/main/openpgp/examples/statistics.rs

```rust
use std::io::Read;

extern crate sequoia_openpgp as openpgp;
use openpgp::parse::*;

const MESSAGE: &str =
    "-----BEGIN PGP MESSAGE-----

     yMACA0JaaDYxQVkmU1nHKJOZA6l4wQTAABAAAAgACCAAUGaaCalNNxCUkepFQEtY
     hKSO3zFBWSZTWTYaxwsA6l5AAMAAAAggADCATUZBKSNSCUkcxQVkmU1k2GscLAOp
     eQADAAAAIIAAwgE1GQSkjUglJHMUFZJlNZNhrHCwDqXkAAwAAACCAAMIBNRkEpI1
     IJSRzFBWSZTWUmfJVgAWotAANkAAAggAFBmgClRjNkhJTMqEqoN9JCSnC7kinChI
     H89bU4A=
     =eySo
     -----END PGP MESSAGE-----";

fn main() -> openpgp::Result<()> {
    let mut bytes_read = 0;
    let mut buf = vec![0; 1024 * 1024];

    let mut ppr = PacketParser::from_bytes(MESSAGE.as_bytes())?;
    while let PacketParserResult::Some(mut pp) = ppr {
        // Match on the kind of packet here while it is in the parser.
        if let openpgp::Packet::Literal(_) = pp.packet {
            // Stream the content of the literal packet.
            while let Ok(_) = pp.read_exact(&mut buf) {
                bytes_read += buf.len();
            }
        }

        // Start parsing the next packet.
        ppr = pp.recurse()?.1;
    }

    assert_eq!(bytes_read, 128 * 1024 * 1024);    // 128 megabytes

    Ok(())
}
```
