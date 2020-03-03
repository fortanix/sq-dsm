This crate aims to provide a complete implementation of OpenPGP as
defined by [RFC 4880] as well as some extensions (e.g., [RFC
6637], which describes ECC cryptography for OpenPGP.  This
includes support for unbuffered message processing.

A few features that the OpenPGP community considers to be
deprecated (e.g., version 3 compatibility) have been left out.  We
have also updated some OpenPGP defaults to avoid foot guns (e.g.,
we selected modern algorithm defaults).  If some functionality is
missing, please file a bug report.

A non-goal of this crate is support for any sort of high-level,
bolted-on functionality.  For instance, [RFC 4880] does not define
trust models, such as the web of trust, direct trust, or TOFU.
Neither does this crate.  [RFC 4880] does provide some mechanisms
for creating trust models (specifically, UserID certifications),
and this crate does expose those mechanisms.

We also try hard to avoid dictating how OpenPGP should be used.
This doesn't mean that we don't have opinions about how OpenPGP
should be used in a number of common scenarios (for instance,
message validation).  But, in this crate, we refrain from
expressing those opinions; we expose an opinionated, high-level
interface in the [sequoia-core] and related crates.  In our
opinion, you should generally use those crates instead of this
one.

[RFC 4880]: https://tools.ietf.org/html/rfc4880
[RFC 6637]: https://tools.ietf.org/html/rfc6637
[sequoia-core]: ../sequoia_core

# Experimental Features

This crate implements functionality from [RFC 4880bis], notable
AEAD encryption containers.  As of this writing, this RFC is still
a draft and the syntax or semantic defined in it may change or go
away.  Therefore, all related functionality may change and
artifacts created using this functionality may not be usable in
the future.  Do not use it for things other than experiments.

[RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08

This crate aims to provide a complete implementation of OpenPGP as
defined by RFC 4880 as well as several extensions (e.g., RFC 6637,
which describes ECC cryptography for OpenPGP, and RFC 4880bis, the
draft of the next OpenPGP standard).  This includes support for
unbuffered message processing.

