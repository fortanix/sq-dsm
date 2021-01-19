#![doc="
Climbing Sequoias.

This is our guided tour through the Sequoia OpenPGP library.

Please note that this guide as well as Sequoia is work in progress.
But, fear not!  This guide is part of the API documentation, and the
code fragments are tested as part of Sequoias test suite.  This makes
sure that this guide is always up-to-date.

For more inspiration, see our various [examples] and our
command-line frontends [sq] and [sqv].

[examples]: https://gitlab.com/sequoia-pgp/sequoia/tree/main/openpgp/examples
[sq]: https://gitlab.com/sequoia-pgp/sequoia/tree/main/sq
[sqv]: https://gitlab.com/sequoia-pgp/sequoia/tree/main/sqv

Happy climbing!

"]

include!(concat!(env!("OUT_DIR"), "/src/lib.rs"));
