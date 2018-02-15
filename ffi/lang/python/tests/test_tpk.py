from os.path import join
from tempfile import TemporaryDirectory

from sequoia.core import Context, NetworkPolicy, Reader, Writer
from sequoia.openpgp import ArmorReader, Fingerprint, TPK, PacketPile

pgp = "../../../openpgp/tests/data/keys/testy.pgp"
asc = "../../../openpgp/tests/data/keys/testy.asc"
fp = Fingerprint.from_hex("3E8877C877274692975189F5D03F6F865226FE8B")

def test_from_reader():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    r = Reader.open(ctx, pgp)
    t = TPK.from_reader(ctx, r)
    assert t.fingerprint() == fp

def test_from_armor_reader():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    k = open(asc, "rb").read()
    r = Reader.from_bytes(ctx, k)
    r = ArmorReader.new(ctx, r)
    t = TPK.from_reader(ctx, r)
    assert t.fingerprint() == fp

def test_from_file():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    t = TPK.open(ctx, pgp)
    assert t.fingerprint() == fp

def test_from_message():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    r = PacketPile.open(ctx, pgp)
    t = TPK.from_packet_pile(ctx, r)
    assert t.fingerprint() == fp

def test_from_bytes():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    t = TPK.from_bytes(ctx, open(pgp, "rb").read())
    assert t.fingerprint() == fp

def test_from_serialize():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    with TemporaryDirectory() as tmp:
        sink = join(tmp, "a")

        t = TPK.open(ctx, pgp)
        with Writer.open(ctx, sink) as s:
            t.serialize(s)

        t = TPK.open(ctx, sink)
        assert t.fingerprint() == fp

def test_equals():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    b = open(pgp, "rb").read()
    t = TPK.from_bytes(ctx, b)
    u = TPK.from_bytes(ctx, b)
    assert t == u

def test_clone():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)
    a = TPK.open(ctx, pgp)
    b = a.copy()
    del a
    c = b.copy()
    del b
    assert c.fingerprint() == fp
