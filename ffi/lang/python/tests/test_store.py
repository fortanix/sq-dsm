from sequoia.prelude import Context, Store, Mapping, Fingerprint

def test_open():
    c = Context(ephemeral=True)
    Mapping.open(c)

def test_add():
    c = Context(ephemeral=True)
    s = Mapping.open(c)
    fp = Fingerprint.from_hex("7DCA58B54EB143169DDEE15F247F6DABC84914FE")
    s.add("Ἀριστοτέλης", fp)

def test_iterate():
    c = Context(ephemeral=True)
    s = Mapping.open(c)
    fp = Fingerprint.from_hex("7DCA58B54EB143169DDEE15F247F6DABC84914FE")
    s.add("Ἀριστοτέλης", fp)
    l = list(s.iter())
    assert len(l) == 1
    l = list(Store.list_keys(c))
    assert len(l) == 1
    fpi, key = l[0]
    assert fpi == fp

def test_logs():
    c = Context(ephemeral=True)
    s = Mapping.open(c)
    fp = Fingerprint.from_hex("7DCA58B54EB143169DDEE15F247F6DABC84914FE")
    b = s.add("Ἀριστοτέλης", fp)
    l = list(s.iter())
    assert len(l) == 1

    # global logs
    logs = list(Store.log(c))
    assert len(logs) > 0

    # per store logs
    logs = list(s.log())
    assert len(logs) > 0

    # per binding logs
    logs = list(b.log())
    assert len(logs) > 0

    # per key logs
    logs = list(b.key().log())
    assert len(logs) > 0
