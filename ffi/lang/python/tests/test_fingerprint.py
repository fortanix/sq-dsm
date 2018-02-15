from sequoia.openpgp import Fingerprint

binary = b"\x7D\xCA\x58\xB5\x4E\xB1\x43\x16\x9D\xDE\xE1\x5F\x24\x7F\x6D\xAB\xC8\x49\x14\xFE"
hexy   = "7DCA58B54EB143169DDEE15F247F6DABC84914FE"
pretty = "7DCA 58B5 4EB1 4316 9DDE  E15F 247F 6DAB C849 14FE"

def test_from_bytes():
    f = Fingerprint.from_bytes(binary)
    assert str(f) == pretty
    assert f.hex() == hexy

def test_from_hex():
    f = Fingerprint.from_hex(hexy)
    assert str(f) == pretty
    assert f.hex() == hexy

def test_to_keyid():
    f = Fingerprint.from_hex(hexy)
    assert f.keyid().hex() == "247F6DABC84914FE"

def test_bad_hex():
    try:
        f = Fingerprint.from_hex("bad hex")
    except:
        pass
    else:
        raise "Expected exception"

def test_equals():
    a = Fingerprint.from_hex(hexy)
    b = Fingerprint.from_hex(hexy)
    assert a == b

def test_clone():
    a = Fingerprint.from_hex(hexy)
    b = a.copy()
    del a
    c = b.copy()
    del b
    assert c.hex() == hexy

def test_hash():
    a = Fingerprint.from_hex(hexy)
    b = Fingerprint.from_hex(hexy)
    assert hash(a) == hash(b)
