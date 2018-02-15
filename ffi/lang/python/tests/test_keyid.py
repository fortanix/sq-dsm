from sequoia.openpgp import KeyID

binary = b"\x24\x7F\x6D\xAB\xC8\x49\x14\xFE"
hexy   = "247F6DABC84914FE"
pretty = "247F 6DAB C849 14FE"

def test_from_bytes():
    k = KeyID.from_bytes(binary)
    assert str(k) == pretty
    assert k.hex() == hexy

def test_from_hex():
    k = KeyID.from_hex(hexy)
    assert str(k) == pretty
    assert k.hex() == hexy

fp_hexy   = "7DCA58B54EB143169DDEE15F247F6DABC84914FE"
fp_pretty = "7DCA 58B5 4EB1 4316 9DDE  E15F 247F 6DAB C849 14FE"
def test_from_hexy_fp():
    k = KeyID.from_bytes(binary)
    assert k == KeyID.from_hex(fp_hexy)
    assert k == KeyID.from_hex(fp_pretty)

def test_malformed():
    try:
        KeyID.from_bytes(b"too few")
    except:
        pass
    else:
        raise "Expected exception"

    try:
        KeyID.from_bytes(b"way too many")
    except:
        pass
    else:
        raise "Expected exception"

    try:
        KeyID.from_hex(b"not hex chars")
    except:
        pass
    else:
        raise "Expected exception"

def test_equals():
    a = KeyID.from_hex(hexy)
    b = KeyID.from_hex(hexy)
    assert a == b

def test_clone():
    a = KeyID.from_hex(hexy)
    b = a.copy()
    del a
    c = b.copy()
    del b
    assert c.hex() == hexy

def test_hash():
    a = KeyID.from_hex(hexy)
    b = KeyID.from_hex(hexy)
    assert hash(a) == hash(b)

