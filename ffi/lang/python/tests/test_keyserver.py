from sequoia.prelude import Context
from sequoia.net import KeyServer

def test_keys_openpgp_org():
    c = Context(ephemeral=True)
    KeyServer.keys_openpgp_org(c)

def test_new():
    c = Context(ephemeral=True)
    KeyServer.new(c, "hkps://keys.domain.example")
