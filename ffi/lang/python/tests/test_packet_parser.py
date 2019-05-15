from enum import Enum
from sequoia.core import Context, NetworkPolicy
from sequoia.openpgp import Tag, PacketParser

pgp = "../../../openpgp/tests/data/messages/encrypted-aes128-password-123456789.gpg"
plain = "../../../openpgp/tests/data/messages/a-cypherpunks-manifesto.txt"

def test_decryption():
    ctx = Context(network_policy=NetworkPolicy.Offline,
                  ephemeral=True)

    class State(Enum):
        # XXX: In Python 3.6, we can use enum.auto() to assign values.
        # But we want to support Debian 9, which uses Python 3.5, as
        # long as it is Debian stable.
        Start = 1
        Decrypted = 2
        Deciphered = 3
        Done = 4

    state = State.Start
    algo, key = None, None
    ppr = PacketParser.open(ctx, pgp)
    while True:
        pp = ppr.packet_parser()
        if not pp:
            break

        packet = pp.packet
        tag = packet.tag
        print(state, pp.recursion_depth, packet)

        if state == State.Start:
            assert pp.recursion_depth == 0
            if tag == Tag.SKESK:
                algo, key = packet.match().decrypt(b"123456789")
                state = State.Decrypted
        elif state == State.Decrypted:
            assert pp.recursion_depth == 0
            if tag == Tag.SEIP:
                pp.decrypt(algo, key)
                state = State.Deciphered
        elif state == State.Deciphered:
            assert pp.recursion_depth == 1
            if tag == Tag.Literal:
                body = pp.buffer_unread_content()
                assert body[:].decode() == open(plain).read()
                state = State.Done

        _, ppr = pp.recurse()

    assert ppr.eof().is_message()
    assert state == State.Done
