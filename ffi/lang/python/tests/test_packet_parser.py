from enum import Enum, auto
from sequoia.core import Context, NetworkPolicy
from sequoia.openpgp import Tag, PacketParser

pgp = "../../../openpgp/tests/data/messages/encrypted-aes128-password-123456789.gpg"
plain = "../../../openpgp/tests/data/messages/a-cypherpunks-manifesto.txt"

def test_decryption():
    ctx = Context("org.sequoia-pgp.tests",
                  network_policy=NetworkPolicy.Offline,
                  ephemeral=True)

    class State(Enum):
        Start = auto()
        Decrypted = auto()
        Deciphered = auto()
        Done = auto()

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
