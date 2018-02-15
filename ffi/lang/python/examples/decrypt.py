import sys
import os
from getpass import getpass
from enum import Enum, auto
from sequoia.core import Context, NetworkPolicy
from sequoia.openpgp import Tag, PacketParser

ctx = Context("org.sequoia-pgp.examples",
              network_policy=NetworkPolicy.Offline,
              ephemeral=True)

class State(Enum):
    Start = auto()
    Decrypted = auto()
    Deciphered = auto()
    Done = auto()

state = State.Start
algo, key = None, None
pp = PacketParser.open(ctx, sys.argv[1])
while pp.has_packet:
    packet = pp.packet
    tag = packet.tag

    if state == State.Start:
        if tag == Tag.SKESK:
            passphrase = getpass("Enter passphrase to decrypt message: ")
            algo, key = packet.match().decrypt(passphrase.encode())
            state = State.Decrypted
        elif tag == Tag.PKESK:
            sys.stderr.write("Decryption using PKESK not yet supported.\n")
    elif state == State.Decrypted:
        if tag == Tag.SEIP:
            pp.decrypt(algo, key)
            state = State.Deciphered
    elif state == State.Deciphered:
        if tag == Tag.Literal:
            body = pp.buffer_unread_content()
            os.write(sys.stdout.fileno(), body)
            state = State.Done

    pp.recurse()
assert state == State.Done
