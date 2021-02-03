from enum import Enum

from _sequoia import ffi, lib
from .openpgp import Cert
from .error import Error
from .glue import SQObject

class NetworkPolicy(Enum):
    Offline = lib.SQ_NETWORK_POLICY_OFFLINE
    Anonymized = lib.SQ_NETWORK_POLICY_ANONYMIZED
    Encrypted = lib.SQ_NETWORK_POLICY_ENCRYPTED
    Insecure = lib.SQ_NETWORK_POLICY_INSECURE

class KeyServer(SQObject):
    _del = lib.sq_keyserver_free

    @classmethod
    def new(cls, ctx, uri, network_policy=NetworkPolicy.Encrypted, cert=None):
        if not cert:
            ks = lib.sq_keyserver_new(
                    ctx.ref(),
                    network_policy.value,
                    uri.encode())
        else:
            ks = lib.sq_keyserver_with_cert(
                ctx.ref(),
                network_policy.value,
                uri.encode(),
                ffi.cast("uint8_t *", ffi.from_buffer(cert)),
                len(cert))
        return KeyServer(ks, context=ctx)

    @classmethod
    def keys_openpgp_org(cls, ctx, network_policy=NetworkPolicy.Encrypted):
        ks = lib.sq_keyserver_keys_openpgp_org(ctx.ref(),
                                    network_policy.value)
        return KeyServer(ks, context=ctx)

    def get(self, keyid):
        return Cert(lib.sq_keyserver_get(self.context().ref(),
                                        self.ref(),
                                        keyid.ref()),
                   context=self.context())

    def send(self, cert):
        r = lib.sq_keyserver_send(self.context().ref(),
                                  self.ref(),
                                  cert.ref())
        if r:
            raise Error._last(self.context())
