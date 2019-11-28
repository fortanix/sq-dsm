from _sequoia import ffi, lib

from .openpgp import Cert
from .error import Error
from .glue import SQObject

class KeyServer(SQObject):
    _del = lib.sq_keyserver_free

    @classmethod
    def new(cls, ctx, uri, cert=None):
        if not cert:
            ks = lib.sq_keyserver_new(ctx.ref(), uri.encode())
        else:
            ks = lib.sq_keyserver_with_cert(
                ctx.ref(), uri.encode(),
                ffi.cast("uint8_t *", ffi.from_buffer(cert)),
                len(cert))
        return KeyServer(ks, context=ctx)

    @classmethod
    def keys_openpgp_org(cls, ctx):
        return KeyServer(lib.sq_keyserver_keys_openpgp_org(ctx.ref()),
                         context=ctx)

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
