from _sequoia import ffi, lib

from .openpgp import TPK
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
    def sks_pool(cls, ctx):
        return KeyServer(lib.sq_keyserver_sks_pool(ctx.ref()),
                         context=ctx)

    def get(self, keyid):
        return TPK(lib.sq_keyserver_get(self.context().ref(),
                                        self.ref(),
                                        keyid.ref()),
                   context=self.context())

    def send(self, tpk):
        r = lib.sq_keyserver_send(self.context().ref(),
                                  self.ref(),
                                  tpk.ref())
        if r:
            raise Error._last(self.context())
