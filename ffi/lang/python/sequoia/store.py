from _sequoia import ffi, lib

from .error import Error
from .glue import _str, SQObject, sq_iterator, sq_time
from .openpgp import Fingerprint, TPK

class Store(SQObject):
    _del = lib.sq_store_free

    @classmethod
    def server_log(cls, ctx):
        yield from sq_iterator(
            ffi.gc(
                lib.sq_store_server_log(ctx.ref()),
                lib.sq_log_iter_free),
            lib.sq_log_iter_next,
            lambda x: Log(x, context=ctx))

    @classmethod
    def list_keys(cls, ctx):
        def next_fn(i):
            fpp = ffi.new("sq_fingerprint_t[1]")
            key = lib.sq_key_iter_next(i, fpp)
            if key == ffi.NULL:
                return ffi.NULL
            else:
                return (Fingerprint(fpp[0], ctx),
                        Key(key, ctx))

        yield from sq_iterator(
            ffi.gc(
                lib.sq_store_list_keys(ctx.ref()),
                lib.sq_key_iter_free),
            next_fn)

    @classmethod
    def open(cls, ctx, name):
        return Store(lib.sq_store_open(ctx.ref(), name.encode()), context=ctx)


    def add(self, label, fingerprint):
        return Binding(lib.sq_store_add(self.context().ref(), self.ref(),
                                        label.encode(), fingerprint.ref()),
                       context=self.context())

    def import_(self, label, tpk):
        return TPK(lib.sq_store_import(self.context().ref(), self.ref(),
                                       label.encode(), tpk.ref()),
                   context=self.context())

    def lookup(self, label):
        return Binding(lib.sq_store_lookup(self.context().ref(), self.ref(),
                                           label.encode()),
                       self.context())

    def delete(self):
        if lib.sq_store_delete(self.ref()):
            raise Error._last(self.context())
        super(Store, self)._delete(skip_free=True)

    def iter(self):
        def next_fn(i):
            labelp = ffi.new("char *[1]")
            fpp = ffi.new("sq_fingerprint_t[1]")
            binding = lib.sq_binding_iter_next(i, labelp, fpp)
            if binding == ffi.NULL:
                return ffi.NULL
            else:
                return (_str(labelp[0]),
                        Fingerprint(fpp[0], self.context()),
                        Binding(binding, self.context()))

        yield from sq_iterator(
            ffi.gc(
                lib.sq_store_iter(self.context().ref(), self.ref()),
                lib.sq_binding_iter_free),
            next_fn)

    def log(self):
        yield from sq_iterator(
            ffi.gc(
                lib.sq_store_log(self.context().ref(), self.ref()),
                lib.sq_log_iter_free),
            lib.sq_log_iter_next,
            lambda x: Log(x, context=self.context()))

class Binding(SQObject):
    _del = lib.sq_binding_free

    def stats(self):
        return Stats(lib.sq_binding_stats(self.context().ref(), self.ref()),
                     self.context())

    def key(self):
        return Key(lib.sq_binding_key(self.context().ref(), self.ref()),
                   self.context())

    def tpk(self):
        return TPK(lib.sq_binding_tpk(self.context().ref(), self.ref()),
                   self.context())

    def import_(self, tpk):
        return TPK(lib.sq_binding_import(self.context().ref(), self.ref(), tpk),
                   self.context())

    def rotate(self, tpk):
        return TPK(lib.sq_binding_rotate(self.context().ref(), self.ref(), tpk),
                   self.context())

    def delete(self):
        if lib.sq_binding_delete(self.ref()):
            raise Error._last(self.context())
        super(Binding, self)._delete(skip_free=True)

    def log(self):
        yield from sq_iterator(
            ffi.gc(
                lib.sq_binding_log(self.context().ref(), self.ref()),
                lib.sq_log_iter_free),
            lib.sq_log_iter_next,
            lambda x: Log(x, context=self.context()))

class Key(SQObject):
    _del = lib.sq_key_free

    def stats(self):
        return Stats(lib.sq_key_stats(self.context().ref(), self.ref()),
                     self.context())

    def tpk(self):
        return TPK(lib.sq_key_tpk(self.context().ref(), self.ref()),
                   self.context())

    def import_(self, tpk):
        return TPK(lib.sq_key_import(self.context().ref(), self.ref(), tpk),
                   self.context())

    def log(self):
        yield from sq_iterator(
            ffi.gc(
                lib.sq_key_log(self.context().ref(), self.ref()),
                lib.sq_log_iter_free),
            lib.sq_log_iter_next)


class Stats(SQObject):
    _del = lib.sq_stats_free
    def __init__(self, o, context=None):
        super(Stats, self).__init__(o, context=context)
        self.encryption = Stamps(ffi.addressof(o, "encryption"))
        self.verification = Stamps(ffi.addressof(o, "verification"))

    @property
    def created(self):
        return sq_time(self.ref().created)

    @property
    def updated(self):
        return sq_time(self.ref().updated)

    def __str__(self):
        return \
            "Stats{{created={}, updated={}, encryption={}, verification={}}}" \
            .format(self.created, self.updated, self.encryption,
                    self.verification)

class Stamps(SQObject):
    @property
    def count(self):
        return self.ref().count

    @property
    def first(self):
        return sq_time(self.ref().first)

    @property
    def last(self):
        return sq_time(self.ref().last)

    def __str__(self):
        return "Stamps{{count={}, first={}, last={}}}".format(
            self.count, self.first, self.last)

class Log(SQObject):
    _del = lib.sq_log_free

    @property
    def timestamp(self):
        return sq_time(self.ref().timestamp)

    @property
    def store(self):
        if self.ref().store == ffi.NULL:
            return None
        else:
            return Store(self.ref().store, context=self.context(),
                         owner=self)

    @property
    def binding(self):
        if self.ref().binding == ffi.NULL:
            return None
        else:
            return Binding(self.ref().binding, context=self.context(),
                           owner=self)

    @property
    def key(self):
        if self.ref().key == ffi.NULL:
            return None
        else:
            return Key(self.ref().key, context=self.context(),
                       owner=self)

    @property
    def slug(self):
        return ffi.string(self.ref().slug).decode()

    @property
    def status(self):
        return ffi.string(self.ref().status).decode()

    @property
    def error(self):
        if self.ref().error == ffi.NULL:
            return None
        else:
            return ffi.string(self.ref().error).decode()

    def __str__(self):
        if self.error:
            return "{}: {}: {}: {}".format(
                self.timestamp, self.slug, self.status, self.error)
        else:
            return "{}: {}: {}".format(
                self.timestamp, self.slug, self.status)
