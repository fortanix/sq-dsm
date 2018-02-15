from enum import Enum

from _sequoia import ffi, lib
from .error import Error
from .glue import _str, SQObject
from .core import AbstractReader, AbstractWriter

class KeyID(SQObject):
    _del = lib.sq_keyid_free
    _clone = lib.sq_keyid_clone
    _str = lib.sq_keyid_to_string
    _eq = lib.sq_keyid_equal
    _hash = lib.sq_keyid_hash

    @classmethod
    def from_bytes(cls, fp):
        if len(fp) != 8:
            raise Error("KeyID must be of length 8")
        return KeyID(lib.sq_keyid_from_bytes(
            ffi.cast("uint8_t *", ffi.from_buffer(fp))))

    @classmethod
    def from_hex(cls, fp):
        return KeyID(lib.sq_keyid_from_hex(fp.encode()))

    def hex(self):
        return _str(lib.sq_keyid_to_hex(self.ref()))

class Fingerprint(SQObject):
    _del = lib.sq_fingerprint_free
    _clone = lib.sq_fingerprint_clone
    _str = lib.sq_fingerprint_to_string
    _eq = lib.sq_fingerprint_equal
    _hash = lib.sq_fingerprint_hash

    @classmethod
    def from_bytes(cls, fp):
        return Fingerprint(lib.sq_fingerprint_from_bytes(
            ffi.cast("uint8_t *", ffi.from_buffer(fp)), len(fp)))

    @classmethod
    def from_hex(cls, fp):
        return Fingerprint(lib.sq_fingerprint_from_hex(fp.encode()))

    def hex(self):
        return _str(lib.sq_fingerprint_to_hex(self.ref()))

    def keyid(self):
        return KeyID(lib.sq_fingerprint_to_keyid(self.ref()))

class PacketPile(SQObject):
    _del = lib.sq_packet_pile_free
    _clone = lib.sq_packet_pile_clone

    @classmethod
    def from_reader(cls, ctx, reader):
        return PacketPile(lib.sq_packet_pile_from_reader(ctx.ref(), reader.ref()),
                          context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return PacketPile(lib.sq_packet_pile_from_file(ctx.ref(), filename.encode()),
                          context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return PacketPile(lib.sq_packet_pile_from_bytes(ctx.ref(),
                                                        ffi.from_buffer(source),
                                                        len(source)),
                          context=ctx)

    def serialize(self, writer):
        status = lib.sq_packet_pile_serialize(self.context().ref(),
                                              self.ref(),
                                              writer.ref())
        if status:
            raise Error._last(self.context())

class TPK(SQObject):
    _del = lib.sq_tpk_free
    _clone = lib.sq_tpk_clone
    _eq = lib.sq_tpk_equal

    @classmethod
    def from_reader(cls, ctx, reader):
        return TPK(lib.sq_tpk_from_reader(ctx.ref(), reader.ref()),
                   context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return TPK(lib.sq_tpk_from_file(ctx.ref(), filename.encode()),
                   context=ctx)

    @classmethod
    def from_packet_pile(cls, ctx, packet_pile):
        return TPK(lib.sq_tpk_from_packet_pile(ctx.ref(), packet_pile.ref_consume()),
                   context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return TPK(lib.sq_tpk_from_bytes(ctx.ref(),
                                         ffi.from_buffer(source),
                                         len(source)),
                   context=ctx)

    def serialize(self, writer):
        status = lib.sq_tpk_serialize(self.context().ref(),
                                      self.ref(),
                                      writer.ref())
        if status:
            raise Error._last(self.context())

    def fingerprint(self):
        return Fingerprint(lib.sq_tpk_fingerprint(self.ref()),
                           context=self.context())

    def merge(self, other):
        new = lib.sq_tpk_merge(self.context().ref(),
                               self.ref_consume(),
                               other.ref_consume())
        if new == ffi.NULL:
            raise Error._last(self.context())
        self.ref_replace(new)

    def dump(self):
        lib.sq_tpk_dump(self.ref())

class Kind(Enum):
    Message = lib.SQ_ARMOR_KIND_MESSAGE
    PublicKey = lib.SQ_ARMOR_KIND_PUBLICKEY
    SecretKey = lib.SQ_ARMOR_KIND_SECRETKEY
    Signature = lib.SQ_ARMOR_KIND_SIGNATURE
    File = lib.SQ_ARMOR_KIND_FILE
    Any = lib.SQ_ARMOR_KIND_ANY

class ArmorReader(AbstractReader):
    @classmethod
    def new(cls, ctx, inner, kind=Kind.Any):
        ar = ArmorReader(lib.sq_armor_reader_new(inner.ref(),
                                                 kind.value),
                         context=ctx)
        ar.inner = inner
        return ar

    def close(self):
        super(ArmorReader, self)._delete()
        self.inner.close()

class ArmorWriter(AbstractWriter):
    @classmethod
    def new(cls, ctx, inner, kind):
        aw = ArmorWriter(lib.sq_armor_writer_new(ctx.ref(),
                                                 inner.ref(),
                                                 kind.value,
                                                 ffi.NULL, 0), #XXX headers
                         context=ctx)
        aw.inner = inner
        return aw

    def close(self):
        super(ArmorWriter, self)._delete()
        self.inner.close()

class Tag(Enum):
    PKESK = lib.SQ_TAG_PKESK
    Signature = lib.SQ_TAG_SIGNATURE
    SKESK = lib.SQ_TAG_SKESK
    OnePassSig = lib.SQ_TAG_ONE_PASS_SIG
    SecretKey = lib.SQ_TAG_SECRET_KEY
    PublicKey = lib.SQ_TAG_PUBLIC_KEY
    SecretSubkey = lib.SQ_TAG_SECRET_SUBKEY
    CompressedData = lib.SQ_TAG_COMPRESSED_DATA
    SED = lib.SQ_TAG_SED
    Marker = lib.SQ_TAG_MARKER
    Literal = lib.SQ_TAG_LITERAL
    Trust = lib.SQ_TAG_TRUST
    UserID = lib.SQ_TAG_USER_ID
    PublicSubkey = lib.SQ_TAG_PUBLIC_SUBKEY
    Unassigned15 = lib.SQ_TAG_UNASSIGNED15
    Unassigned16 = lib.SQ_TAG_UNASSIGNED16
    UserAttribute = lib.SQ_TAG_USER_ATTRIBUTE
    SEIP = lib.SQ_TAG_SEIP
    MDC = lib.SQ_TAG_MDC
    # xxx the rest

class Key(SQObject):
    @property
    def fingerprint(self):
        return Fingerprint(lib.sq_p_key_fingerprint(self.ref()))

    @property
    def keyid(self):
        return KeyID(lib.sq_p_key_keyid(self.ref()))

class PublicKey(Key):
    pass
class PublicSubkey(Key):
    pass
class SecretKey(Key):
    pass
class SecretSubkey(Key):
    pass

class UserID(SQObject):
    @property
    def value(self):
        buf_len = ffi.new("size_t[1]")
        buf = lib.sq_user_id_value(self.ref(), buf_len)
        return ffi.buffer(buf, buf_len[0])

class UserAttribute(SQObject):
    @property
    def value(self):
        buf_len = ffi.new("size_t[1]")
        buf = lib.sq_user_attribute_value(self.ref(), buf_len)
        return ffi.buffer(buf, buf_len[0])

class SKESK(SQObject):
    def decrypt(self, passphrase):
        algo = ffi.new("uint8_t[1]")
        key = ffi.new("uint8_t[32]")
        key_len = ffi.new("size_t[1]")
        key_len[0] = len(key)
        if lib.sq_skesk_decrypt(self.context().ref(),
                                self.ref(),
                                ffi.from_buffer(passphrase),
                                len(passphrase),
                                algo, key, key_len):
            raise Error._last(self.context())
        return (algo[0], ffi.buffer(key, key_len[0]))

class SEIP(SQObject):
    pass

class Packet(SQObject):
    _map = {
        Tag.PublicKey: lambda x, **kwargs: PublicKey(x.key, **kwargs),
        Tag.PublicSubkey: lambda x, **kwargs: PublicSubkey(x.key, **kwargs),
        Tag.SecretKey: lambda x, **kwargs: SecretKey(x.key, **kwargs),
        Tag.SecretSubkey: lambda x, **kwargs: SecretSubkey(x.key, **kwargs),
        Tag.UserID: lambda x, **kwargs: UserID(x.user_id, **kwargs),
        Tag.UserAttribute: lambda x, **kwargs: UserAttribute(x.user_attribute, **kwargs),
        Tag.SKESK: lambda x, **kwargs: SKESK(x.skesk, **kwargs),
        Tag.SEIP: lambda x, **kwargs: SEIP(x.seip, **kwargs),
    }
    @property
    def tag(self):
        return Tag(lib.sq_packet_tag(self.ref()))
    def __str__(self):
        return "<Packet tag={}>".format(self.tag)
    def match(self):
        return self._map[self.tag](self.ref(), context=self.context(), owner=self)

class PacketParserResult(SQObject):
    _del = lib.sq_packet_parser_result_free

    def packet_parser(self):
        ref = lib.sq_packet_parser_result_packet_parser(self.ref())
        if ref != ffi.NULL:
            # Success!  We are consumed.
            self._delete(skip_free=True)
            return PacketParser(ref, context=self.context())
        else:
            return None

    def eof(self):
        ref = lib.sq_packet_parser_result_eof(self.ref())
        if ref != ffi.NULL:
            # Success!  We are consumed.
            self._delete(skip_free=True)
            return PacketParserEOF(ref, context=self.context())
        else:
            return None

class PacketParserEOF(SQObject):
    _del = lib.sq_packet_parser_eof_free

    def is_message(self):
        return bool(lib.sq_packet_parser_eof_is_message(self.ref()))

class PacketParser(SQObject):
    _del = lib.sq_packet_parser_free

    @classmethod
    def from_reader(cls, ctx, reader):
        return PacketParserResult(
            lib.sq_packet_parser_from_reader(ctx.ref(), reader.ref()),
            context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return PacketParserResult(
            lib.sq_packet_parser_from_file(ctx.ref(), filename.encode()),
            context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return PacketParserResult(
            lib.sq_packet_parser_from_bytes(ctx.ref(),
                                            ffi.from_buffer(source),
                                            len(source)),
            context=ctx)

    @property
    def has_packet(self):
        return self.ref() != ffi.NULL

    @property
    def packet(self):
        return Packet(lib.sq_packet_parser_packet(self.ref()),
                      context=self.context(),
                      owner=self)

    @property
    def recursion_depth(self):
        return lib.sq_packet_parser_recursion_depth(self.ref())

    def next(self):
        packet = ffi.new("sq_packet_t[1]")
        old_rl = ffi.new("uint8_t[1]")
        ppr = ffi.new("sq_packet_parser_result_t[1]")
        new_rl = ffi.new("uint8_t[1]")

        if lib.sq_packet_parser_next(self.context().ref(),
                                     self.ref_consume(),
                                     packet,
                                     ppr):
            raise Error._last(self.context())

        return (Packet(packet[0]), PacketParserResult(ppr[0], self.context()))

    def recurse(self):
        packet = ffi.new("sq_packet_t[1]")
        old_rl = ffi.new("uint8_t[1]")
        ppr = ffi.new("sq_packet_parser_result_t[1]")
        new_rl = ffi.new("uint8_t[1]")

        if lib.sq_packet_parser_recurse(self.context().ref(),
                                        self.ref_consume(),
                                        packet,
                                        ppr):
            raise Error._last(self.context())

        return (Packet(packet[0]), PacketParserResult(ppr[0], self.context()))

    def buffer_unread_content(self):
        buf_len = ffi.new("size_t[1]")
        buf = lib.sq_packet_parser_buffer_unread_content(self.context().ref(),
                                                         self.ref(),
                                                         buf_len)
        if buf == ffi.NULL:
            raise Error._last(self.context())
        return ffi.buffer(buf, buf_len[0])

    def decrypt(self, algo, key):
        if lib.sq_packet_parser_decrypt(self.context().ref(),
                                        self.ref(),
                                        algo,
                                        ffi.from_buffer(key),
                                        len(key)):
            raise Error._last(self.context())
