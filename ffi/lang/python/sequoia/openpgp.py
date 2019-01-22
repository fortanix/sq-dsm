from enum import Enum

from _sequoia import ffi, lib
from .error import Error
from .glue import _str, SQObject, invoke
from .core import AbstractReader, AbstractWriter

class KeyID(SQObject):
    _del = lib.pgp_keyid_free
    _clone = lib.pgp_keyid_clone
    _str = lib.pgp_keyid_to_string
    _eq = lib.pgp_keyid_equal
    _hash = lib.pgp_keyid_hash

    @classmethod
    def from_bytes(cls, fp):
        if len(fp) != 8:
            raise Error("KeyID must be of length 8")
        return KeyID(lib.pgp_keyid_from_bytes(
            ffi.cast("uint8_t *", ffi.from_buffer(fp))))

    @classmethod
    def from_hex(cls, fp):
        return KeyID(lib.pgp_keyid_from_hex(fp.encode()))

    def hex(self):
        return _str(lib.pgp_keyid_to_hex(self.ref()))

class Fingerprint(SQObject):
    _del = lib.pgp_fingerprint_free
    _clone = lib.pgp_fingerprint_clone
    _str = lib.pgp_fingerprint_to_string
    _debug = lib.pgp_fingerprint_debug
    _eq = lib.pgp_fingerprint_equal
    _hash = lib.pgp_fingerprint_hash

    @classmethod
    def from_bytes(cls, fp):
        return Fingerprint(lib.pgp_fingerprint_from_bytes(
            ffi.cast("uint8_t *", ffi.from_buffer(fp)), len(fp)))

    @classmethod
    def from_hex(cls, fp):
        return Fingerprint(lib.pgp_fingerprint_from_hex(fp.encode()))

    def hex(self):
        return _str(lib.pgp_fingerprint_to_hex(self.ref()))

    def keyid(self):
        return KeyID(lib.pgp_fingerprint_to_keyid(self.ref()))

class PacketPile(SQObject):
    _debug = lib.pgp_packet_pile_debug
    _del = lib.pgp_packet_pile_free
    _clone = lib.pgp_packet_pile_clone

    @classmethod
    def from_reader(cls, ctx, reader):
        return PacketPile(invoke(lib.pgp_packet_pile_from_reader, reader.ref()),
                          context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return PacketPile(invoke(lib.pgp_packet_pile_from_file, filename.encode()),
                          context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return PacketPile(invoke(lib.pgp_packet_pile_from_bytes,
                                 ffi.from_buffer(source),
                                 len(source)),
                          context=ctx)

    def serialize(self, writer):
        status = invoke(lib.pgp_packet_pile_serialize,
                        self.ref(),
                        writer.ref())
        if status:
            raise Error._last(self.context())

class TPK(SQObject):
    _del = lib.pgp_tpk_free
    _clone = lib.pgp_tpk_clone
    _eq = lib.pgp_tpk_equal

    @classmethod
    def from_reader(cls, ctx, reader):
        return TPK(invoke(lib.pgp_tpk_from_reader, reader.ref()),
                   context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return TPK(invoke(lib.pgp_tpk_from_file, filename.encode()),
                   context=ctx)

    @classmethod
    def from_packet_pile(cls, ctx, packet_pile):
        return TPK(invoke(lib.pgp_tpk_from_packet_pile, packet_pile.ref_consume()),
                   context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return TPK(invoke(lib.pgp_tpk_from_bytes,
                          ffi.from_buffer(source),
                          len(source)),
                   context=ctx)

    def serialize(self, writer):
        status = invoke(lib.pgp_tpk_serialize,
                        self.ref(),
                        writer.ref())
        if status:
            raise Error._last(self.context())

    def fingerprint(self):
        return Fingerprint(lib.pgp_tpk_fingerprint(self.ref()),
                           context=self.context())

    def merge(self, other):
        new = invoke(lib.pgp_tpk_merge,
                     self.ref_consume(),
                     other.ref_consume())
        if new == ffi.NULL:
            raise Error._last(self.context())
        self.ref_replace(new)

    def dump(self):
        lib.pgp_tpk_dump(self.ref())

class Kind(Enum):
    Message = lib.PGP_ARMOR_KIND_MESSAGE
    PublicKey = lib.PGP_ARMOR_KIND_PUBLICKEY
    SecretKey = lib.PGP_ARMOR_KIND_SECRETKEY
    Signature = lib.PGP_ARMOR_KIND_SIGNATURE
    File = lib.PGP_ARMOR_KIND_FILE
    Any = lib.PGP_ARMOR_KIND_ANY

class ArmorReader(AbstractReader):
    @classmethod
    def new(cls, ctx, inner, kind=Kind.Any):
        ar = ArmorReader(lib.pgp_armor_reader_new(inner.ref(),
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
        aw = ArmorWriter(invoke(lib.pgp_armor_writer_new,
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
    PKESK = lib.PGP_TAG_PKESK
    Signature = lib.PGP_TAG_SIGNATURE
    SKESK = lib.PGP_TAG_SKESK
    OnePassSig = lib.PGP_TAG_ONE_PASS_SIG
    SecretKey = lib.PGP_TAG_SECRET_KEY
    PublicKey = lib.PGP_TAG_PUBLIC_KEY
    SecretSubkey = lib.PGP_TAG_SECRET_SUBKEY
    CompressedData = lib.PGP_TAG_COMPRESSED_DATA
    SED = lib.PGP_TAG_SED
    Marker = lib.PGP_TAG_MARKER
    Literal = lib.PGP_TAG_LITERAL
    Trust = lib.PGP_TAG_TRUST
    UserID = lib.PGP_TAG_USER_ID
    PublicSubkey = lib.PGP_TAG_PUBLIC_SUBKEY
    Unassigned15 = lib.PGP_TAG_UNASSIGNED15
    Unassigned16 = lib.PGP_TAG_UNASSIGNED16
    UserAttribute = lib.PGP_TAG_USER_ATTRIBUTE
    SEIP = lib.PGP_TAG_SEIP
    MDC = lib.PGP_TAG_MDC
    # xxx the rest

class Key(SQObject):
    @property
    def fingerprint(self):
        return Fingerprint(lib.pgp_key_fingerprint(self.ref()))

    @property
    def keyid(self):
        return KeyID(lib.pgp_key_keyid(self.ref()))

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
        buf = lib.pgp_user_id_value(self.ref(), buf_len)
        return ffi.buffer(buf, buf_len[0])

class UserAttribute(SQObject):
    @property
    def value(self):
        buf_len = ffi.new("size_t[1]")
        buf = lib.pgp_user_attribute_value(self.ref(), buf_len)
        return ffi.buffer(buf, buf_len[0])

class SKESK(SQObject):
    def decrypt(self, passphrase):
        algo = ffi.new("uint8_t[1]")
        key = ffi.new("uint8_t[32]")
        key_len = ffi.new("size_t[1]")
        key_len[0] = len(key)
        invoke(lib.pgp_skesk_decrypt,
               self.ref(),
               ffi.from_buffer(passphrase),
               len(passphrase),
               algo, key, key_len)
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
        return Tag(lib.pgp_packet_tag(self.ref()))
    def __str__(self):
        return "<Packet tag={}>".format(self.tag)
    def match(self):
        return self._map[self.tag](self.ref(), context=self.context(), owner=self)

class PacketParserResult(SQObject):
    _del = lib.pgp_packet_parser_result_free

    def packet_parser(self):
        ref = lib.pgp_packet_parser_result_packet_parser(self.ref())
        if ref != ffi.NULL:
            # Success!  We are consumed.
            self._delete(skip_free=True)
            return PacketParser(ref, context=self.context())
        else:
            return None

    def eof(self):
        ref = lib.pgp_packet_parser_result_eof(self.ref())
        if ref != ffi.NULL:
            # Success!  We are consumed.
            self._delete(skip_free=True)
            return PacketParserEOF(ref, context=self.context())
        else:
            return None

class PacketParserEOF(SQObject):
    _del = lib.pgp_packet_parser_eof_free

    def is_message(self):
        return bool(lib.pgp_packet_parser_eof_is_message(self.ref()))

class PacketParser(SQObject):
    _del = lib.pgp_packet_parser_free

    @classmethod
    def from_reader(cls, ctx, reader):
        return PacketParserResult(
            invoke(lib.pgp_packet_parser_from_reader, reader.ref()),
            context=ctx)

    @classmethod
    def open(cls, ctx, filename):
        return PacketParserResult(
            invoke(lib.pgp_packet_parser_from_file, filename.encode()),
            context=ctx)

    @classmethod
    def from_bytes(cls, ctx, source):
        return PacketParserResult(
            invoke(lib.pgp_packet_parser_from_bytes,
                   ffi.from_buffer(source),
                   len(source)),
            context=ctx)

    @property
    def has_packet(self):
        return self.ref() != ffi.NULL

    @property
    def packet(self):
        return Packet(lib.pgp_packet_parser_packet(self.ref()),
                      context=self.context(),
                      owner=self)

    @property
    def recursion_depth(self):
        return lib.pgp_packet_parser_recursion_depth(self.ref())

    def next(self):
        packet = ffi.new("pgp_packet_t[1]")
        old_rl = ffi.new("uint8_t[1]")
        ppr = ffi.new("pgp_packet_parser_result_t[1]")
        new_rl = ffi.new("uint8_t[1]")

        invoke(lib.pgp_packet_parser_next,
               self.ref_consume(),
               packet,
               ppr)

        return (Packet(packet[0]), PacketParserResult(ppr[0], self.context()))

    def recurse(self):
        packet = ffi.new("pgp_packet_t[1]")
        old_rl = ffi.new("uint8_t[1]")
        ppr = ffi.new("pgp_packet_parser_result_t[1]")
        new_rl = ffi.new("uint8_t[1]")

        invoke(lib.pgp_packet_parser_recurse,
               self.ref_consume(),
               packet,
               ppr)

        return (Packet(packet[0]), PacketParserResult(ppr[0], self.context()))

    def buffer_unread_content(self):
        buf_len = ffi.new("size_t[1]")
        buf = invoke(lib.pgp_packet_parser_buffer_unread_content,
                     self.ref(),
                     buf_len)
        return ffi.buffer(buf, buf_len[0])

    def decrypt(self, algo, key):
        invoke(lib.pgp_packet_parser_decrypt,
               self.ref(),
               algo,
               ffi.from_buffer(key),
               len(key))
