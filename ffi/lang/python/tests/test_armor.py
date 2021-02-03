import os
from os.path import join
from tempfile import TemporaryDirectory

from sequoia.core import Context, Reader, Writer
from sequoia.openpgp import ArmorReader, ArmorWriter, Kind

TEST_VECTORS = [0, 1, 2, 3, 47, 48, 49, 50, 51]

ctx = Context(ephemeral=True)

def fn_bin(t):
    return "../../../openpgp/tests/data/armor/test-{}.bin".format(t)

def fn_asc(t):
    return "../../../openpgp/tests/data/armor/test-{}.asc".format(t)

def test_dearmor_file():
    for t in TEST_VECTORS:
        bin = open(fn_bin(t), "rb").read()
        ar = ArmorReader.new(ctx, Reader.open(ctx, fn_asc(t)))
        assert(bin == ar.read())

def test_dearmor_fd():
    for t in TEST_VECTORS:
        bin = open(fn_bin(t), "rb").read()
        fd = os.open(fn_asc(t), os.O_RDONLY)
        ar = ArmorReader.new(ctx, Reader.from_fd(ctx, fd))
        assert(bin == ar.read())

def test_dearmor_bytes():
    for t in TEST_VECTORS:
        bin = open(fn_bin(t), "rb").read()
        asc = open(fn_asc(t), "rb").read()
        ar = ArmorReader.new(ctx, Reader.from_bytes(ctx, asc))
        assert(bin == ar.read())

def test_enarmor_file():
    for t in TEST_VECTORS:
        with TemporaryDirectory() as tmp:
            bin = open(fn_bin(t), "rb").read()
            sink = join(tmp, "a")
            ar = ArmorWriter.new(ctx, Writer.open(ctx, sink), Kind.File)
            ar.write(bin)
            ar.close()

            assert(open(fn_asc(t)).read() == open(sink).read())

def test_enarmor_fd():
    for t in TEST_VECTORS:
        with TemporaryDirectory() as tmp:
            bin = open(fn_bin(t), "rb").read()
            sink = join(tmp, "a")
            fd = os.open(sink, os.O_WRONLY|os.O_CREAT)
            ar = ArmorWriter.new(ctx, Writer.from_fd(ctx, fd), Kind.File)
            ar.write(bin)
            ar.close()

            assert(open(fn_asc(t)).read() == open(sink).read())

def test_enarmor_bytes():
    for t in TEST_VECTORS:
        bin = open(fn_bin(t), "rb").read()
        sink = bytearray(141)
        ar = ArmorWriter.new(ctx, Writer.from_bytes(ctx, sink), Kind.File)
        ar.write(bin)
        ar.close()

        assert(sink.startswith(open(fn_asc(t), "rb").read()))
