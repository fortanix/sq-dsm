from os.path import join, dirname
from cffi import FFI, error
from itertools import chain

inc = join(dirname(__file__), '../../../include/sequoia')
defs = "".join(l
               for l in chain(open(join(inc, "error.h")).readlines(),
                              open(join(inc, "core.h")).readlines(),
                              open(join(inc, "openpgp/crypto.h")).readlines(),
                              open(join(inc, "openpgp.h")).readlines(),
                              open(join(inc, "net.h")).readlines(),
                              open(join(inc, "store.h")).readlines())
               if not l.startswith('#'))

defs = defs.replace("INT_MAX", "{}".format(1<<31))

ffibuilder = FFI()
ffibuilder.set_source('_sequoia',
                      '#include <sequoia.h>',
                      libraries=['sequoia_ffi'])

# cffi magic to make time_t work.
ffibuilder.cdef('typedef int... time_t;')

try:
    ffibuilder.cdef(defs, override=True)
except error.CDefError as e:
    try:
        current_decl = e.args[1]
        linenum = current_decl.coord.line

        print("ATTENTION:  Line numbers are not very reliable :(")
        print()
        print("{}: {}".format(linenum, e.args[0]))
        print()

        for i, l in enumerate(defs.split("\n")):
            if i < linenum - 5 or i > linenum + 5:
                continue
            print("{}: {}".format(i + 1, l))
        print()

        print("AST:", e.args[1])
        print()
    except (AttributeError, TypeError, IndexError):
        pass

    raise

if __name__ == '__main__':
    ffibuilder.compile(verbose=True)
