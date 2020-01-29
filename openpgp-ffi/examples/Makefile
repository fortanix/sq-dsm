# Makefile for examples written in C.

CARGO	?= cargo
CARGO_TARGET_DIR	?= $(shell pwd)/../../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))

# We are producing binaries here.
EXAMPLE_TARGET_DIR      ?= $(CARGO_TARGET_DIR)/debug/c-examples/openpgp-ffi

EXAMPLES = \
	example reader parser encrypt-for armor \
	decrypt-with \
	generate-key \
	type-safety-demo use-after-free-demo immutable-reference-demo \
	writer-cookie \

CFLAGS  = -I../include -O0 -g -Wall -Werror
LDFLAGS = -L$(CARGO_TARGET_DIR)/debug -lsequoia_openpgp_ffi

# Prefix our target directory.
TARGETS := $(foreach example,$(EXAMPLES),$(EXAMPLE_TARGET_DIR)/$(example))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): ../include/sequoia/openpgp.h

$(EXAMPLE_TARGET_DIR)/%: %.c
	mkdir -p $(EXAMPLE_TARGET_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<"
