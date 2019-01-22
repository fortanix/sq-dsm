# Makefile for examples written in C.

CARGO	?= cargo
CARGO_TARGET_DIR	?= $(shell pwd)/../../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))

TARGETS = example reader parser encrypt-for armor type-safety-demo
CFLAGS  = -I../include -O0 -g -Wall -Werror
LDFLAGS = -L$(CARGO_TARGET_DIR)/debug -lsequoia_openpgp_ffi

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): ../include/sequoia/openpgp.h
