# Makefile for Sequoia's bindings.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=

CARGO	?= cargo
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))

VERSION		?= $(shell grep '^version[[:space:]]*=[[:space:]]*' Cargo.toml | cut -d'"' -f2)
VERSION_MAJOR	= $(shell echo $(VERSION) | cut -d'.' -f1)

# Tools.
INSTALL		?= install

# Make sure subprocesses pick these up.
export PREFIX
export DESTDIR

all: build

.PHONY: build
build:
	:

# Testing and examples.
.PHONY: test check
test check:
	:

.PHONY: examples
examples:
	$(MAKE) -Cexamples

# Installation.
.PHONY: build-release
build-release:
	:

.PHONY: install
install:
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/pkgconfig
	sed -e 's|VERSION|$(VERSION)|g' \
	    -e 's|PREFIX|$(PREFIX)|g' \
		sequoia-openpgp.pc.in \
		> $(DESTDIR)$(PREFIX)/share/pkgconfig/sequoia-openpgp.pc
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include/sequoia \
		include/sequoia/*.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_openpgp_ffi.so \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.so.$(VERSION)
	ln -fs libsequoia_openpgp_ffi.so.$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.so.$(VERSION_MAJOR)
	ln -fs libsequoia_openpgp_ffi.so.$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.so
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_openpgp_ffi.a \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.a

# Housekeeping.
.PHONY: clean
clean:
	$(MAKE) -Cexamples clean
