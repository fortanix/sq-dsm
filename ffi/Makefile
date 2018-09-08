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
	sed -e 's|VERSION|$(VERSION)|g' \
	    -e 's|PREFIX|$(shell pwd)|g' \
            -e 's|libdir=.*|libdir='"$(CARGO_TARGET_DIR)"'/debug|g' \
		sequoia.pc.in \
		> $(CARGO_TARGET_DIR)/debug/sequoia.pc

# Testing and examples.
.PHONY: test check
test check:

.PHONY: examples
examples:
	$(MAKE) -Cexamples

# Installation.
.PHONY: build-release
build-release:

.PHONY: install
install: sequoia.pc
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/pkgconfig
	sed -e 's|VERSION|$(VERSION)|g' \
	    -e 's|PREFIX|$(PREFIX)|g' \
		sequoia.pc.in \
		> $(DESTDIR)$(PREFIX)/share/pkgconfig/sequoia.pc
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include include/sequoia.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include/sequoia \
		include/sequoia/*.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_ffi.so \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.so.$(VERSION)
	ln -fs libsequoia_ffi.so.$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.so.$(VERSION_MAJOR)
	ln -fs libsequoia_ffi.so.$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.so
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_ffi.a \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.a

# Housekeeping.
.PHONY: clean
clean:
	rm -f sequoia.pc
	$(MAKE) -Cexamples clean
