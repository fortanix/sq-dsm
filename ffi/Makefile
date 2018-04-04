# Makefile for Sequoia's bindings.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=

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

# Testing and examples.
.PHONY: test check
test check:

.PHONY: examples
examples:
	$(MAKE) -Cexamples

# Installation.
.PHONY: build-release
build-release:

sequoia.pc: sequoia.pc.in
	sed -e 's|VERSION|$(VERSION)|g' \
	    -e 's|PREFIX|$(PREFIX)|g' \
		$< >$@

.PHONY: install
install: sequoia.pc
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/pkgconfig
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/pkgconfig \
		sequoia.pc
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include include/sequoia.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include/sequoia \
		include/sequoia/*.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) ../target/release/libsequoia_ffi.so \
		$(DESTDIR)$(PREFIX)/lib/libsequoia.so.$(VERSION)
	ln -fs libsequoia.so.$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia.so.$(VERSION_MAJOR)
	$(INSTALL) ../target/release/libsequoia_ffi.a \
		$(DESTDIR)$(PREFIX)/lib/libsequoia.a

# Housekeeping.
.PHONY: clean
clean:
	rm -f sequoia.pc
	$(MAKE) -Cexamples clean
