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

# Build the right library
ifeq ($(shell uname -s), Darwin)
	_SEQ_LIB_EXT	= dylib
else
	_SEQ_LIB_EXT	= so
endif

# Tools.
ifeq ($(shell uname -s), Darwin)
	INSTALL		?= ginstall
else
	INSTALL		?= install
endif

# Make sure subprocesses pick these up.
export PREFIX
export DESTDIR

# $(1) = install dir
# $(2) = whether to set libdir and prefix to $(1) (empty string = false)
sequoia_pc = \
	sed -e 's|VERSION|$(VERSION)|g' \
	    $(if $(2),-e 's|PREFIX|$(shell pwd)|g',-e's|PREFIX|$(PREFIX)|g') \
	    $(if $(2),-e 's|libdir=.*|libdir=$(1)|g') \
	  sequoia.pc.in \
	  >$(1)/sequoia.pc

all: build

.PHONY: build
build:
	$(MAKE) -Clang/python build
	$(call sequoia_pc,$(CARGO_TARGET_DIR)/debug,true)

# Testing and examples.
.PHONY: test check
test check:
	$(MAKE) -Clang/python test

.PHONY: examples
examples:
	$(MAKE) -Cexamples --always-make

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --package sequoia-ffi
	$(MAKE) -Clang/python build-release
	$(call sequoia_pc,$(CARGO_TARGET_DIR)/release,true)
	$(MAKE) -C../store install

.PHONY: install
install: build-release
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/pkgconfig
	$(call sequoia_pc,$(DESTDIR)$(PREFIX)/share/pkgconfig,)
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include include/sequoia.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include/sequoia \
		include/sequoia/*.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_ffi.$(_SEQ_LIB_EXT) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.$(_SEQ_LIB_EXT).$(VERSION)
	ln -fs libsequoia_ffi.$(_SEQ_LIB_EXT).$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.$(_SEQ_LIB_EXT).$(VERSION_MAJOR)
	ln -fs libsequoia_ffi.$(_SEQ_LIB_EXT).$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.$(_SEQ_LIB_EXT)
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_ffi.a \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_ffi.a
	$(MAKE) -C../store install
	# Now the bindings.
	$(MAKE) -Clang/python install

# Housekeeping.
.PHONY: clean
clean:
	$(MAKE) -Cexamples clean
	$(MAKE) -Clang/python clean
