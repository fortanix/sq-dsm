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
# $(2) = whether to set libdir to $(1) (empty string = false)
sequoia_openpgp_pc = \
	sed -e 's|VERSION|$(VERSION)|g' \
	    -e 's|PREFIX|$(shell pwd)|g' \
	    $(if $(2),-e 's|libdir=.*|libdir=$(1)|g') \
	  sequoia-openpgp.pc.in \
	  > $(1)/sequoia-openpgp.pc

all: build

.PHONY: build
build:
	$(call sequoia_openpgp_pc,$(CARGO_TARGET_DIR)/debug,true)

.PHONY: force-build
force-build:
	cd .. ; cargo build -p sequoia-openpgp-ffi

# Testing and examples.
.PHONY: test check
test check: check-headers

# Header files.
.PHONY: check-headers
check-headers: force-build
	nm -g --defined-only \
		$(CARGO_TARGET_DIR)/debug/libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT) \
		| cut -d' ' -f3 | sort -u | grep pgp_ \
		| while read SYM ; \
			do git grep -q "$$SYM" include || echo $$SYM ; \
		done | tee $(CARGO_TARGET_DIR)/debug/.check-headers ; \
	! test -s $(CARGO_TARGET_DIR)/debug/.check-headers

.PHONY: examples
examples:
	$(MAKE) -Cexamples

# Installation.
.PHONY: build-release
build-release:
	$(call sequoia_openpgp_pc,$(CARGO_TARGET_DIR)/release,true)

.PHONY: install
install:
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/pkgconfig
	$(call sequoia_openpgp_pc,$(DESTDIR)$(PREFIX)/share/pkgconfig,)
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/include/sequoia \
		include/sequoia/*.h
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT).$(VERSION)
	ln -fs libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT).$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT).$(VERSION_MAJOR)
	ln -fs libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT).$(VERSION) \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.$(_SEQ_LIB_EXT)
	$(INSTALL) $(CARGO_TARGET_DIR)/release/libsequoia_openpgp_ffi.a \
		$(DESTDIR)$(PREFIX)/lib/libsequoia_openpgp_ffi.a

# Housekeeping.
.PHONY: clean
clean:
	$(MAKE) -Cexamples clean
