# Makefile for Sequoia.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=
CARGO_FLAGS	?=
# cargo's "target" directory.  Normally, this is in the root
# directory of the project, but it can be overriden by setting
# CARGO_TARGET_DIR.
CARGO_TARGET_DIR	?= $(shell pwd)/target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
# The tests to run.
CARGO_TEST_ARGS	?= --all

# Signing source distributions.
SIGN_WITH	?= XXXXXXXXXXXXXXXX

# Tools.
CARGO		?= cargo
GIT		?= git
TAR		?= tar
XZ		?= xz
GPG		?= gpg

ifeq ($(shell uname -s), Darwin)
	INSTALL	?= ginstall
else
	INSTALL	?= install
endif

VERSION		?= $(shell grep '^version[[:space:]]*=[[:space:]]*' Cargo.toml | cut -d'"' -f2)

# Make sure subprocesses pick these up.
export PREFIX
export DESTDIR
export CARGO_FLAGS
export CARGO_TARGET_DIR
export CARGO_TEST_ARGS

all: build examples

.PHONY: build
build:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) build $(CARGO_FLAGS) --all
	$(MAKE) -Copenpgp-ffi build
	$(MAKE) -Cffi build

# Testing and examples.
.PHONY: test check
test check:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) test $(CARGO_FLAGS) $(CARGO_TEST_ARGS)
	$(MAKE) -Copenpgp-ffi test
	$(MAKE) -Cffi test
	$(MAKE) examples

.PHONY: examples
examples:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --examples
	$(MAKE) -Copenpgp-ffi examples
	$(MAKE) -Cffi examples

# Documentation.
.PHONY: doc
doc:
	RUSTDOCFLAGS="$$RUSTDOCFLAGS --html-in-header doc/highlight.js/9.12.0/inc.html" \
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) doc $(CARGO_FLAGS) --no-deps --all
	cp --recursive doc/highlight.js $(CARGO_TARGET_DIR)/doc

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --all
	$(MAKE) -Copenpgp-ffi build-release
	$(MAKE) -Cffi build-release

.PHONY: install
install: build-release
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/lib/sequoia \
	    $(CARGO_TARGET_DIR)/release/sequoia-public-key-store
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/bin \
	    $(CARGO_TARGET_DIR)/release/sq
	$(MAKE) -Copenpgp-ffi install
	$(MAKE) -Cffi install
	$(MAKE) -Csqv install

# Infrastructure for creating source distributions.
.PHONY: dist
dist: $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar.xz.sig

$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION):
	$(GIT) clone . $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION)
	cd $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION) && \
		mkdir .cargo && \
		CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
		    $(CARGO) vendor $(CARGO_FLAGS) \
			| sed 's/^directory = ".*"$$/directory = "vendor"/' \
			> .cargo/config && \
		rm -rf .git

$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar: \
		$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION)
	$(TAR) cf $@ -C $(CARGO_TARGET_DIR)/dist sequoia-$(VERSION)

%.xz: %
	$(XZ) -c $< >$@

%.sig: %
	$(GPG) --local-user $(SIGN_WITH) --detach-sign --armor $<

.PHONY: dist-test dist-check
dist-test dist-check: $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar.xz
	rm -rf $(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION)
	mkdir -p $(CARGO_TARGET_DIR)/dist-check
	$(TAR) xf $< -C $(CARGO_TARGET_DIR)/dist-check
	cd $(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION) && \
		CARGO_HOME=$$(mktemp -d) $(MAKE) test CARGO_FLAGS=--frozen
	rm -rf $(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION)

# Housekeeping.
.PHONY: clean
clean:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) $(CARGO_FLAGS) clean
	$(MAKE) -Copenpgp-ffi clean
	$(MAKE) -Cffi clean
