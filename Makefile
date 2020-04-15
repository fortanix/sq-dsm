# Makefile for Sequoia.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=
CARGO_FLAGS	?=
# cargo's "target" directory.  Normally, this is in the root
# directory of the project, but it can be overridden by setting
# CARGO_TARGET_DIR.
CARGO_TARGET_DIR	?= $(shell pwd)/target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
# The tests to run.
CARGO_TEST_ARGS	?= --all
# Version as stated in the top-level Cargo.toml.
VERSION		?= $(shell grep '^version[[:space:]]*=[[:space:]]*' Cargo.toml\
                           | cut -d'"' -f2)

# Signing source distributions.
SIGN_WITH	?= XXXXXXXXXXXXXXXX

# Tools.
CARGO		?= cargo
GIT		?= git
TAR		?= tar
XZ		?= xz
GPG		?= gpg
CODESPELL	?= codespell
CODESPELL_FLAGS ?= --disable-colors --write-changes

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
	sed 's|"/|"file://$(shell pwd)/doc/|' doc/highlight.js/9.12.0/inc.html \
		> $(CARGO_TARGET_DIR)/inc.html
	RUSTDOCFLAGS="$$RUSTDOCFLAGS --html-in-header $(CARGO_TARGET_DIR)/inc.html" \
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) doc $(CARGO_FLAGS) --no-deps --all

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --all
	$(MAKE) -Copenpgp-ffi build-release
	$(MAKE) -Cffi build-release
	$(MAKE) -Csqv build-release
	$(MAKE) -Csop build-release

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
	$(MAKE) -Csop install
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/zsh/site-functions \
	    $(CARGO_TARGET_DIR)/_sq
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/zsh/site-functions \
	    $(CARGO_TARGET_DIR)/_sqv
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	$(INSTALL) $(CARGO_TARGET_DIR)/sq.bash \
	    $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sq
	$(INSTALL) $(CARGO_TARGET_DIR)/sqv.bash \
	    $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sqv
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/fish/completions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/fish/completions \
	    $(CARGO_TARGET_DIR)/sq.fish
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/fish/completions \
	    $(CARGO_TARGET_DIR)/sqv.fish

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

.PHONY: sanity-check-versions
sanity-check-versions:
	set -e ; V=$(VERSION) ; VV=$(shell echo $(VERSION) | cut -d. -f1-2) ;\
        bad() { echo "bad $$*." ; exit 1 ; } ;\
	find . -name Cargo.toml | while read TOML ; do \
	  echo -n "$$TOML " ;\
	  grep '^version *=' $$TOML | grep -q $$V || bad version ;\
	  grep '^documentation *=' $$TOML \
	    | egrep -q "($${V})|(https://docs.rs/)" || bad documentation ;\
	  grep '{ *path *= *"' $$TOML | while read L ; do \
	    echo $$L | grep -q $$VV || bad intra-workspace dependency ;\
	  done ;\
	  echo good. ;\
	done

.PHONY: codespell
codespell:
	$(CODESPELL) $(CODESPELL_FLAGS) \
	  -L "ede,iff,mut,nd,te,uint" \
	  -S "*.bin,*.gpg,*.pgp,./.git,./target,data,highlight.js"
