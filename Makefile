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
# The packages to build, test and document, e.g., "-p sequoia-openpgp"
CARGO_PACKAGES	?= --all
# Additional arguments to pass to cargo test, e.g., "--doc".
CARGO_TEST_ARGS	?=
# Version as stated in the top-level Cargo.toml.
VERSION		?= $(shell grep '^version[[:space:]]*=[[:space:]]*' openpgp/Cargo.toml\
                           | cut -d'"' -f2)

# Signing source distributions.
SIGN_WITH	?= XXXXXXXXXXXXXXXX

# Tools.
CARGO		?= cargo
GIT		?= git
TAR		?= tar
GZIP		?= gzip
XZ		?= xz
GPG		?= gpg
CODESPELL	?= codespell
CODESPELL_FLAGS ?= --disable-colors --write-changes

SOURCE_DATE_EPOCH = $(shell git show -s --no-show-signature --format=%cI)
TAR_FLAGS = --sort=name \
      --mtime="$(SOURCE_DATE_EPOCH)" \
      --owner=0 --group=0 --numeric-owner \
      --mode=go=rX,u+rw,a-s \
      --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime

ifneq ($(filter Darwin %BSD,$(shell uname -s)),)
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
export CARGO_PACKAGES
export CARGO_TEST_ARGS

all: build examples

.PHONY: build
build:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) build $(CARGO_FLAGS) $(CARGO_PACKAGES)
	$(MAKE) -Copenpgp-ffi build
	$(MAKE) -Cffi build

# Testing and examples.
#
# If CARGO_PACKAGES contains a package specification ("-p foo"), then
# only run cargo test.
.PHONY: test check
test check:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) test $(CARGO_FLAGS) $(CARGO_PACKAGES) $(CARGO_TEST_ARGS)
	if echo "$(CARGO_PACKAGES)" | grep -q -E -e '(^| )[-]p +.'; \
	then \
		echo 'WARNING: Not running other tests, because $$CARGO_PACKAGES specifies a package.'; \
	else \
		$(MAKE) -Copenpgp-ffi test; \
		$(MAKE) -Cffi test; \
		$(MAKE) examples; \
	fi

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
	    $(CARGO) doc $(CARGO_FLAGS) --no-deps $(CARGO_PACKAGES)

# Installation.
.PHONY: build-release
build-release:
	$(MAKE) -Copenpgp-ffi build-release
	$(MAKE) -Cffi build-release
	$(MAKE) -Csq build-release
	$(MAKE) -Csqv build-release
	$(MAKE) -Csop build-release

.PHONY: install
install: build-release
	$(MAKE) -Copenpgp-ffi install
	$(MAKE) -Cffi install
	$(MAKE) -Csq install
	$(MAKE) -Csqv install
	$(MAKE) -Csop install

# Infrastructure for creating source distributions.
.PHONY: dist
dist:	$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar.pgp.gz \
	$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar.pgp.xz

$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION):
	$(GIT) clone . $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION)
	cd $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION) && \
		rm -rf .git

$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar: \
		$(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION)
	$(TAR) $(TAR_FLAGS) -cf $@ -C $(CARGO_TARGET_DIR)/dist sequoia-$(VERSION)

%.gz: %
	$(GZIP) -c "$<" >"$@"

%.xz: %
	$(XZ) -c "$<" >"$@"

%.pgp: %
	$(GPG) --local-user "$(SIGN_WITH)" --compression-algo=none \
		--sign --output "$@" "$<"

# Testing source distributions.
.PHONY: dist-test dist-check
dist-test dist-check: $(CARGO_TARGET_DIR)/dist/sequoia-$(VERSION).tar.pgp.gz
	mkdir -p "$(CARGO_TARGET_DIR)/dist-check"
	rm -rf "$(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION)"
	$(GZIP) -d -c "$<" |\
		$(GPG) -o - --verify |\
		$(TAR) xf - -C "$(CARGO_TARGET_DIR)/dist-check"
	cd "$(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION)" && \
		CARGO_HOME=$$(mktemp -d) $(MAKE) test CARGO_FLAGS=--locked
	rm -rf "$(CARGO_TARGET_DIR)/dist-check/sequoia-$(VERSION)"

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
	for TOML in */Cargo.toml ; do \
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
	  -L "ede,iff,mut,nd,te,uint,KeyServer,keyserver,Keyserver,keyservers,Keyservers,keypair,keypairs,KeyPair,fpr,dedup" \
	  -S "*.bin,*.gpg,*.pgp,./.git,data,highlight.js,*/target,Makefile"
