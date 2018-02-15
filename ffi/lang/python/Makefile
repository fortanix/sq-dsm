# Makefile for Sequoia's Python bindings.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=
CFLAGS		+= -I../../include

# Tools.
PYTHON		?= python3
IPYTHON		?= ipython3
PYTEST		?= pytest-3
INSTALL		?= install

ifneq "$(PYTHON)" "disable"
PY_VERSION	= $(shell $(PYTHON) -c \
	'import sys; print("{0.major}.{0.minor}".format(sys.version_info))')
endif

# Make sure subprocesses pick these up.
export CFLAGS

all: build

.PHONY: build
build: .stamp-build
.stamp-build: sequoia/* ../../include/sequoia/*
ifneq "$(PYTHON)" "disable"
	LDFLAGS=-L../../../target/debug $(PYTHON) setup.py build
	touch $@
endif

# Testing and examples.
.PHONY: test check
test check:
ifneq "$(PYTHON)" "disable"
	LDFLAGS=-L../../../target/debug LD_LIBRARY_PATH=../../../target/debug \
		$(PYTHON) setup.py test
endif

.PHONY: shell
shell: build
ifneq "$(PYTHON)" "disable"
	cp build/*/_sequoia.abi*.so . # XXX can we get setuptools to do that?
	LDFLAGS=-L../../../target/debug LD_LIBRARY_PATH=../../../target/debug \
		$(IPYTHON) -i -c \
'from sequoia.prelude import *; ctx = Context("org.sequoia-pgp.tests.interactive")'
endif

# Installation.
.PHONY: build-release
build-release: .stamp-build-release
.stamp-build-release:
ifneq "$(PYTHON)" "disable"
	rm -f .stamp-build
	$(PYTHON) setup.py clean
	LDFLAGS=-L../../../target/release \
		$(PYTHON) setup.py build
	touch $@
endif

ifneq "$(DESTDIR)" ""
  root_arg=--root=$(DESTDIR)
endif

.PHONY: install
install: build-release
ifneq "$(PYTHON)" "disable"
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib/python$(PY_VERSION)/site-packages

	LDFLAGS=-L../../../target/release \
		$(PYTHON) setup.py install $(root_arg) --prefix=$(PREFIX)
endif

# Housekeeping.
.PHONY: clean
clean:
ifneq "$(PYTHON)" "disable"
	$(PYTHON) setup.py clean
	rm -f _sequoia.*.so
	rm -f .stamp-build .stamp-build-release
endif
