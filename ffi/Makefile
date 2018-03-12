# Makefile for Sequoia's bindings.

# Configuration.
PREFIX		?= /usr/local
DESTDIR		?=

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

.PHONY: install
install:

# Housekeeping.
.PHONY: clean
clean:
	$(MAKE) -Cexamples clean
