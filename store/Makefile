# Configuration.
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))

# Tools.
CARGO	?= cargo

ifneq ($(filter Darwin BSD,$(shell uname -s)),"")
	INSTALL		?= ginstall
else
	INSTALL		?= install
endif

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --package sequoia-store

.PHONY: install
install: build-release
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib/sequoia
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/lib/sequoia \
	    $(CARGO_TARGET_DIR)/release/sequoia-public-key-store
