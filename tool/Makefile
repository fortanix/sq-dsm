# Configuration.
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
SQ	?= $(CARGO_TARGET_DIR)/debug/sq

# Tools.
CARGO	?= cargo

ifneq ($(filter Darwin FreeBSD,$(shell uname -s)),"")
	INSTALL		?= ginstall
else
	INSTALL		?= install
endif

all: src/sq-usage.rs

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --package sequoia-tool
	$(MAKE) -C../store build-release

.PHONY: install
install: build-release
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/bin $(CARGO_TARGET_DIR)/release/sq
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/zsh/site-functions \
	    $(CARGO_TARGET_DIR)/_sq
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	$(INSTALL) $(CARGO_TARGET_DIR)/sq.bash \
	    $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sq
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/fish/completions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/fish/completions \
	    $(CARGO_TARGET_DIR)/sq.fish
	$(MAKE) -C../store install

# Maintenance.
.PHONY: update-usage
update-usage: src/sq-usage.rs

src/sq-usage.rs: make-usage.sh $(SQ)
	sh make-usage.sh $(SQ) >$@~ && mv $@~ $@
