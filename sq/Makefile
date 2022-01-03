# Configuration.
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
SQ	?= $(CARGO_TARGET_DIR)/debug/sq

# Tools.
CARGO	?= cargo

ifneq ($(filter Darwin %BSD,$(shell uname -s)),)
	INSTALL		?= ginstall
else
	INSTALL		?= install
endif

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --package sequoia-sq
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

test-dsm:
	./tests/dsm/key_expiration.sh --rsa2k
	./tests/dsm/key_expiration.sh --rsa3k
	./tests/dsm/key_expiration.sh --rsa4k
	./tests/dsm/key_expiration.sh --p256
	./tests/dsm/key_expiration.sh --p384
	./tests/dsm/key_expiration.sh --p521
	./tests/dsm/key_expiration.sh --cv25519
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --rsa2k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --rsa3k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --rsa4k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --p256
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --p384
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --p521
	./tests/dsm/extract_dsm_import_gpg_auto.tcl --cv25519
	./tests/dsm/sq_roundtrips.sh --rsa2k
	./tests/dsm/sq_roundtrips.sh --rsa3k
	./tests/dsm/sq_roundtrips.sh --rsa4k
	./tests/dsm/sq_roundtrips.sh --p256
	./tests/dsm/sq_roundtrips.sh --p384
	./tests/dsm/sq_roundtrips.sh --p521
	./tests/dsm/sq_roundtrips.sh --cv25519
