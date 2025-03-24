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
	cargo build
	./tests/dsm/print_dsm_key_info.sh
	./tests/dsm/test_custom_metadata.sh
	./tests/dsm/knownkeys_import_dsm.sh
	./tests/dsm/generate_gpg_import_dsm_auto.tcl
	./tests/dsm/key_expiration.sh -c rsa2k
	./tests/dsm/key_expiration.sh -c rsa3k
	./tests/dsm/key_expiration.sh -c rsa4k
	./tests/dsm/key_expiration.sh -c nistp256
	./tests/dsm/key_expiration.sh -c nistp384
	./tests/dsm/key_expiration.sh -c nistp521
	./tests/dsm/key_expiration.sh -c cv25519
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c rsa2k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c rsa3k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c rsa4k
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c nistp256
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c nistp384
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c nistp521
	./tests/dsm/extract_dsm_import_gpg_auto.tcl -c cv25519
	./tests/dsm/sq_roundtrips.sh -x -c cv25519 # Passing api-key
	./tests/dsm/sq_roundtrips.sh -c rsa2k
	./tests/dsm/sq_roundtrips.sh -c rsa3k
	./tests/dsm/sq_roundtrips.sh -c rsa4k
	./tests/dsm/sq_roundtrips.sh -c nistp256
	./tests/dsm/sq_roundtrips.sh -c nistp384
	./tests/dsm/sq_roundtrips.sh -c nistp521
	./tests/dsm/sq_roundtrips.sh -c cv25519
	./tests/local/generate_keys.sh -c rsa2k
	./tests/local/generate_keys.sh -c rsa3k
	./tests/local/generate_keys.sh -c rsa4k
	./tests/local/generate_keys.sh -c nistp256
	./tests/local/generate_keys.sh -c nistp384
	./tests/local/generate_keys.sh -c nistp521
	./tests/local/generate_keys.sh -c cv25519
