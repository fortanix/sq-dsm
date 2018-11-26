CARGO	?= cargo
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
SQ	?= $(CARGO_TARGET_DIR)/debug/sq

all: src/sq-usage.rs

# Maintenance.
.PHONY: update-usage
update-usage: src/sq-usage.rs

src/sq-usage.rs: make-usage.sh $(SQ)
	sh make-usage.sh $(SQ) >$@
