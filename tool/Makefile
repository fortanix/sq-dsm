CARGO	?= cargo
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
SQ	?= $(CARGO_TARGET_DIR)/debug/sq
SQV	?= $(CARGO_TARGET_DIR)/debug/sqv

all: src/sq-usage.rs src/sqv-usage.rs

.PHONY: update-usage
update-usage: src/sq-usage.rs src/sqv-usage.rs

src/sq-usage.rs: make-usage.sh $(SQ)
	sh make-usage.sh $(SQ) >$@
src/sqv-usage.rs: make-usage.sh $(SQV)
	sh make-usage.sh $(SQV) >$@
