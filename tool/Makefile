CARGO	?= cargo
SQ	?= ../target/debug/sq

all: sq src/usage.rs

sq: ../target/debug/sq

.PHONY: ../target/debug/sq
../target/debug/sq:
	$(CARGO) build

src/usage.rs: make-usage.sh $(SQ)
	sh make-usage.sh $(SQ) >$@
