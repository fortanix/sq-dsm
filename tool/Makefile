CARGO	?= cargo
SQ	?= ../target/debug/sq
SQV	?= ../target/debug/sqv

all: src/sq-usage.rs src/sqv-usage.rs

src/sq-usage.rs: make-usage.sh $(SQ)
	sh make-usage.sh $(SQ) >$@
src/sqv-usage.rs: make-usage.sh $(SQV)
	sh make-usage.sh $(SQV) >$@
