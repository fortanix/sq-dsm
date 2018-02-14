# Makefile for examples written in C.

TARGETS = example keyserver configure
CFLAGS  = -I../src -O0 -g -Wall
LDFLAGS = -L../../target/debug -lsequoia_ffi

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): ../src/sequoia.h
