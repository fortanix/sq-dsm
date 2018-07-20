# Makefile for examples written in C.

TARGETS = example keyserver configure reader parser encrypt-for
CFLAGS  = -I../include -O0 -g -Wall
LDFLAGS = -L../../target/debug -lsequoia_ffi

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): ../include/sequoia.h
