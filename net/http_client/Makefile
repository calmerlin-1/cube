# Makefile — CUBE HTTP client. Raw HTTP/1.x over plain TCP.
# No URL parsing, no DNS beyond what connect() needs, no TLS.
# Portable across Android/Termux/Linux/macOS.

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

CC     ?= cc
AR     = llvm-ar
RANLIB = llvm-ranlib

SRC_DIRS = src src/http2

SRCS = $(filter-out src/test.c, $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c)))
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

LIB = build/libhttp_client.a

CFLAGS = -O2 -I../../utils -I../.. -Wall -Wextra -Iinclude -Isrc/http2
LIBS   =

.PHONY: all clean info test

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libhttp_client.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"


# ---- tests ----
TESTS = tests/test_http10

tests/test_http10: tests/test_http10.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) -o $@
	@echo "  $@"

test: $(TESTS)
	@for t in $(TESTS); do \
		echo "== $$t =="; \
		./$$t; \
	done

clean:
	rm -f build/*.o build/*.a
	@echo "  cleaned"

info:
	@echo "CC:    $(CC)"
	@echo "AR:    $(AR)"
	@echo "OS:    $(UNAME_S)"
	@echo "Arch:  $(shell uname -m)"
	@echo "LIBS:  $(LIBS)"
