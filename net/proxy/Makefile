# Makefile — CUBE proxy module.
CC ?= cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)

CFLAGS = -O2 -Wall -Wextra -Iinclude
SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))
LIB  = build/libproxy.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libproxy.a built"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	rm -f build/*.o build/*.a
