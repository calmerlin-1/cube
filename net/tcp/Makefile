CC      ?= cc
CFLAGS  := -O2 -Wall -Wextra -Iinclude

LIB     := build/libtcp.a
OBJ     := build/tcp.o

.PHONY: all clean test
all: $(LIB)

build:
	@mkdir -p build

build/tcp.o: src/tcp.c include/tcp.h | build
	$(CC) $(CFLAGS) -c src/tcp.c -o $@

$(LIB): build/tcp.o
	$(AR) rcs $@ $<
	@echo "  libtcp.a built"

test: $(LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) tests/tcp_test.c $(LIB) -o build/tcp_test
	@echo "  tcp_test built"
	./build/tcp_test

clean:
	rm -rf build
	@echo "  cleaned"
