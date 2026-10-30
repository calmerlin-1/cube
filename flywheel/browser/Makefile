# Makefile — flywheel/browser: cube's native page renderer.
CC ?= cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)

CFLAGS = -O2 -Wall -Wextra -Iinclude \
         -I../html/include -I../dom/include -I../css/include \
         -I../js/include -I../js/src -I../js/src/runtime
SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))
LIB  = build/libbrowser_native.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libbrowser_native.a built"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	rm -f build/*.o build/*.a
