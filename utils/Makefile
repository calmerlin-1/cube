CC ?= $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || echo aarch64-linux-android-clang)
AR = llvm-ar

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, build/%.o, $(SRCS))
CFLAGS = -O2 -Wall -Wextra -I.

LIB = build/libutils.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libutils.a built with $(words $(OBJS)) objects"

build/%.o: %.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	rm -rf build
	@echo "  cleaned"
