# Makefile — flywheel/css

CC ?= $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || echo cc)
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
# Prefer llvm-ar (Termux) if GNU ar isn't actually functional

SRC_DIRS = src/api src/tokenizer src/parser src/match src/runtime
SRCS = $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c))
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

CFLAGS ?= -O2 -Wall -Wextra -Iinclude -Isrc/tokenizer -Isrc/parser -Isrc/runtime
LIB    = build/libcss.a

.PHONY: all clean test test_css fuzz fuzz_hard fuzz_chaos

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libcss.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

build/test_css: tests/test_css.c $(OBJS)
	$(CC) $(CFLAGS) tests/test_css.c $(OBJS) -o $@
	@echo "  built: build/test_css"

build/fuzz_css: tests/fuzz_css.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_css.c $(OBJS) -o $@
	@echo "  built: build/fuzz_css"

build/fuzz_hard: tests/fuzz_hard.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_hard.c $(OBJS) -o $@
	@echo "  built: build/fuzz_hard"

build/fuzz_chaos: tests/fuzz_chaos.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_chaos.c $(OBJS) -o $@
	@echo "  built: build/fuzz_chaos"

test: build/test_css build/fuzz_css
	./build/test_css
	./build/fuzz_css

test_css: build/test_css
	./build/test_css

fuzz: build/fuzz_css
	./build/fuzz_css

fuzz_hard: build/fuzz_hard
	./build/fuzz_hard

fuzz_chaos: build/fuzz_chaos
	./build/fuzz_chaos

clean:
	rm -f build/*.o build/*.a build/test_css build/fuzz_css build/fuzz_hard build/fuzz_chaos
	@echo "  cleaned"
