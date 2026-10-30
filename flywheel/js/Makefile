# Makefile — flywheel/js. Portable.

CC ?= $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || echo cc)
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo llvm-ar)

SRC_DIRS = src src/runtime
SRCS = $(wildcard src/*.c) $(wildcard src/runtime/*.c)
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

CFLAGS ?= -O2 -Wall -Wextra -Iinclude -Isrc -Isrc/runtime
LIBS   = -lm

ENGINE = $(OBJS)

.PHONY: all tools clean baseline bench bench_cached targeted vulnfuzz

# Default target is the library only; benchmarks/tools stay opt-in so a
# plain `make` works on every platform (including Windows/MinGW).
all: build/libjs.a
tools: build/bench build/bench_cached build/targeted build/vulnfuzz build/bench_baseline build/profile

build/libjs.a: $(ENGINE)
	@mkdir -p build
	$(AR) rcs $@ $(ENGINE)
	@echo "  libjs.a built"

# Engine objects
build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Benchmarks
build/bench: bench/bench.c $(ENGINE)
	$(CC) $(CFLAGS) bench/bench.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/bench"

build/bench_cached: bench/bench_cached.c $(ENGINE)
	$(CC) $(CFLAGS) bench/bench_cached.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/bench_cached"

build/bench_baseline: bench/bench_baseline.c $(ENGINE)
	$(CC) $(CFLAGS) bench/bench_baseline.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/bench_baseline"

build/targeted: tools/targeted.c $(ENGINE)
	$(CC) $(CFLAGS) tools/targeted.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/targeted"

build/vulnfuzz: tools/vulnfuzz.c $(ENGINE)
	$(CC) $(CFLAGS) tools/vulnfuzz.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/vulnfuzz"

build/profile: tools/profile.c $(ENGINE)
	$(CC) $(CFLAGS) tools/profile.c $(ENGINE) -o $@ $(LIBS)
	@echo "  built: build/profile"

bench: build/bench
	./build/bench

bench_cached: build/bench_cached
	./build/bench_cached

baseline: build/bench_baseline
	./build/bench_baseline | tee bench/baseline.txt

clean:
	rm -f build/*.o build/runtime/*.o
	@echo "  cleaned objects"
