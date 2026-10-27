# Makefile — flywheel/html

CC ?= $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || echo aarch64-linux-android-clang)
AR = llvm-ar
# Prefer llvm-ar (Termux) if GNU ar isn't actually functional

SRC_DIRS = src/tokenizer src/parser src/entity src/runtime src/render
SRCS = $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c))
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

CFLAGS ?= -O2 -Wall -Wextra -Iinclude -Isrc/tokenizer -Isrc/parser -Isrc/entity -Isrc/runtime -Isrc/render -I../css/include
LIB    = build/libhtml.a

.PHONY: all clean test test_html test_corpus fuzz fuzz_html

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libhtml.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"


build/test_format: tests/test_format.c $(OBJS)
	$(CC) $(CFLAGS) tests/test_format.c $(OBJS) -o $@
	@echo "  built: build/test_format"
build/test_html: tests/test_html.c $(OBJS)
	$(CC) $(CFLAGS) tests/test_html.c $(OBJS) -o $@
	@echo "  built: build/test_html"

CSS_LIB = ../css/build/libcss.a

build/test_corpus: tests/test_corpus.c $(OBJS) $(CSS_LIB)
	$(CC) $(CFLAGS) -I../css/include tests/test_corpus.c $(OBJS) $(CSS_LIB) -o $@
	@echo "  built: build/test_corpus"

build/test_extract: tests/test_extract.c $(OBJS)
	$(CC) $(CFLAGS) tests/test_extract.c $(OBJS) -o $@
	@echo "  built: build/test_extract"



build/fuzz_html: tests/fuzz_html.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_html.c $(OBJS) -o $@
	@echo "  built: build/fuzz_html"

build/fuzz_html_hard: tests/fuzz_html_hard.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_html_hard.c $(OBJS) -o $@
	@echo "  built: build/fuzz_html_hard"

build/fuzz_html_chaos: tests/fuzz_html_chaos.c $(OBJS)
	$(CC) $(CFLAGS) tests/fuzz_html_chaos.c $(OBJS) -o $@
	@echo "  built: build/fuzz_html_chaos"

test: build/test_html build/fuzz_html
	./build/test_html
	./build/fuzz_html

test_html: build/test_html
	./build/test_html

fuzz: build/fuzz_html
	./build/fuzz_html

fuzz_hard: build/fuzz_html_hard
	./build/fuzz_html_hard

fuzz_chaos: build/fuzz_html_chaos
	./build/fuzz_html_chaos

clean:
	rm -f build/*.o build/*.a build/test_html build/test_corpus build/fuzz_html build/fuzz_html_hard build/fuzz_html_chaos
	@echo "  cleaned"
