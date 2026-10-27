# Makefile — flywheel/url. Builds liburl.a from the C sources.

CC     ?= cc
AR     = llvm-ar
RANLIB = llvm-ranlib

SRC_DIRS = src src/../data

SRCS = $(wildcard src/*.c) $(wildcard data/*.c)
OBJS = $(patsubst %.c, build/%.o, $(notdir $(SRCS)))

# Need to know full paths for pattern rule
SRCS_FULL = $(wildcard src/*.c) $(wildcard data/*.c)
OBJS_FULL = $(patsubst src/%.c, build/%.o, $(wildcard src/*.c)) \
            $(patsubst data/%.c, build/%.o, $(wildcard data/*.c))

LIB = build/liburl.a

CFLAGS ?= -O2 -Wall -Wextra -Iinclude -Isrc



# ---- throughput tester ----
UTILS_LIB = ../../utils/build/libutils.a
UTILS_INC = ../../utils

tests/url_throughput_tester: tests/url_throughput_tester.c $(LIB)
	$(CC) $(CFLAGS) -I$(UTILS_INC) $< $(LIB) $(UTILS_LIB) -o $@

throughput: tests/url_throughput_tester
	@./tests/url_throughput_tester



# ---- scan parity test ----
tests/scan_parity: tests/scan_parity.c $(LIB)
	$(CC) $(CFLAGS) -I$(UTILS_INC) $< $(LIB) $(UTILS_LIB) -o $@

parity: tests/scan_parity
	@./tests/scan_parity tests/corpus/*.txt



# ---- url field dump tool ----
tests/url_dump: tests/url_dump.c $(LIB)
	$(CC) $(CFLAGS) -I$(UTILS_INC) $< $(LIB) $(UTILS_LIB) -o $@



# ---- url cache tester ----
tests/url_cache_tester: tests/url_cache_tester.c $(LIB)
	$(CC) $(CFLAGS) -I$(UTILS_INC) $< $(LIB) $(UTILS_LIB) -o $@

cached: tests/url_cache_tester
	@./tests/url_cache_tester tests/corpus/repeat.txt



# ---- url_join tester ----
tests/url_join_tester: tests/url_join_tester.c $(LIB)
	$(CC) $(CFLAGS) -I$(UTILS_INC) $< $(LIB) $(UTILS_LIB) -o $@

join: tests/url_join_tester
	@./tests/url_join_tester

.PHONY: all clean info throughput parity cached join

all: $(LIB)

$(LIB): $(OBJS_FULL)
	$(AR) rcs $@ $(OBJS_FULL)
	@echo "  liburl.a built with $(words $(OBJS_FULL)) objects"

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

build/%.o: data/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	rm -f build/*.o build/*.a
	@echo "  cleaned"

info:
	@echo "SRCS: $(SRCS_FULL)"
	@echo "OBJS: $(OBJS_FULL)"
	@echo "CC:   $(CC)"
