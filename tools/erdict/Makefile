# Makefile — erdict. Search + analyze + patch for C source.

UNAME_S := $(shell uname -s 2>/dev/null || echo Linux)
ifeq ($(UNAME_S),Darwin)
  CC ?= cc
else ifeq ($(UNAME_S),Linux)
  CC ?= cc
else
  CC ?= cc
endif

CFLAGS = -O2 -Wall -Wextra -I.
SRCS = main.c io.c strutil.c ws.c pattern.c \
       output.c symbols.c walk.c \
       search.c range.c structure.c syntax.c stats.c patch.c journal.c check.c tree.c query.c rename_tree.c hash.c mflags.c
OBJS = $(patsubst %.c,build/%.o,$(SRCS))

BIN = erdict

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@
	@echo "  erdict built"

build/%.o: %.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(BIN)
	@echo "  cleaned"

test: $(BIN)
	@./tests/run_tests.sh
