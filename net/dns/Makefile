# Makefile — CUBE DNS module. Portable across Android/Termux/Linux/macOS.

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Darwin)
  CC     ?= cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
RANLIB ?= $(shell command -v ranlib 2>/dev/null || command -v llvm-ranlib 2>/dev/null || echo ranlib)
else ifeq ($(UNAME_S),Linux)
  CC     ?= cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
RANLIB ?= $(shell command -v ranlib 2>/dev/null || command -v llvm-ranlib 2>/dev/null || echo ranlib)
else
  CC     ?= aarch64-linux-android-clang
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
RANLIB ?= $(shell command -v ranlib 2>/dev/null || command -v llvm-ranlib 2>/dev/null || echo ranlib)
endif

CFLAGS  = -O2 -Wall -Wextra \
          -Iinclude \
          -Isrc/proto \
          -Isrc/transport \
          -Isrc/runtime \
          -Isrc/api \
          -I../crisptls/include
LDFLAGS =
CRISPTLS_LIB = ../crisptls/build/libcrisptls.a
LIBS    = $(CRISPTLS_LIB) -lsodium

SRC_DIRS = src/api src/proto src/transport src/cache src/runtime
SRCS     = $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c))
OBJS     = $(patsubst src/%.c, build/%.o, $(SRCS))

TEST_SRC = ../../tests/test_dns.c
TEST_BIN = ../../tests/test_dns

LIB      = build/libdns.a

.PHONY: all clean test info

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libdns.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

$(TEST_BIN): $(TEST_SRC) $(OBJS)
	$(CC) $(CFLAGS) $(TEST_SRC) $(OBJS) -o $(TEST_BIN) $(LDFLAGS) $(LIBS)
	@echo "  $(TEST_BIN) built"

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f build/*.o build/*.a $(TEST_BIN)
	@echo "  cleaned"

info:
	@echo "CC:     $(CC)"
	@echo "AR:     $(AR)"
	@echo "OS:     $(UNAME_S)"
	@echo "LIBS:   $(LIBS)"
