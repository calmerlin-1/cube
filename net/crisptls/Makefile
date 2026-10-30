# Makefile — CRISP TLS. Portable across Android, Linux, macOS, Windows.

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Darwin)
  CC ?= cc
  AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
else ifeq ($(UNAME_S),Linux)
  CC ?= cc
  AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
else
  CC ?= cc
  AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
endif

SRC_DIRS = src/api \
           src/quic \
           src/session \
           src/certs \
           src/crypto \
           src/policy \
           src/policy/profiles \
           src/proto/record \
           src/proto/handshake \
           src/proto/extensions \
           src/proto/keyschedule \
           src/proto/state \
           src/runtime

SRCS = $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c))
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

LIB = build/libcrisptls.a
CORE = build/crisptls

# DNS lib lives next door
DNS_LIB = ../dns/build/libdns.a
UTILS_LIB = ../../utils/build/libutils.a
DNS_INC = ../dns/include

CFLAGS ?= -g -O1 -Wall -Wextra -I../.. \
         -Isrc/quic \
         -Iinclude \
         -Isrc/crypto \
         -Isrc/runtime \
         -Isrc/policy \
         -Isrc/session \
         -Isrc/policy/profiles \
         -Isrc/proto/record \
         -Isrc/proto/handshake \
         -Isrc/proto/extensions \
         -Isrc/proto/keyschedule \
         -Isrc/proto/state \
         -I../../utils

LIBS = -lsodium

.PHONY: all clean info

all: $(LIB) $(CORE)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libcrisptls.a built with $(words $(OBJS)) objects"

$(CORE): core.c $(LIB) $(DNS_LIB) $(UTILS_LIB)
	$(CC) $(CFLAGS) -I$(DNS_INC) core.c $(LIB) $(DNS_LIB) $(UTILS_LIB) $(LIBS) -s -o $@
	@echo "  $(CORE) built"

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	find build -name '*.o' -delete ; rm -f build/*.a $(CORE)
	@echo "  cleaned"

info:
	@echo "CC:    $(CC)"
	@echo "AR:    $(AR)"
	@echo "OS:    $(UNAME_S)"
	@echo "Arch:  $(shell uname -m)"
	@echo "LIBS:  $(LIBS)"
