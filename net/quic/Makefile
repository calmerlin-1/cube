# Makefile — net/quic. Standalone QUIC transport.
# Depends on libcrisptls for crypto primitives.

CC     = cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
RANLIB ?= $(shell command -v ranlib 2>/dev/null || command -v llvm-ranlib 2>/dev/null || echo ranlib)

CRISPTLS_INC  = ../crisptls/include
CRISPTLS_LIB  = ../crisptls/build/libcrisptls.a
DNS_INC       = ../dns/include

SRC_DIRS = src
SRCS = $(foreach d, $(SRC_DIRS), $(wildcard $(d)/*.c))
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

LIB = build/libquic.a

# NOTE: we reach into crisptls internal headers because QUIC needs
# the handshake primitives (clienthello_build, serverhello_parse,
# keyschedule, finished_13) that aren't part of crisptls's public API.
# Long-term these should be re-exported under include/, but for now
# this is pragmatic and contained to net/quic/.
CRISPTLS_SRC = ../crisptls/src
CFLAGS ?= -O2 -Wall -Wextra \
         -Iinclude \
         -I$(CRISPTLS_INC) \
         -I$(CRISPTLS_SRC)/crypto \
         -I$(CRISPTLS_SRC)/runtime \
         -I$(CRISPTLS_SRC)/policy \
         -I$(CRISPTLS_SRC)/policy/profiles \
         -I$(CRISPTLS_SRC)/proto/handshake \
         -I$(CRISPTLS_SRC)/proto/keyschedule \
         -I$(CRISPTLS_SRC)/proto/record \
         -I$(CRISPTLS_SRC)/proto/state \
         -I$(CRISPTLS_SRC)/proto/extensions \
         -I$(CRISPTLS_SRC)/session \
         -I$(DNS_INC)
LIBS   = -lsodium

.PHONY: all clean info

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libquic.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

clean:
	rm -f build/*.o build/*.a
	@echo "  cleaned"

info:
	@echo "CC:   $(CC)"
	@echo "SRCS: $(SRCS)"
