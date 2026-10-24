# tests/Makefile — standalone test binaries for cube modules.

CC ?= aarch64-linux-android-clang
ROOT := ..
CRISPTLS_LIB := $(ROOT)/net/crisptls/build/libcrisptls.a
UDP_INC      := $(ROOT)/net/udp
CRISPTLS_INC := $(ROOT)/net/crisptls/include
CRISPTLS_SRC := $(ROOT)/net/crisptls/src
UTILS_INC    := $(ROOT)/utils

CFLAGS := -O2 -Wall -Wextra -g \
          -I$(UDP_INC) \
          -I$(CRISPTLS_INC) \
          -I$(CRISPTLS_SRC)/crypto \
          -I$(CRISPTLS_SRC)/proto/handshake \
          -I$(UTILS_INC)
LDFLAGS :=
LIBS := $(CRISPTLS_LIB) -lcrypto -lsodium -lssl

.PHONY: all clean

all: quic_probe

quic_probe: quic_probe.c $(ROOT)/net/udp/udp.c
	$(CC) $(CFLAGS) -o $@ quic_probe.c $(ROOT)/net/udp/udp.c $(LIBS)

clean:
	rm -f quic_probe
