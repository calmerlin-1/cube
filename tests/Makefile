# tests/Makefile — unified test runner.
#
#   make test          — run all tests that don't need the network
#   make integration   — run tests/run.sh (network; slow)
#   make clean         — clean all test binaries

CC      ?= cc
ROOT    := ..
BUILD   := build

# Shared includes for test binaries that #include crisptls headers directly.
CRISPTLS_INC := -I$(ROOT)/net/crisptls/include \
                -I$(ROOT)/net/crisptls/src/crypto \
                -I$(ROOT)/net/crisptls/src/proto/handshake \
                -I$(ROOT)/utils
CFLAGS  := -O2 -Wall -Wextra -g $(CRISPTLS_INC)

# Link against the built static libs.
LDADD   := $(ROOT)/net/crisptls/build/libcrisptls.a \
           $(ROOT)/net/dns/build/libdns.a \
           $(ROOT)/utils/build/libutils.a \
           -lcrypto -lsodium -lssl

.PHONY: all test integration clean help

all: help

help:
	@echo "tests/Makefile targets:"
	@echo "  make test          — run all non-network tests"
	@echo "  make integration   — run tests/run.sh (network)"
	@echo "  make clean         — remove built test binaries"

# ---- Non-network test suites ------------------------------------------------
#
# Each suite that manages its own Makefile is delegated to. Each suite that
# has stray *.c files under a subdir is compiled here with a generic rule.

SUBDIR_SUITES := crisptls

test:
	@set -e; \
	total_pass=0; total_fail=0; \
	echo; \
	echo "════════════════════════════════════════════════════════════"; \
	echo "   crisptls unit tests (fe, hmac, p256, sha)                  "; \
	echo "════════════════════════════════════════════════════════════"; \
	$(MAKE) -C $(ROOT)/net/crisptls/tests test || total_fail=$$((total_fail+1)); \
	\
	echo; \
	echo "════════════════════════════════════════════════════════════"; \
	echo "   crisptls policy / rfc tests                                "; \
	echo "════════════════════════════════════════════════════════════"; \
	$(MAKE) -C crisptls all || exit 1; \
	$(MAKE) -C crisptls rfc || total_fail=$$((total_fail+1)); \
	\
	echo; \
	if [ $$total_fail -eq 0 ]; then \
	    echo "════════ ALL TESTS PASSED ════════"; \
	else \
	    echo "════════ $$total_fail SUITE(S) FAILED ════════"; \
	    exit 1; \
	fi

# ---- Network integration tests (opt-in) -------------------------------------
integration:
	@echo "running tests/run.sh (network, ~2 min)"
	@./run.sh

clean:
	-$(MAKE) -C $(ROOT)/net/crisptls/tests clean
	-$(MAKE) -C crisptls clean
	rm -rf build .results
