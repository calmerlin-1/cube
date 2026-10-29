# net/crisptls/tests/Makefile — build and run crisptls unit tests.
# Each test is a standalone binary; exits nonzero on failure.

CC      ?= cc
ROOT    := ../../..
BUILD   := ../build

LIB     := $(BUILD)/libcrisptls.a
INC     := -I$(ROOT)/net/crisptls/include \
           -I$(ROOT)/net/crisptls/src/crypto \
           -I$(ROOT)/net/crisptls/src/proto/handshake \
           -I$(ROOT)/utils

CFLAGS  ?= -O2 -Wall -Wextra -g $(INC)
LIBS    := $(LIB) -lsodium

TESTS   := test_fe test_hmac_native test_p256 test_sha_edge test_sha_native
BINS    := $(addprefix $(BUILD)/,$(TESTS))

.PHONY: all test run clean

all: $(BINS)

$(BUILD)/test_%: test_%.c $(LIB)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $< $(LIBS) -o $@

test run: all
	@set -e; \
	pass=0; fail=0; \
	for t in $(TESTS); do \
	    echo "═══════ $$t ═══════"; \
	    if $(BUILD)/$$t; then \
	        pass=$$((pass+1)); \
	    else \
	        fail=$$((fail+1)); \
	    fi; \
	done; \
	echo; \
	echo "unit tests: $$pass passed, $$fail failed"; \
	[ $$fail -eq 0 ]

clean:
	rm -f $(BINS)
