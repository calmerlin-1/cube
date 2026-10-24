# Makefile — build and run all crisptls tests.
#
# Tests live here; binaries land in ../../net/crisptls/build/.
# Run `make all` to build, `make rfc` to run RFC conformance only,
# `make clean` to remove built binaries.

CC      ?= cc
CFLAGS  := -O2 -w -I../../net/crisptls/include \
           -I../../net/crisptls/src/crypto \
           -I../../net/crisptls/src/proto/keyschedule
LDADD   := ../../net/crisptls/build/libcrisptls.a \
           ../../net/dns/build/libdns.a \
           ../../utils/build/libutils.a \
           -lcrypto -lsodium -lssl
OUT     := ../../net/crisptls/build

# RFC conformance tests (added this session)
RFC_TESTS = tier_test ssl3_rfc_test tls_legacy_rfc_test
# Other unit tests (pre-existing)
UNIT_TESTS = connect_test quic_test quic_packet_test sha384_test x25519_test

ALL = $(RFC_TESTS) $(UNIT_TESTS)

.PHONY: all rfc clean

all: $(ALL)

rfc: $(RFC_TESTS)
	@echo
	@for t in $(RFC_TESTS); do \
		echo "═══ $$t ═══"; \
		$(OUT)/$$t || exit 1; \
	done
	@echo
	@echo "════════ ALL RFC TESTS PASSED ════════"

$(ALL):
	$(CC) $(CFLAGS) $@.c $(LDADD) -o $(OUT)/$@
	@echo "  built $(OUT)/$@"

clean:
	rm -f $(foreach t,$(ALL),$(OUT)/$(t))
	@echo "  cleaned test binaries"
