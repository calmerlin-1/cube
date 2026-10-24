CC      ?= cc
CFLAGS  := -O2 -Wall -Wextra
BIN     := profile_gen

.PHONY: all clean
all: $(BIN)

$(BIN): profile_gen.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "  $(BIN) built"

clean:
	rm -f $(BIN)
	@echo "  cleaned"

policy_test: policy_test.c
	$(CC) $(CFLAGS) -I../include policy_test.c \
		../build/libcrisptls.a ../../dns/build/libdns.a ../../../utils/build/libutils.a \
		-lcrypto -lsodium -lssl -o $@
	@echo "  policy_test built"
