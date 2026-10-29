# Makefile — CUBE top-level. Builds the `cube` orchestrator
# by linking crisptls + dns + tcp + http_client + url + utils.

CC     ?= cc
AR     = llvm-ar
RANLIB = llvm-ranlib

# Library paths (each module has its own Makefile + build/lib*.a)
CRISPTLS_LIB   = net/crisptls/build/libcrisptls.a
CRISPTLS_INC   = net/crisptls/include
DNS_LIB        = net/dns/build/libdns.a
DNS_INC        = net/dns/include
TCP_LIB        = net/tcp/build/libtcp.a
TCP_INC        = net/tcp/include
HTTP_LIB       = net/http_client/build/libhttp_client.a
HTTP_INC       = net/http_client/include
URL_LIB        = flywheel/url/build/liburl.a
URL_INC        = flywheel/url/include
JSON_LIB       = flywheel/json/build/libjson.a
HTML_LIB       = flywheel/html/build/libhtml.a
DOM_LIB       = flywheel/dom/build/libdom.a
CSS_LIB       = flywheel/css/build/libcss.a
DOM_INC       = flywheel/dom/include
CSS_INC       = flywheel/css/include
HTML_INC       = flywheel/html/include
JSON_INC       = flywheel/json/include
UTILS_LIB      = utils/build/libutils.a
UTILS_INC      = utils

CFLAGS = -O1 -I. -Iutils -Wall -Wextra \
         -I$(CRISPTLS_INC) \
         -I$(DNS_INC) \
         -I$(TCP_INC) \
         -I$(HTTP_INC) \
         -I$(URL_INC) \
         -I$(JSON_INC) \
         -I$(HTML_INC) \
	         -I$(DOM_INC) \
	         -I$(CSS_INC) \
         -I$(UTILS_INC)

LIBS   = -lcrypto -lsodium -lssl

# Every subdir with a Makefile. Order matters for cross-subdir deps.
SUBDIRS = utils flywheel/json flywheel/css flywheel/url flywheel/html flywheel/dom \
          net/tcp net/dns net/crisptls net/http_client

CUBE   = cube

.PHONY: all clean libs info test integration-test help


all: libs $(CUBE)

test:
	@$(MAKE) -C tests test

integration-test:
	@$(MAKE) -C tests integration

help:
	@echo "cube build targets:"
	@echo "  make              — build everything"
	@echo "  make test         — run non-network tests"
	@echo "  make integration-test — run network tests (slow)"
	@echo "  make clean        — clean all build outputs"
	@echo "  make info         — show compiler and flags"


# Build the sub-library Makefiles first.
libs:
	@set -e; for d in $(SUBDIRS); do \
	    if [ -f "$$d/Makefile" ]; then $(MAKE) -C "$$d" >/dev/null || exit 1; fi; \
	done
	@echo "  all libs built"

$(CUBE): libs src/cube.c $(CRISPTLS_LIB) $(DNS_LIB) $(TCP_LIB) $(HTTP_LIB) $(URL_LIB) $(HTML_LIB) $(DOM_LIB) $(CSS_LIB) $(JSON_LIB) $(UTILS_LIB)
	$(CC) $(CFLAGS) src/cube.c \
	    $(HTTP_LIB) \
	    $(CRISPTLS_LIB) \
	    $(DNS_LIB) \
	    $(TCP_LIB) \
	    $(URL_LIB) \
            $(HTML_LIB) \
	         $(DOM_LIB) \
	         $(CSS_LIB) \
            $(JSON_LIB) \
	    $(UTILS_LIB) \
	    $(LIBS) -s -o $@
	@echo "  cube built"

clean:
	rm -f $(CUBE)
	@echo "  cube cleaned"

info:
	@echo "CC:     $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LIBS:   $(LIBS)"
