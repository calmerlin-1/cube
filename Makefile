# Makefile — CUBE top-level. Builds the `cube` orchestrator
# by linking crisptls + dns + tcp + http_client + url + utils.

CC     ?= cc
AR ?= $(shell command -v ar 2>/dev/null || command -v llvm-ar 2>/dev/null || echo ar)
RANLIB ?= $(shell command -v ranlib 2>/dev/null || command -v llvm-ranlib 2>/dev/null || echo ranlib)

# Optional dependencies are detected, never assumed. Missing zlib simply
# disables gzip/deflate decoding; missing pthread keeps DNS sequential.
HAVE_ZLIB    := $(shell printf 'int main(void){return 0;}\n' | $(CC) -x c - -include zlib.h -lz -o /tmp/.cube_zlib 2>/dev/null && echo 1 || echo 0)
HAVE_PTHREAD := $(shell printf 'int main(void){return 0;}\n' | $(CC) -x c - -include pthread.h -pthread -o /tmp/.cube_pthread 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_ZLIB),1)
  ZLIB_CFLAGS = -DHAVE_ZLIB=1
  ZLIB_LIBS   = -lz
endif
ifeq ($(HAVE_PTHREAD),1)
  PTHREAD_CFLAGS = -DHAVE_PTHREAD=1 -pthread
  PTHREAD_LIBS   = -pthread
endif

# Library paths (each module has its own Makefile + build/lib*.a)
CRISPTLS_LIB   = net/crisptls/build/libcrisptls.a
CRISPTLS_INC   = net/crisptls/include
DNS_LIB        = net/dns/build/libdns.a
DNS_INC        = net/dns/include
TCP_LIB        = net/tcp/build/libtcp.a
TCP_INC        = net/tcp/include
PROXY_LIB      = net/proxy/build/libproxy.a
PROXY_INC      = net/proxy/include
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

CFLAGS = -O1 -I. -Iutils -Wall -Wextra $(ZLIB_CFLAGS) $(PTHREAD_CFLAGS) \
         -I$(CRISPTLS_INC) \
         -I$(DNS_INC) \
         -I$(TCP_INC) \
         -I$(PROXY_INC) \
         -I$(HTTP_INC) \
         -I$(URL_INC) \
         -I$(JSON_INC) \
         -I$(HTML_INC) \
	         -I$(DOM_INC) \
	         -I$(CSS_INC) \
         -I$(UTILS_INC)

LIBS   = -lsodium $(ZLIB_LIBS) $(PTHREAD_LIBS)

# Every subdir with a Makefile. Order matters for cross-subdir deps.
SUBDIRS = utils flywheel/json flywheel/css flywheel/url flywheel/html flywheel/dom \
          net/proxy net/tcp net/dns net/crisptls net/http_client

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

$(CUBE): libs src/cube.c $(CRISPTLS_LIB) $(DNS_LIB) $(TCP_LIB) $(PROXY_LIB) $(HTTP_LIB) $(URL_LIB) $(HTML_LIB) $(DOM_LIB) $(CSS_LIB) $(JSON_LIB) $(UTILS_LIB)
	$(CC) $(CFLAGS) src/cube.c \
	    $(HTTP_LIB) \
	    $(CRISPTLS_LIB) \
	    $(DNS_LIB) \
	    $(PROXY_LIB) \
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
