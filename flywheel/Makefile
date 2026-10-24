# Makefile — flywheel (top level). Builds core.c against all engines.

CC ?= $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || echo aarch64-linux-android-clang)

HTML_LIB = html/build/libhtml.a
CSS_LIB  = css/build/libcss.a
JS_LIB   = js/build/libjs.a
DOM_LIB  = dom/build/libdom.a

CFLAGS = -O2 -Wall -Wextra \
         -Ihtml/include \
         -Icss/include \
         -Ihtml/src/runtime \
         -Ijs/include \
         -Icss/src/runtime

.PHONY: all clean rebuild

all: build/core

$(HTML_LIB):
	$(MAKE) -C html all

$(CSS_LIB):
	$(MAKE) -C css all

$(JS_LIB):
	$(MAKE) -C js all

$(DOM_LIB): $(HTML_LIB) $(CSS_LIB) $(JS_LIB)
	$(MAKE) -C dom all

build/core: core.c $(HTML_LIB) $(CSS_LIB) $(JS_LIB) $(DOM_LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) core.c $(DOM_LIB) $(JS_LIB) $(HTML_LIB) $(CSS_LIB) -lm -o $@
	@echo "  built: build/core"

rebuild: clean all

clean:
	rm -rf build
	@echo "  cleaned"
