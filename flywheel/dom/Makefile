# Makefile — flywheel/dom. DOM mutation, query, JS bindings.

CC     = cc
AR     = llvm-ar
RANLIB = llvm-ranlib

HTML_INC = ../html/include
HTML_SRC = ../html/src
CSS_INC  = ../css/include
CSS_SRC  = ../css/src
JS_INC   = ../js/include
JS_SRC   = ../js/src

SRCS = src/dom_mutate.c src/dom_query.c src/dom_js.c src/dom_style.c
OBJS = $(patsubst src/%.c, build/%.o, $(SRCS))

LIB = build/libdom.a

CFLAGS ?= -O2 -Wall -Wextra \
         -Iinclude \
         -I$(HTML_INC) -I$(HTML_SRC)/runtime \
         -I$(CSS_INC)  -I$(CSS_SRC)/runtime \
         -I$(JS_INC)

# Test-target compile flags: same includes, plus lib path hints.
TEST_CFLAGS = $(CFLAGS) \
              -I../css/src/parser -I../css/src/tokenizer \
              -I../js/src/runtime

# CSS sources compiled inline (skip platform.c to avoid duplicate plat_*
# with libhtml.a, which provides them). See test files for details.
CSS_SRCS = ../css/src/parser/css_cache.c \
           ../css/src/parser/css_parse.c \
           ../css/src/parser/css_selector.c \
           ../css/src/parser/css_value.c \
           ../css/src/runtime/arena.c \
           ../css/src/tokenizer/css_token.c

# JS sources needed by the JS-integration test (skip js platform.c too).
JS_TEST_SRCS = $(wildcard ../js/src/*.c) \
               ../js/src/runtime/os_hooks.c \
               ../js/src/runtime/os_sensors.c

.PHONY: all clean test test_style test_js test_compose

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	@echo "  libdom.a built with $(words $(OBJS)) objects"

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  $@"

# ---- Tests ----

build/test_style: tests/test_style.c $(LIB)
	$(CC) $(TEST_CFLAGS) \
	  tests/test_style.c \
	  $(LIB) \
	  ../html/build/libhtml.a \
	  $(CSS_SRCS) \
	  -o $@
	@echo "  built: build/test_style"

build/test_js_style: tests/test_js_style.c $(LIB)
	$(CC) $(TEST_CFLAGS) \
	  tests/test_js_style.c \
	  $(LIB) \
	  ../html/build/libhtml.a \
	  $(JS_TEST_SRCS) \
	  $(CSS_SRCS) \
	  -lm \
	  -o $@
	@echo "  built: build/test_js_style"

test_style: build/test_style
	./build/test_style

test_js: build/test_js_style
	./build/test_js_style

build/test_compose: tests/test_compose.c $(LIB)
	$(CC) $(TEST_CFLAGS) \
	  tests/test_compose.c \
	  $(LIB) \
	  ../html/build/libhtml.a \
	  $(CSS_SRCS) \
	  -lm \
	  -o $@
	@echo "  built: build/test_compose"

test_compose: build/test_compose
	./build/test_compose

test: test_style test_js

clean:
	rm -f build/*.o build/*.a build/test_style build/test_js_style
	@echo "  cleaned"
