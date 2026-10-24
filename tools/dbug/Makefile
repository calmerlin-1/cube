CC ?= cc
CFLAGS = -O2 -Wall -Wextra -I. -I../sear

SEAR_SRCS = ../sear/io.c ../sear/strutil.c ../sear/ws.c \
            ../sear/output.c ../sear/pattern.c ../sear/symbols.c \
            ../sear/walk.c ../sear/syntax.c

DBUG_SRCS = main.c analyze.c build.c trace.c crash.c

SEAR_OBJS = $(patsubst ../sear/%.c,build/sear_%.o,$(SEAR_SRCS))
DBUG_OBJS = $(patsubst %.c,build/%.o,$(DBUG_SRCS))
OBJS      = $(DBUG_OBJS) $(SEAR_OBJS)

BIN   = dbug
SHIM  = shim.so
DEMO  = demo

.PHONY: all clean demo

all: $(BIN) $(SHIM) $(DEMO)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@
	@echo "  dbug built"

$(SHIM): shim.c
	$(CC) -O2 -Wall -Wextra -shared -fPIC shim.c -o $@ -ldl
	@echo "  shim.so built"

$(DEMO): demo.c
	$(CC) -O2 -Wall -Wextra demo.c -o $@
	@echo "  demo built"

build/sear_%.o: ../sear/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: %.c dbug.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(BIN) $(SHIM) $(DEMO)
	@echo "  cleaned"
