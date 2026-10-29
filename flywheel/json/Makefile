CC      ?= cc
CFLAGS  := -O2 -Wall -Wextra -Iinclude

LIB     := build/libjson.a
OBJ     := build/json_color.o

.PHONY: all clean
all: $(LIB)

build:
	@mkdir -p build

build/json_color.o: src/json_color.c include/json.h | build
	$(CC) $(CFLAGS) -c src/json_color.c -o $@

$(LIB): build/json_color.o
	$(AR) rcs $@ $<
	@echo "  libjson.a built"

clean:
	rm -rf build
	@echo "  cleaned"
