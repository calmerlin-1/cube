CC      ?= cc
CFLAGS  := -O2 -Wall -Wextra -Iinclude

LIB     := build/libjson.a
OBJ     := build/json_color.o build/json_validate.o

.PHONY: all clean
all: $(LIB)

build:
	@mkdir -p build

build/json_color.o: src/json_color.c include/json.h | build
	$(CC) $(CFLAGS) -c src/json_color.c -o $@

build/json_validate.o: src/json_validate.c include/json.h | build
	$(CC) $(CFLAGS) -c src/json_validate.c -o $@

$(LIB): $(OBJ)
	$(AR) rcs $@ $(OBJ)
	@echo "  libjson.a built"

clean:
	rm -rf build
	@echo "  cleaned"
