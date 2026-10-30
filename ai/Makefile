# ai/Makefile - standalone CUBE AI capability layer. Not wired into the root build.

CC ?= cc
AR ?= ar
RANLIB ?= ranlib

CFLAGS ?= -O2 -Wall -Wextra -std=c11
CPPFLAGS += -Iinclude

BUILD = build
LIB = $(BUILD)/libcube_ai.a
INFO = $(BUILD)/ai_info
OBJS = $(BUILD)/ai_registry.o $(BUILD)/ai_asset.o
HEADERS = include/cube_ai.h src/ai_internal.h

.PHONY: all clean info

all: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	$(RANLIB) $@

$(INFO): examples/ai_info.c $(LIB) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

info: $(INFO)
	CUBE_AI_HOME="$(CURDIR)/models" ./$(INFO)

clean:
	rm -rf $(BUILD)
