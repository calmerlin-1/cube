# Makefile — cube dev tools. Not part of the browser.
.PHONY: all clean
all:
	@for d in */; do \
	    [ -f "$$d/Makefile" ] && $(MAKE) -C "$$d" || true; \
	done
clean:
	@for d in */; do \
	    [ -f "$$d/Makefile" ] && $(MAKE) -C "$$d" clean || true; \
	done
