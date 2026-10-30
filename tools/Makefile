# tools/Makefile — build all native cube tools.
# Crypto oracle is Python and intentionally excluded.

TOOLS := erdict dbug sear

.PHONY: all clean test $(TOOLS)

all: $(TOOLS)

$(TOOLS):
	$(MAKE) -C $@

test: all
	@set -e; for t in $(TOOLS); do \
	    if [ -x "$$t/$$t" ]; then echo "  $$t: ok"; \
	    else echo "  $$t: MISSING" >&2; exit 1; fi; \
	done
	@./erdict/erdict --help >/dev/null
	@./sear/sear --help >/dev/null
	@./dbug/dbug --help >/dev/null
	@echo "  all tools smoke-tested"

clean:
	@for t in $(TOOLS); do $(MAKE) -C $$t clean; done
