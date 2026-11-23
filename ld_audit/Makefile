CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: audit_lib.so victim-process/sample

audit_lib.so: audit_lib.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -Wl,-z,now -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

test: all
	@output="$$(LD_AUDIT="$(CURDIR)/audit_lib.so" \
		./victim-process/sample 2>&1)"; \
	printf '%s\n' "$$output"; \
	printf '%s\n' "$$output" | grep -Fq '[LD_AUDIT] audit interface active'; \
	printf '%s\n' "$$output" | grep -Fq '[LD_AUDIT] object opened'; \
	printf '%s\n' "$$output" | grep -Fq '[LD_AUDIT] puts binding observed'; \
	printf '%s\n' "$$output" | grep -Fq '[VICTIM] normal puts call'

clean:
	rm -f audit_lib.so victim-process/sample
