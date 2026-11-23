CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: redirector victim-process/sample

redirector: redirector.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $<

test: all
	@set -e; for mode in setregs pokeuser; do \
		status=0; \
		if [ "$$mode" = setregs ]; then \
			./redirector --spawn ./victim-process/sample || status=$$?; \
		else \
			./redirector --pokeuser --spawn ./victim-process/sample \
				|| status=$$?; \
		fi; \
		if [ "$$status" -eq 77 ]; then \
			echo "[SKIP] PTRACE_TRACEME is blocked for $$mode"; \
		elif [ "$$status" -ne 0 ]; then \
			exit "$$status"; \
		fi; \
	done

clean:
	rm -f redirector victim-process/sample
