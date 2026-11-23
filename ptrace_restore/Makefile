CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: inject victim-process/sample

inject: inject.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $<

test: all
	@status=0; ./inject --spawn ./victim-process/sample || status=$$?; \
	if [ "$$status" -eq 77 ]; then \
		echo "[SKIP] ptrace attach is blocked by this environment"; \
		exit 0; \
	fi; \
	exit "$$status"

clean:
	rm -f inject victim-process/sample
