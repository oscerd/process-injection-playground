CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: injector victim-process/sample

injector: injector.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $< -pthread

test: all
	@status=0; ./injector --spawn ./victim-process/sample || status=$$?; \
	if [ "$$status" -eq 77 ]; then \
		echo "[SKIP] thread-group ptrace is blocked by this environment"; \
		exit 0; \
	fi; \
	exit "$$status"

clean:
	rm -f injector victim-process/sample
