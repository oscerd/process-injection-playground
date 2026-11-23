CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: observer victim-process/sample

observer: observer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

test: all
	@status=0; ./observer --spawn ./victim-process/sample || status=$$?; \
	if [ "$$status" -eq 77 ]; then \
		echo "[SKIP] ptrace seize is blocked by this environment"; \
		exit 0; \
	fi; \
	exit "$$status"

clean:
	rm -f observer victim-process/sample
