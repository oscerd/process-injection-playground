CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: hollower victim-process/sample

hollower: hollower.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.S
	$(CC) -nostdlib -static -no-pie -Wl,-e,_start -o $@ $<

test: all
	@status=0; ./hollower --spawn ./victim-process/sample || status=$$?; \
	if [ "$$status" -eq 77 ]; then \
		echo "[SKIP] exec-stop tracing is blocked by this environment"; \
		exit 0; \
	fi; \
	exit "$$status"

clean:
	rm -f hollower victim-process/sample
