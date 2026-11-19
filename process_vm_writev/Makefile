CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

VICTIMS := victim-process/sample victim-process/function_pointer

all: inject $(VICTIMS)

inject: inject.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/function_pointer: victim-process/function_pointer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

test: all
	@set -e; for victim in $(VICTIMS); do \
		status=0; ./inject --spawn "./$$victim" || status=$$?; \
		if [ "$$status" -eq 77 ]; then \
			echo "[SKIP] Cross-process writes are blocked for $$victim"; \
		elif [ "$$status" -ne 0 ]; then \
			exit "$$status"; \
		fi; \
	done

clean:
	rm -f inject $(VICTIMS)
