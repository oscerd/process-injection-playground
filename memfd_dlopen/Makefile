CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: loader demo_lib.so

loader: loader.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -ldl

demo_lib.so: demo_lib.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $<

test: all
	@status=0; ./loader ./demo_lib.so || status=$$?; \
	if [ "$$status" -eq 77 ]; then \
		echo "[SKIP] memfd_create is blocked or unavailable"; \
		exit 0; \
	fi; \
	exit "$$status"

clean:
	rm -f loader demo_lib.so
