CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

all: inject demo_lib.so victim-process/sample

inject: inject.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -ldl

demo_lib.so: demo_lib.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $<

victim-process/sample: victim-process/sample.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -no-pie -o $@ $<

test: all
	@set -e; for mode in disk memfd; do \
		status=0; \
		./inject --mode "$$mode" --library ./demo_lib.so \
			--spawn ./victim-process/sample || status=$$?; \
		if [ "$$status" -eq 77 ]; then \
			echo "[SKIP] remote $$mode loading is blocked"; \
		elif [ "$$status" -ne 0 ]; then \
			exit "$$status"; \
		fi; \
	done

clean:
	rm -f inject demo_lib.so victim-process/sample
