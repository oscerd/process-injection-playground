CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

VICTIMS := victim-process/sample victim-process/function_pointer \
	victim-process/non_dumpable victim-process/got_partial \
	victim-process/got_full victim-process/stack_return

all: inject $(VICTIMS)

inject: inject.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/function_pointer: victim-process/function_pointer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/non_dumpable: victim-process/non_dumpable.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/got_partial: victim-process/got_overwrite.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -fno-builtin-puts -no-pie \
		-Wl,-z,relro,-z,lazy -o $@ $<

victim-process/got_full: victim-process/got_overwrite.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DFULL_RELRO -fno-pie -fno-builtin-puts \
		-no-pie -Wl,-z,relro,-z,now -o $@ $<

victim-process/stack_return: victim-process/stack_return.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-pie -fno-omit-frame-pointer \
		-fno-optimize-sibling-calls -fno-stack-protector -no-pie -o $@ $<

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
