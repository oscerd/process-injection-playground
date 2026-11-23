CC ?= gcc
CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

.PHONY: all clean test

CONTROLLED_VICTIMS := victim-process/read_only victim-process/non_dumpable

all: inject victim-process/sample controlled_writer $(CONTROLLED_VICTIMS)

inject: inject.c
	$(CC) -Wall -Wextra -g -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) -Wall -Wextra -g -o $@ $<

controlled_writer: controlled_writer.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/read_only: victim-process/read_only.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

victim-process/non_dumpable: victim-process/read_only.c demo_protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNON_DUMPABLE -o $@ $<

test: controlled_writer $(CONTROLLED_VICTIMS)
	@set -e; for victim in $(CONTROLLED_VICTIMS); do \
		status=0; ./controlled_writer --spawn "./$$victim" || status=$$?; \
		if [ "$$status" -eq 77 ]; then \
			echo "[SKIP] procfs memory override is blocked for $$victim"; \
		elif [ "$$status" -ne 0 ]; then \
			exit "$$status"; \
		fi; \
	done

clean:
	rm -f inject controlled_writer victim-process/sample $(CONTROLLED_VICTIMS)
