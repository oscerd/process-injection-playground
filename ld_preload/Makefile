CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -shared -ldl

all: injected_lib.so victim-process/sample

# Build the malicious shared library
injected_lib.so: injected_lib.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Build the victim process
victim-process/sample: victim-process/sample.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f injected_lib.so victim-process/sample

.PHONY: all clean
