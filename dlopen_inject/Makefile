CC = gcc
CFLAGS = -Wall -Wextra -g
LIB_CFLAGS = -Wall -Wextra -fPIC
LIB_LDFLAGS = -shared -ldl

all: inject malicious_lib.so victim-process/sample

inject: inject.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

malicious_lib.so: malicious_lib.c
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f inject malicious_lib.so victim-process/sample

.PHONY: all clean
