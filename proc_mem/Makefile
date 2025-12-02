CC = gcc
CFLAGS = -Wall -Wextra -g

all: inject victim-process/sample

inject: inject.c
	$(CC) $(CFLAGS) -o $@ $<

victim-process/sample: victim-process/sample.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f inject victim-process/sample

.PHONY: all clean
