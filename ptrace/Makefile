all: inject sample

inject: inject.c
	gcc inject.c -Wall -Wextra -o inject -std=c99

sample: victim-process
	gcc victim-process/sample.c -o victim-process/sample -std=c99

clean: 
	rm -f inject victim-process/sample
