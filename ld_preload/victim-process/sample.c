/*
 * Victim Process for LD_PRELOAD Injection
 *
 * A simple program that will be injected with a malicious library
 */

#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Victim Process Started (PID: %d)\n", getpid());

    int counter = 0;
    while(1) {
        printf("Normal execution - Counter: %d\n", counter++);
        puts("This is a normal puts() call");
        sleep(2);
    }

    return 0;
}
