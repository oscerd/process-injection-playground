/*
 * Victim Process for /proc/mem Injection
 *
 * A simple infinite loop program that serves as an injection target
 */

#include <stdio.h>
#include <unistd.h>

int main() {
    int counter = 0;

    printf("Victim Process Started\n");
    printf("PID: %d\n", getpid());
    printf("Waiting for injection...\n");
    fflush(stdout);

    while(1) {
        counter++;
        sleep(1);
    }

    return 0;
}
