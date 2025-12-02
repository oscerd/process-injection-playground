/*
 * Victim Process for dlopen Injection
 *
 * A simple program that will have a library injected at runtime
 */

#include <stdio.h>
#include <unistd.h>

int main() {
    int counter = 0;

    printf("Victim Process Started\n");
    printf("PID: %d\n", getpid());
    printf("This process has no idea it will be injected...\n");
    printf("\n");

    while(1) {
        printf("Counter: %d\n", counter++);
        sleep(2);
    }

    return 0;
}
