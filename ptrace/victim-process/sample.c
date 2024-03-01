#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// This is just a stupid main running in a while
int main() {
    printf("PID: %d\n", getpid());

    while (1) {
        continue;
    }
    
    return 0;
}
