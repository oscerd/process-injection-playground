#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int announce_ready(int fd) {
    const unsigned char ready = 1;

    for (;;) {
        ssize_t result = write(fd, &ready, sizeof(ready));
        if (result == (ssize_t)sizeof(ready)) {
            return 0;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *ready_fd_text = getenv("PTRACE_READY_FD");
    if (ready_fd_text == NULL) {
        fprintf(stderr, "Run this victim through observer --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long ready_fd = strtol(ready_fd_text, &end, 10);
    if (end == ready_fd_text || *end != '\0' || ready_fd < 0 ||
        announce_ready((int)ready_fd) != 0) {
        perror("announce readiness");
        return EXIT_FAILURE;
    }
    close((int)ready_fd);

    printf("Victim PID %d is running normally\n", getpid());
    for (;;) {
        pause();
    }
}
