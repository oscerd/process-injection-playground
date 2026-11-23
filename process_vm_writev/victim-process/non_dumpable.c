#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "../demo_protocol.h"

static volatile uint64_t protected_marker;
static volatile sig_atomic_t write_attempt_finished;

static void handle_write_attempt(int signal_number) {
    (void)signal_number;
    write_attempt_finished = 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, (const char *)buffer + written,
                               length - written);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        written += (size_t)result;
    }

    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    struct sigaction action = {
        .sa_handler = handle_write_attempt,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    if (prctl(PR_SET_DUMPABLE, 0L) != 0) {
        perror("prctl PR_SET_DUMPABLE");
        return EXIT_FAILURE;
    }

    const char *request_fd_text = getenv("PIP_REQUEST_FD");
    if (request_fd_text == NULL) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long request_fd = strtol(request_fd_text, &end, 10);
    uint64_t marker = PIP_DEMO_MARKER;
    struct pip_demo_request request = {
        .magic = PIP_DEMO_MAGIC,
        .remote_address = (uintptr_t)&protected_marker,
        .length = sizeof(marker),
        .flags = PIP_EXPECT_DENIED,
    };
    memcpy(request.value, &marker, sizeof(marker));

    if (end == request_fd_text || *end != '\0' || request_fd < 0 ||
        write_exact((int)request_fd, &request, sizeof(request)) != 0) {
        perror("announce denied-write request");
        return EXIT_FAILURE;
    }
    close((int)request_fd);

    puts("Victim is non-dumpable; waiting for the expected denial...");
    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        if (protected_marker != 0) {
            fprintf(stderr, "Protected marker was unexpectedly modified\n");
            return EXIT_FAILURE;
        }
        if (write_attempt_finished != 0) {
            puts("Protected marker remained unchanged");
            return EXIT_SUCCESS;
        }
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Injector did not complete the denial check\n");
    return EXIT_FAILURE;
}
