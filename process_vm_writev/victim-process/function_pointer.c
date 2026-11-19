#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../demo_protocol.h"

typedef void (*action_fn)(void);

static void normal_action(void) {
    puts("[NORMAL] Original function-pointer target executed");
}

static void redirected_action(void) {
    puts("[REDIRECTED] Benign function-pointer callback executed");
}

static action_fn volatile current_action = normal_action;

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
    _Static_assert(sizeof(action_fn) <= PIP_MAX_WRITE_SIZE,
                   "function pointer does not fit the demo protocol");
    setvbuf(stdout, NULL, _IONBF, 0);

    normal_action();

    const char *request_fd_text = getenv("PIP_REQUEST_FD");
    if (request_fd_text == NULL) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long request_fd = strtol(request_fd_text, &end, 10);
    action_fn replacement = redirected_action;
    struct pip_demo_request request = {
        .magic = PIP_DEMO_MAGIC,
        .remote_address = (uintptr_t)&current_action,
        .length = sizeof(replacement),
    };
    memcpy(request.value, &replacement, sizeof(replacement));

    if (end == request_fd_text || *end != '\0' || request_fd < 0 ||
        write_exact((int)request_fd, &request, sizeof(request)) != 0) {
        perror("announce function-pointer request");
        return EXIT_FAILURE;
    }
    close((int)request_fd);

    puts("Waiting for the function-pointer redirection...");
    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        action_fn observed = current_action;
        if (observed == redirected_action) {
            observed();
            return EXIT_SUCCESS;
        }
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Timed out waiting for function-pointer redirection\n");
    return EXIT_FAILURE;
}
