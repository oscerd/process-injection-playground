#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include "../demo_protocol.h"

typedef void (*action_fn)(void);

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

__attribute__((noreturn)) static void redirected_action(void) {
    static const char message[] =
        "[REDIRECTED] Victim is executing its existing benign function\n";
    if (write_exact(STDOUT_FILENO, message, sizeof(message) - 1) != 0) {
        _exit(1);
    }
    _exit(0);
}

int main(void) {
    _Static_assert(sizeof(action_fn) <= sizeof(uintptr_t),
                   "function pointer representation is unsupported");
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *request_fd_text = getenv("PTRACE_TRACEME_FD");
    if (request_fd_text == NULL) {
        fprintf(stderr, "Run this victim through redirector --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long request_fd = strtol(request_fd_text, &end, 10);
    if (end == request_fd_text || *end != '\0' || request_fd < 0) {
        fprintf(stderr, "Invalid request file descriptor\n");
        return EXIT_FAILURE;
    }

    errno = 0;
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
        int trace_error = errno;
        fprintf(stderr, "PTRACE_TRACEME: %s\n", strerror(trace_error));
        return trace_error == EPERM || trace_error == EACCES ? 77
                                                             : EXIT_FAILURE;
    }

    action_fn target = redirected_action;
    uintptr_t target_bits = 0;
    memcpy(&target_bits, &target, sizeof(target));
    struct redirect_request request = {
        .magic = REDIRECT_MAGIC,
        .target_address = target_bits,
    };
    if (write_exact((int)request_fd, &request, sizeof(request)) != 0) {
        return EXIT_FAILURE;
    }
    close((int)request_fd);

    puts("[VICTIM] Opted into tracing and stopping for its parent");
    raise(SIGSTOP);

    fprintf(stderr, "Victim resumed without the expected RIP redirection\n");
    return EXIT_FAILURE;
}
