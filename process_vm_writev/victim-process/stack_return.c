#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../demo_protocol.h"

#if !defined(__x86_64__)
#error "This saved-return-address lab currently supports x86_64 only"
#endif

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

__attribute__((noreturn, used)) static void redirected_action(void) {
    static const char message[] =
        "[STACK REDIRECTED] Saved return address selected a benign callback\n";
    if (write_exact(STDOUT_FILENO, message, sizeof(message) - 1) != 0) {
        _exit(1);
    }
    _exit(0);
}

/*
 * A normal ret enters with the caller's stack alignment, not the alignment a
 * called function expects. This tiny trampoline performs a real call so the
 * benign C callback receives the x86_64 System V entry alignment.
 */
__attribute__((naked, noreturn, noinline)) static void redirected_return(void) {
    __asm__ volatile("call redirected_action\n\t"
                     "ud2");
}

__attribute__((noinline)) static int await_return_overwrite(int request_fd) {
    _Static_assert(sizeof(action_fn) <= PIP_MAX_WRITE_SIZE,
                   "function pointer does not fit the demo protocol");
    _Static_assert(sizeof(action_fn) <= sizeof(uintptr_t),
                   "function pointer representation is unsupported");

    uintptr_t *frame = (uintptr_t *)__builtin_frame_address(0);
    volatile uintptr_t *return_slot = frame + 1;
    uintptr_t original_return = *return_slot;

    action_fn replacement = redirected_return;
    uintptr_t replacement_bits = 0;
    memcpy(&replacement_bits, &replacement, sizeof(replacement));

    struct pip_demo_request request = {
        .magic = PIP_DEMO_MAGIC,
        .remote_address = (uintptr_t)return_slot,
        .length = sizeof(replacement),
    };
    memcpy(request.value, &replacement, sizeof(replacement));

    printf("[VICTIM] Saved return slot: %p\n", (const void *)return_slot);
    printf("[VICTIM] Original return address: 0x%lx\n",
           (unsigned long)original_return);
    if (write_exact(request_fd, &request, sizeof(request)) != 0) {
        return -1;
    }
    close(request_fd);

    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        if (*return_slot == replacement_bits) {
            puts("[VICTIM] Returning through the modified stack slot");
            return 0;
        }
        if (*return_slot != original_return) {
            fprintf(stderr, "Saved return slot contains an unexpected value\n");
            return -1;
        }
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Timed out waiting for the return-address overwrite\n");
    return -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *request_fd_text = getenv("PIP_REQUEST_FD");
    if (request_fd_text == NULL) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long request_fd = strtol(request_fd_text, &end, 10);
    if (end == request_fd_text || *end != '\0' || request_fd < 0) {
        fprintf(stderr, "Invalid request file descriptor\n");
        return EXIT_FAILURE;
    }

    if (await_return_overwrite((int)request_fd) != 0) {
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Original control flow unexpectedly resumed\n");
    return EXIT_FAILURE;
}
