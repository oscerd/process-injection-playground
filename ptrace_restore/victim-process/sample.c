#include "../demo_protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The ptrace restore lab currently supports x86_64 only"
#endif

static volatile uint64_t demo_marker;
static volatile sig_atomic_t running = 1;
static int status_fd = -1;

__attribute__((naked, noinline, used, aligned(64)))
static void remote_patch_slot(void) {
    __asm__ volatile(
        ".rept 64\n\t"
        "nop\n\t"
        ".endr\n\t"
        "ret\n\t");
}

static int write_all(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int parse_status_fd(void) {
    const char *text = getenv(RESTORE_DEMO_STATUS_FD);
    if (text == NULL) {
        return -1;
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 ||
        value > INT32_MAX) {
        return -1;
    }
    return (int)value;
}

static uintptr_t function_address(void (*function)(void)) {
    uintptr_t address = 0;
    _Static_assert(sizeof(address) == sizeof(function),
                   "function pointers do not fit in uintptr_t");
    memcpy(&address, &function, sizeof(address));
    return address;
}

static void confirm_resume(int signal_number) {
    (void)signal_number;
    const unsigned char marker = 'R';
    ssize_t ignored = write(status_fd, &marker, sizeof(marker));
    (void)ignored;
    running = 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    status_fd = parse_status_fd();
    if (status_fd < 0) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = confirm_resume;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    void (*slot)(void) = remote_patch_slot;
    struct restore_demo_ready ready = {
        .magic = RESTORE_DEMO_MAGIC,
        .patch_address = function_address(slot),
        .marker_address = (uintptr_t)&demo_marker,
    };
    if (write_all(status_fd, &ready, sizeof(ready)) != 0) {
        perror("announce readiness");
        return EXIT_FAILURE;
    }

    printf("Victim PID %d is waiting with marker 0\n", getpid());
    while (running != 0) {
        pause();
    }

    close(status_fd);
    if (demo_marker != 0) {
        fprintf(stderr, "Marker was not restored\n");
        return EXIT_FAILURE;
    }
    puts("Victim resumed after complete state restoration");
    return EXIT_SUCCESS;
}
