#include "../demo_protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The remote dlopen lab currently supports x86_64 only"
#endif

static unsigned char remote_path[REMOTE_DEMO_PATH_CAPACITY]
    __attribute__((aligned(16)));
static unsigned char remote_stack[REMOTE_DEMO_STACK_SIZE]
    __attribute__((aligned(16)));

static volatile sig_atomic_t running = 1;
static int marker_fd = -1;

__attribute__((naked, noinline, used, aligned(64)))
static void remote_patch_slot(void) {
    __asm__ volatile(
        ".rept 64\n\t"
        "nop\n\t"
        ".endr\n\t"
        "ret\n\t");
}

static int parse_fd(const char *name) {
    const char *text = getenv(name);
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

static uintptr_t function_address(void (*function)(void)) {
    uintptr_t address = 0;
    _Static_assert(sizeof(address) == sizeof(function),
                   "function pointers do not fit in uintptr_t");
    memcpy(&address, &function, sizeof(address));
    return address;
}

static void acknowledge_signal(int signal_number) {
    (void)signal_number;
    const unsigned char marker = 'A';
    if (marker_fd >= 0) {
        ssize_t ignored = write(marker_fd, &marker, sizeof(marker));
        (void)ignored;
    }
}

static void stop_victim(int signal_number) {
    (void)signal_number;
    running = 0;
}

static int install_handler(int signal_number, void (*handler)(int)) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    return sigaction(signal_number, &action, NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    int ready_fd = parse_fd(REMOTE_DEMO_READY_FD);
    marker_fd = parse_fd(REMOTE_DEMO_MARKER_FD);
    if (ready_fd < 0 || marker_fd < 0) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }
    if (install_handler(SIGUSR1, acknowledge_signal) != 0 ||
        install_handler(SIGTERM, stop_victim) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    void (*slot)(void) = remote_patch_slot;
    struct remote_demo_ready ready = {
        .magic = REMOTE_DEMO_MAGIC,
        .patch_address = function_address(slot),
        .path_address = (uintptr_t)remote_path,
        .stack_address = (uintptr_t)remote_stack,
        .stack_size = sizeof(remote_stack),
    };
    if (write_all(ready_fd, &ready, sizeof(ready)) != 0) {
        perror("announce readiness");
        return EXIT_FAILURE;
    }
    close(ready_fd);

    printf("Victim PID %d is ready for a controlled remote load\n", getpid());
    while (running != 0) {
        pause();
    }

    close(marker_fd);
    return remote_path[0] == '\0' ? EXIT_SUCCESS : EXIT_FAILURE;
}
