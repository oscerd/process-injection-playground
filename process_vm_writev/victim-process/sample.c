#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile uint64_t injection_marker;

static int write_exact(int fd, const void *buffer, size_t length) {
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, (const char *)buffer + written, length - written);
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

    uintptr_t marker_address = (uintptr_t)&injection_marker;
    const char *address_fd_text = getenv("PIP_ADDRESS_FD");
    if (address_fd_text != NULL) {
        char *end = NULL;
        long address_fd = strtol(address_fd_text, &end, 10);
        if (end == address_fd_text || *end != '\0' || address_fd < 0 ||
            write_exact((int)address_fd, &marker_address,
                        sizeof(marker_address)) != 0) {
            perror("announce marker address");
            return EXIT_FAILURE;
        }
        close((int)address_fd);
    }

    printf("Victim PID: %d\n", getpid());
    printf("Marker address: 0x%" PRIxPTR "\n", marker_address);
    printf("Waiting for a benign remote marker...\n");

    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        if (injection_marker != 0) {
            printf("Observed marker: 0x%016" PRIx64 "\n", injection_marker);
            return EXIT_SUCCESS;
        }
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Timed out waiting for the remote write\n");
    return EXIT_FAILURE;
}
