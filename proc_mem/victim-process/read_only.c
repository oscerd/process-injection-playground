#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "../demo_protocol.h"

#ifdef NON_DUMPABLE
static volatile sig_atomic_t write_attempt_finished;
static void handle_write_attempt(int signal_number) {
    (void)signal_number;
    write_attempt_finished = 1;
}
#endif

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

#ifdef NON_DUMPABLE
    struct sigaction action = {
        .sa_handler = handle_write_attempt,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0 ||
        prctl(PR_SET_DUMPABLE, 0L) != 0) {
        perror("prepare non-dumpable victim");
        return EXIT_FAILURE;
    }
#endif

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        return EXIT_FAILURE;
    }
    void *mapping = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    volatile uint64_t *marker_address = mapping;
    *marker_address = 0;
    if (mprotect(mapping, (size_t)page_size, PROT_READ) != 0) {
        perror("mprotect");
        munmap(mapping, (size_t)page_size);
        return EXIT_FAILURE;
    }

    const char *request_fd_text = getenv("PROC_MEM_REQUEST_FD");
    char *end = NULL;
    long request_fd = request_fd_text == NULL
                          ? -1
                          : strtol(request_fd_text, &end, 10);
    uint64_t marker = PROC_MEM_DEMO_MARKER;
    struct proc_mem_request request = {
        .magic = PROC_MEM_DEMO_MAGIC,
        .remote_address = (uintptr_t)marker_address,
        .length = sizeof(marker),
#ifdef NON_DUMPABLE
        .flags = PROC_MEM_EXPECT_DENIED,
#endif
    };
    memcpy(request.value, &marker, sizeof(marker));

    if (request_fd_text == NULL || end == request_fd_text || *end != '\0' ||
        request_fd < 0 ||
        write_exact((int)request_fd, &request, sizeof(request)) != 0) {
        fprintf(stderr, "Failed to announce procfs memory request\n");
        munmap(mapping, (size_t)page_size);
        return EXIT_FAILURE;
    }
    close((int)request_fd);

#ifdef NON_DUMPABLE
    puts("[VICTIM] Non-dumpable read-only mapping awaits an access denial");
#else
    puts("[VICTIM] Read-only mapping awaits a procfs memory write");
#endif

    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        uint64_t observed = *marker_address;
#ifdef NON_DUMPABLE
        if (observed != 0) {
            fprintf(stderr, "Read-only marker was unexpectedly changed\n");
            munmap(mapping, (size_t)page_size);
            return EXIT_FAILURE;
        }
        if (write_attempt_finished != 0) {
            puts("[VICTIM] Read-only marker remained unchanged");
            munmap(mapping, (size_t)page_size);
            return EXIT_SUCCESS;
        }
#else
        if (observed == PROC_MEM_DEMO_MARKER) {
            puts("[VICTIM] Marker changed despite the read-only mapping");
            munmap(mapping, (size_t)page_size);
            return EXIT_SUCCESS;
        }
        if (observed != 0) {
            fprintf(stderr, "Read-only marker contains an unexpected value\n");
            munmap(mapping, (size_t)page_size);
            return EXIT_FAILURE;
        }
#endif
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Timed out waiting for the procfs memory experiment\n");
    munmap(mapping, (size_t)page_size);
    return EXIT_FAILURE;
}
