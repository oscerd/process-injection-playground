#include "../demo_protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The VDSO hijack lab currently supports x86_64 only"
#endif

typedef int (*vdso_gettimeofday_fn)(struct timeval *, struct timezone *);

static volatile sig_atomic_t running = 1;
static volatile struct vdso_demo_results results = {
    .patched_result = -1,
    .restored_result = -1,
};
static vdso_gettimeofday_fn vdso_gettimeofday;
static int status_fd = -1;

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
    const char *text = getenv(VDSO_DEMO_STATUS_FD);
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

static uintptr_t function_address(vdso_gettimeofday_fn function) {
    uintptr_t address = 0;
    _Static_assert(sizeof(address) == sizeof(function),
                   "function pointers do not fit in uintptr_t");
    memcpy(&address, &function, sizeof(address));
    return address;
}

static void exercise_patched_vdso(int signal_number) {
    (void)signal_number;
    struct timeval value;
    results.patched_result = vdso_gettimeofday(&value, NULL);
    kill(getpid(), SIGTRAP);
    const unsigned char marker = 'P';
    ssize_t ignored = write(status_fd, &marker, sizeof(marker));
    (void)ignored;
}

static void verify_restored_vdso(int signal_number) {
    (void)signal_number;
    struct timeval value;
    results.restored_result = vdso_gettimeofday(&value, NULL);
    const unsigned char marker =
        results.restored_result == 0 ? 'R' : 'F';
    ssize_t ignored = write(status_fd, &marker, sizeof(marker));
    (void)ignored;
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
    status_fd = parse_status_fd();
    if (status_fd < 0) {
        fprintf(stderr, "Run this victim through injector --spawn\n");
        return EXIT_FAILURE;
    }

    void *handle = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_LOCAL);
    void *symbol = handle == NULL ? NULL : dlsym(handle, "__vdso_gettimeofday");
    if (symbol != NULL) {
        _Static_assert(sizeof(vdso_gettimeofday) == sizeof(symbol),
                       "function and data pointers have different sizes");
        memcpy(&vdso_gettimeofday, &symbol, sizeof(symbol));
    }

    struct vdso_demo_ready ready = {
        .magic = VDSO_DEMO_MAGIC,
        .symbol_address =
            vdso_gettimeofday == NULL ? 0 : function_address(vdso_gettimeofday),
        .result_address = (uintptr_t)&results,
    };
    if (vdso_gettimeofday == NULL) {
        if (write_all(status_fd, &ready, sizeof(ready)) != 0) {
            perror("announce unavailable VDSO symbol");
            return EXIT_FAILURE;
        }
        pause();
        return 77;
    }

    struct timeval baseline;
    if (vdso_gettimeofday(&baseline, NULL) != 0 ||
        install_handler(SIGUSR1, exercise_patched_vdso) != 0 ||
        install_handler(SIGUSR2, verify_restored_vdso) != 0) {
        perror("prepare VDSO victim");
        return EXIT_FAILURE;
    }
    if (write_all(status_fd, &ready, sizeof(ready)) != 0) {
        perror("announce readiness");
        return EXIT_FAILURE;
    }

    printf("Victim PID %d published __vdso_gettimeofday at 0x%lx\n",
           getpid(), (unsigned long)ready.symbol_address);
    while (running != 0) {
        pause();
    }

    close(status_fd);
    if (handle != NULL) {
        dlclose(handle);
    }
    return results.patched_result == VDSO_DEMO_RETURN_MARKER &&
                   results.restored_result == 0
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
