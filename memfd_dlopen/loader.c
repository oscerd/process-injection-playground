#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*demo_entry_fn)(void);

static int copy_to_memfd(int source_fd, int destination_fd) {
    unsigned char buffer[16 * 1024];

    for (;;) {
        ssize_t bytes_read = read(source_fd, buffer, sizeof(buffer));
        if (bytes_read == 0) {
            return 0;
        }
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read shared object");
            return -1;
        }

        size_t written = 0;
        while (written < (size_t)bytes_read) {
            ssize_t result = write(destination_fd, buffer + written,
                                   (size_t)bytes_read - written);
            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("write memfd");
                return -1;
            }
            written += (size_t)result;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shared-object>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int source_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (source_fd < 0) {
        perror("open shared object");
        return EXIT_FAILURE;
    }

    errno = 0;
    int memory_fd = memfd_create("process-injection-demo", MFD_CLOEXEC);
    if (memory_fd < 0) {
        int memfd_error = errno;
        fprintf(stderr, "memfd_create: %s\n", strerror(memfd_error));
        close(source_fd);
        return (memfd_error == ENOSYS || memfd_error == EPERM ||
                memfd_error == EACCES)
                   ? 77
                   : EXIT_FAILURE;
    }

    if (copy_to_memfd(source_fd, memory_fd) != 0) {
        close(source_fd);
        close(memory_fd);
        return EXIT_FAILURE;
    }
    close(source_fd);

    char memory_path[64];
    int path_length = snprintf(memory_path, sizeof(memory_path),
                               "/proc/self/fd/%d", memory_fd);
    if (path_length < 0 || (size_t)path_length >= sizeof(memory_path)) {
        fprintf(stderr, "Failed to construct the memfd path\n");
        close(memory_fd);
        return EXIT_FAILURE;
    }

    printf("[*] Loading shared object through %s\n", memory_path);
    fflush(stdout);
    void *handle = dlopen(memory_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        close(memory_fd);
        return EXIT_FAILURE;
    }

    dlerror();
    void *symbol = dlsym(handle, "demo_entry");
    const char *symbol_error = dlerror();
    if (symbol_error != NULL) {
        fprintf(stderr, "dlsym: %s\n", symbol_error);
        dlclose(handle);
        close(memory_fd);
        return EXIT_FAILURE;
    }

    _Static_assert(sizeof(demo_entry_fn) == sizeof(symbol),
                   "function and data pointers have different sizes");
    demo_entry_fn demo_entry = NULL;
    memcpy(&demo_entry, &symbol, sizeof(demo_entry));

    int result = demo_entry();
    printf("[+] demo_entry returned %d\n", result);

    dlclose(handle);
    close(memory_fd);
    return result == 42 ? EXIT_SUCCESS : EXIT_FAILURE;
}
