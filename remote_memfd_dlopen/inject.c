#include "demo_protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The remote dlopen lab currently supports x86_64 only"
#endif

enum load_mode {
    LOAD_FROM_DISK,
    LOAD_FROM_MEMFD,
};

static void terminate_child(pid_t child) {
    if (child <= 0) {
        return;
    }
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
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

static int read_exact(int fd, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t bytes_read = read(fd, cursor, length);
        if (bytes_read < 0 && errno == EINTR) {
            continue;
        }
        if (bytes_read <= 0) {
            return -1;
        }
        cursor += (size_t)bytes_read;
        length -= (size_t)bytes_read;
    }
    return 0;
}

static int wait_for_marker(int fd, unsigned char expected) {
    struct pollfd descriptor = {
        .fd = fd,
        .events = POLLIN,
    };
    int poll_result;
    do {
        poll_result = poll(&descriptor, 1, 3000);
    } while (poll_result < 0 && errno == EINTR);
    if (poll_result <= 0) {
        return -1;
    }

    unsigned char marker = 0;
    return read_exact(fd, &marker, sizeof(marker)) == 0 && marker == expected
               ? 0
               : -1;
}

static int copy_to_memfd(const char *source_path) {
    int source_fd = open(source_path, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0) {
        perror("open shared object");
        return -1;
    }

    int memory_fd = memfd_create("remote-dlopen-demo", MFD_CLOEXEC);
    if (memory_fd < 0) {
        int saved_errno = errno;
        close(source_fd);
        errno = saved_errno;
        return -1;
    }

    unsigned char buffer[16U * 1024U];
    for (;;) {
        ssize_t bytes_read = read(source_fd, buffer, sizeof(buffer));
        if (bytes_read == 0) {
            break;
        }
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read shared object");
            close(source_fd);
            close(memory_fd);
            return -1;
        }
        if (write_all(memory_fd, buffer, (size_t)bytes_read) != 0) {
            perror("write memfd");
            close(source_fd);
            close(memory_fd);
            return -1;
        }
    }

    close(source_fd);
    return memory_fd;
}

static int clear_close_on_exec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0 ? -1 : 0;
}

static int set_fd_environment(const char *name, int fd) {
    char text[32];
    int length = snprintf(text, sizeof(text), "%d", fd);
    return length < 0 || (size_t)length >= sizeof(text) ||
                   setenv(name, text, 1) != 0
               ? -1
               : 0;
}

static pid_t spawn_victim(const char *program, int memory_fd,
                          int *marker_read_fd,
                          struct remote_demo_ready *ready) {
    int ready_pipe[2];
    int marker_pipe[2];
    if (pipe(ready_pipe) != 0) {
        perror("ready pipe");
        return -1;
    }
    if (pipe(marker_pipe) != 0) {
        perror("marker pipe");
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        close(marker_pipe[0]);
        close(marker_pipe[1]);
        return -1;
    }

    if (child == 0) {
        close(ready_pipe[0]);
        close(marker_pipe[0]);
        if (clear_close_on_exec(ready_pipe[1]) != 0 ||
            clear_close_on_exec(marker_pipe[1]) != 0 ||
            (memory_fd >= 0 && clear_close_on_exec(memory_fd) != 0) ||
            set_fd_environment(REMOTE_DEMO_READY_FD, ready_pipe[1]) != 0 ||
            set_fd_environment(REMOTE_DEMO_MARKER_FD, marker_pipe[1]) != 0) {
            _exit(127);
        }
        execl(program, program, (char *)NULL);
        _exit(127);
    }

    close(ready_pipe[1]);
    close(marker_pipe[1]);
    if (read_exact(ready_pipe[0], ready, sizeof(*ready)) != 0 ||
        ready->magic != REMOTE_DEMO_MAGIC) {
        fprintf(stderr, "[-] Victim did not publish a valid protocol record\n");
        close(ready_pipe[0]);
        close(marker_pipe[0]);
        terminate_child(child);
        return -1;
    }
    close(ready_pipe[0]);
    *marker_read_fd = marker_pipe[0];
    return child;
}

static int read_remote(pid_t child, uint64_t address, void *buffer,
                       size_t length) {
    unsigned char *output = buffer;
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child,
                           (void *)(uintptr_t)(address + offset), NULL);
        if (errno != 0) {
            return -1;
        }
        size_t remaining = length - offset;
        size_t amount = remaining < sizeof(word) ? remaining : sizeof(word);
        memcpy(output + offset, &word, amount);
    }
    return 0;
}

static int write_remote(pid_t child, uint64_t address, const void *buffer,
                        size_t length) {
    const unsigned char *input = buffer;
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        long word = 0;
        size_t remaining = length - offset;
        size_t amount = remaining < sizeof(word) ? remaining : sizeof(word);
        if (amount != sizeof(word)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, child,
                          (void *)(uintptr_t)(address + offset), NULL);
            if (errno != 0) {
                return -1;
            }
        }
        memcpy(&word, input + offset, amount);
        if (ptrace(PTRACE_POKEDATA, child,
                   (void *)(uintptr_t)(address + offset), (void *)word) != 0) {
            return -1;
        }
    }
    return 0;
}

static const char *path_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static uint64_t find_mapping_base(pid_t child, const char *object_name) {
    char maps_path[64];
    int path_length = snprintf(maps_path, sizeof(maps_path),
                               "/proc/%d/maps", child);
    if (path_length < 0 || (size_t)path_length >= sizeof(maps_path)) {
        return 0;
    }

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        return 0;
    }

    uint64_t result = 0;
    char line[PATH_MAX + 256];
    while (fgets(line, sizeof(line), maps) != NULL) {
        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t offset = 0;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %*4s %" SCNx64,
                   &start, &end, &offset) == 3 &&
            offset == 0 && strstr(line, object_name) != NULL) {
            result = start;
            break;
        }
    }
    fclose(maps);
    return result;
}

static uint64_t find_remote_dlopen(pid_t child) {
    dlerror();
    void *symbol = dlsym(RTLD_DEFAULT, "dlopen");
    const char *symbol_error = dlerror();
    if (symbol_error != NULL || symbol == NULL) {
        fprintf(stderr, "dlsym dlopen: %s\n",
                symbol_error == NULL ? "not found" : symbol_error);
        return 0;
    }

    Dl_info information;
    if (dladdr(symbol, &information) == 0 || information.dli_fbase == NULL ||
        information.dli_fname == NULL) {
        fprintf(stderr, "[-] dladdr could not describe the local dlopen\n");
        return 0;
    }

    uint64_t local_symbol = (uintptr_t)symbol;
    uint64_t local_base = (uintptr_t)information.dli_fbase;
    uint64_t target_base = find_mapping_base(
        child, path_basename(information.dli_fname));
    if (target_base == 0 || local_symbol < local_base) {
        fprintf(stderr, "[-] Could not resolve the target loader mapping\n");
        return 0;
    }
    return target_base + (local_symbol - local_base);
}

static size_t build_dlopen_stub(unsigned char *stub, uint64_t path_address,
                                uint64_t dlopen_address) {
    size_t cursor = 0;

    stub[cursor++] = 0x48;
    stub[cursor++] = 0xbf;
    memcpy(stub + cursor, &path_address, sizeof(path_address));
    cursor += sizeof(path_address);

    stub[cursor++] = 0xbe;
    uint32_t flags = RTLD_NOW | RTLD_LOCAL;
    memcpy(stub + cursor, &flags, sizeof(flags));
    cursor += sizeof(flags);

    stub[cursor++] = 0x48;
    stub[cursor++] = 0xb8;
    memcpy(stub + cursor, &dlopen_address, sizeof(dlopen_address));
    cursor += sizeof(dlopen_address);

    stub[cursor++] = 0xff;
    stub[cursor++] = 0xd0;
    stub[cursor++] = 0xcc;
    return cursor;
}

static int mapping_contains(pid_t child, const char *needle) {
    char maps_path[64];
    int length = snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", child);
    if (length < 0 || (size_t)length >= sizeof(maps_path)) {
        return 0;
    }
    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        return 0;
    }
    char line[PATH_MAX + 256];
    int found = 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static int restore_and_verify(pid_t child,
                              const struct remote_demo_ready *ready,
                              const unsigned char *saved_patch,
                              const unsigned char *saved_path,
                              size_t path_length,
                              const unsigned char *saved_stack,
                              const struct user_regs_struct *saved_registers) {
    if (write_remote(child, ready->patch_address, saved_patch,
                     REMOTE_DEMO_PATCH_SIZE) != 0 ||
        write_remote(child, ready->path_address, saved_path, path_length) != 0 ||
        write_remote(child, ready->stack_address, saved_stack,
                     (size_t)ready->stack_size) != 0 ||
        ptrace(PTRACE_SETREGS, child, NULL, saved_registers) != 0) {
        return -1;
    }

    unsigned char patch_check[REMOTE_DEMO_PATCH_SIZE];
    unsigned char path_check[REMOTE_DEMO_PATH_CAPACITY];
    if (read_remote(child, ready->patch_address, patch_check,
                    sizeof(patch_check)) != 0 ||
        read_remote(child, ready->path_address, path_check, path_length) != 0 ||
        memcmp(patch_check, saved_patch, sizeof(patch_check)) != 0 ||
        memcmp(path_check, saved_path, path_length) != 0) {
        return -1;
    }
    return 0;
}

static int fail_after_spawn(pid_t child, int marker_fd, int memory_fd) {
    if (marker_fd >= 0) {
        close(marker_fd);
    }
    terminate_child(child);
    if (memory_fd >= 0) {
        close(memory_fd);
    }
    return EXIT_FAILURE;
}

static int run_remote_load(enum load_mode mode, const char *library,
                           const char *victim_program) {
    char disk_path[PATH_MAX];
    if (realpath(library, disk_path) == NULL) {
        perror("realpath shared object");
        return EXIT_FAILURE;
    }

    int memory_fd = -1;
    if (mode == LOAD_FROM_MEMFD) {
        errno = 0;
        memory_fd = copy_to_memfd(disk_path);
        if (memory_fd < 0) {
            int memfd_error = errno;
            fprintf(stderr, "memfd staging: %s\n", strerror(memfd_error));
            return memfd_error == ENOSYS || memfd_error == EPERM ||
                           memfd_error == EACCES
                       ? 77
                       : EXIT_FAILURE;
        }
    }

    struct remote_demo_ready ready;
    int marker_fd = -1;
    pid_t child = spawn_victim(victim_program, memory_fd, &marker_fd, &ready);
    if (child < 0) {
        if (memory_fd >= 0) {
            close(memory_fd);
        }
        return EXIT_FAILURE;
    }

    char target_path[REMOTE_DEMO_PATH_CAPACITY];
    int target_length = mode == LOAD_FROM_MEMFD
                            ? snprintf(target_path, sizeof(target_path),
                                       "/proc/self/fd/%d", memory_fd)
                            : snprintf(target_path, sizeof(target_path), "%s",
                                       disk_path);
    if (target_length < 0 || (size_t)target_length >= sizeof(target_path)) {
        fprintf(stderr, "[-] Target library path is too long\n");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }
    size_t path_length = (size_t)target_length + 1U;

    printf("[*] Attaching to controlled child PID %d for %s loading\n", child,
           mode == LOAD_FROM_MEMFD ? "memfd-backed" : "on-disk");
    errno = 0;
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        int attach_error = errno;
        fprintf(stderr, "PTRACE_ATTACH: %s\n", strerror(attach_error));
        fail_after_spawn(child, marker_fd, memory_fd);
        return attach_error == EPERM || attach_error == EACCES ? 77
                                                               : EXIT_FAILURE;
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        perror("waitpid attach stop");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }
    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0) {
        perror("PTRACE_SETOPTIONS");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    struct user_regs_struct saved_registers;
    if (ptrace(PTRACE_GETREGS, child, NULL, &saved_registers) != 0) {
        perror("PTRACE_GETREGS");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    uint64_t dlopen_address = find_remote_dlopen(child);
    if (dlopen_address == 0 || ready.stack_size != REMOTE_DEMO_STACK_SIZE) {
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    unsigned char saved_patch[REMOTE_DEMO_PATCH_SIZE];
    unsigned char saved_path[REMOTE_DEMO_PATH_CAPACITY];
    unsigned char *saved_stack = malloc((size_t)ready.stack_size);
    if (saved_stack == NULL ||
        read_remote(child, ready.patch_address, saved_patch,
                    sizeof(saved_patch)) != 0 ||
        read_remote(child, ready.path_address, saved_path, path_length) != 0 ||
        read_remote(child, ready.stack_address, saved_stack,
                    (size_t)ready.stack_size) != 0) {
        perror("save remote state");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    unsigned char stub[REMOTE_DEMO_PATCH_SIZE];
    memset(stub, 0x90, sizeof(stub));
    size_t stub_length = build_dlopen_stub(stub, ready.path_address,
                                           dlopen_address);
    if (stub_length > sizeof(stub) ||
        write_remote(child, ready.path_address, target_path, path_length) != 0 ||
        write_remote(child, ready.patch_address, stub, sizeof(stub)) != 0) {
        perror("stage remote call");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    struct user_regs_struct call_registers = saved_registers;
    call_registers.rip = ready.patch_address;
    call_registers.rsp = (ready.stack_address + ready.stack_size - 128U) &
                         ~UINT64_C(0xf);
    call_registers.rbp = 0;
    if (ptrace(PTRACE_SETREGS, child, NULL, &call_registers) != 0 ||
        ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("execute remote dlopen");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[-] Remote call did not return through INT3\n");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    struct user_regs_struct result_registers;
    if (ptrace(PTRACE_GETREGS, child, NULL, &result_registers) != 0 ||
        result_registers.rax == 0) {
        fprintf(stderr, "[-] Remote dlopen returned NULL\n");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    const char *mapping_marker = mode == LOAD_FROM_MEMFD
                                     ? "memfd:remote-dlopen-demo"
                                     : disk_path;
    if (!mapping_contains(child, mapping_marker)) {
        fprintf(stderr, "[-] Expected library mapping was not visible\n");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }

    if (restore_and_verify(child, &ready, saved_patch, saved_path, path_length,
                           saved_stack, &saved_registers) != 0) {
        perror("restore remote state");
        free(saved_stack);
        return fail_after_spawn(child, marker_fd, memory_fd);
    }
    free(saved_stack);

    if (ptrace(PTRACE_DETACH, child, NULL, NULL) != 0) {
        perror("PTRACE_DETACH");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }
    puts("[+] Restored patch bytes, scratch data, stack, and registers");

    if (wait_for_marker(marker_fd, 'L') != 0 || kill(child, SIGUSR1) != 0 ||
        wait_for_marker(marker_fd, 'A') != 0) {
        fprintf(stderr, "[-] Target did not confirm load and resumed execution\n");
        return fail_after_spawn(child, marker_fd, memory_fd);
    }
    puts("[+] Constructor ran and the restored victim answered SIGUSR1");

    close(marker_fd);
    if (kill(child, SIGTERM) != 0 || waitpid(child, &status, 0) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Restored victim did not exit cleanly\n");
        terminate_child(child);
        if (memory_fd >= 0) {
            close(memory_fd);
        }
        return EXIT_FAILURE;
    }

    if (memory_fd >= 0) {
        close(memory_fd);
    }
    printf("[+] %s remote dlopen case completed\n",
           mode == LOAD_FROM_MEMFD ? "Memfd-backed" : "On-disk");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 7 || strcmp(argv[1], "--mode") != 0 ||
        strcmp(argv[3], "--library") != 0 ||
        strcmp(argv[5], "--spawn") != 0) {
        fprintf(stderr,
                "Usage: %s --mode disk|memfd --library <library.so> "
                "--spawn <victim>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    enum load_mode mode;
    if (strcmp(argv[2], "disk") == 0) {
        mode = LOAD_FROM_DISK;
    } else if (strcmp(argv[2], "memfd") == 0) {
        mode = LOAD_FROM_MEMFD;
    } else {
        fprintf(stderr, "Mode must be disk or memfd\n");
        return EXIT_FAILURE;
    }
    return run_remote_load(mode, argv[4], argv[6]);
}
