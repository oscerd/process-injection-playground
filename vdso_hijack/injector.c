#include "demo_protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The VDSO hijack lab currently supports x86_64 only"
#endif

static void terminate_child(pid_t child) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
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

static int set_fd_environment(int fd) {
    char text[32];
    int length = snprintf(text, sizeof(text), "%d", fd);
    return length < 0 || (size_t)length >= sizeof(text) ||
                   setenv(VDSO_DEMO_STATUS_FD, text, 1) != 0
               ? -1
               : 0;
}

static pid_t spawn_victim(const char *program, int *status_fd,
                          struct vdso_demo_ready *ready) {
    int status_pipe[2];
    if (pipe(status_pipe) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(status_pipe[0]);
        close(status_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(status_pipe[0]);
        if (set_fd_environment(status_pipe[1]) != 0) {
            _exit(127);
        }
        execl(program, program, (char *)NULL);
        _exit(127);
    }

    close(status_pipe[1]);
    if (read_exact(status_pipe[0], ready, sizeof(*ready)) != 0 ||
        ready->magic != VDSO_DEMO_MAGIC) {
        fprintf(stderr, "[-] Victim did not publish a valid protocol record\n");
        close(status_pipe[0]);
        terminate_child(child);
        return -1;
    }
    *status_fd = status_pipe[0];
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

static int address_is_in_vdso(pid_t child, uint64_t address) {
    char maps_path[64];
    int length = snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", child);
    if (length < 0 || (size_t)length >= sizeof(maps_path)) {
        return 0;
    }
    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        return 0;
    }

    char line[PATH_MAX + 128];
    int found = 0;
    while (fgets(line, sizeof(line), maps) != NULL) {
        uint64_t start = 0;
        uint64_t end = 0;
        if (strstr(line, "[vdso]") != NULL &&
            sscanf(line, "%" SCNx64 "-%" SCNx64, &start, &end) == 2 &&
            address >= start && address < end) {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static int wait_for_stop(pid_t child, int expected_signal) {
    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != expected_signal) {
        return -1;
    }
    return 0;
}

static int run_demo(const char *victim_program) {
    struct vdso_demo_ready ready;
    int status_fd = -1;
    pid_t child = spawn_victim(victim_program, &status_fd, &ready);
    if (child < 0) {
        return EXIT_FAILURE;
    }
    if (ready.symbol_address == 0) {
        puts("[SKIP] __vdso_gettimeofday is unavailable");
        close(status_fd);
        terminate_child(child);
        return 77;
    }
    if (!address_is_in_vdso(child, ready.symbol_address)) {
        fprintf(stderr, "[-] Published symbol is not inside [vdso]\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    printf("[*] Attaching to child PID %d and [vdso] address 0x%" PRIx64 "\n",
           child, ready.symbol_address);
    errno = 0;
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        int attach_error = errno;
        fprintf(stderr, "PTRACE_ATTACH: %s\n", strerror(attach_error));
        close(status_fd);
        terminate_child(child);
        return attach_error == EPERM || attach_error == EACCES ? 77
                                                               : EXIT_FAILURE;
    }
    if (wait_for_stop(child, SIGSTOP) != 0 ||
        ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0) {
        perror("prepare ptrace stop");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    unsigned char saved_bytes[VDSO_DEMO_PATCH_SIZE];
    unsigned char patched_bytes[VDSO_DEMO_PATCH_SIZE];
    if (read_remote(child, ready.symbol_address, saved_bytes,
                    sizeof(saved_bytes)) != 0) {
        perror("read VDSO bytes");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    memcpy(patched_bytes, saved_bytes, sizeof(patched_bytes));
    const unsigned char return_marker[] = {
        0xb8, VDSO_DEMO_RETURN_MARKER, 0x00, 0x00, 0x00,
        0xc3,
    };
    memcpy(patched_bytes, return_marker, sizeof(return_marker));
    if (write_remote(child, ready.symbol_address, patched_bytes,
                     sizeof(patched_bytes)) != 0 ||
        ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGUSR1) != 0) {
        perror("patch and exercise VDSO");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    if (wait_for_stop(child, SIGTRAP) != 0) {
        fprintf(stderr, "[-] Victim did not trap after the patched VDSO call\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    struct vdso_demo_results observed_results;
    if (read_remote(child, ready.result_address, &observed_results,
                    sizeof(observed_results)) != 0 ||
        observed_results.patched_result != VDSO_DEMO_RETURN_MARKER) {
        fprintf(stderr, "[-] Patched VDSO function did not return marker %d\n",
                VDSO_DEMO_RETURN_MARKER);
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    printf("[+] Patched VDSO function returned marker %d\n",
           observed_results.patched_result);

    if (write_remote(child, ready.symbol_address, saved_bytes,
                     sizeof(saved_bytes)) != 0) {
        perror("restore VDSO bytes");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    unsigned char restored_bytes[VDSO_DEMO_PATCH_SIZE];
    if (read_remote(child, ready.symbol_address, restored_bytes,
                    sizeof(restored_bytes)) != 0 ||
        memcmp(restored_bytes, saved_bytes, sizeof(saved_bytes)) != 0) {
        fprintf(stderr, "[-] VDSO byte restoration verification failed\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    if (ptrace(PTRACE_DETACH, child, NULL, NULL) != 0) {
        perror("PTRACE_DETACH");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    unsigned char marker = 0;
    if (read_exact(status_fd, &marker, sizeof(marker)) != 0 || marker != 'P' ||
        kill(child, SIGUSR2) != 0 ||
        read_exact(status_fd, &marker, sizeof(marker)) != 0 || marker != 'R') {
        fprintf(stderr, "[-] Victim did not confirm restored VDSO behavior\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    close(status_fd);

    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Restored VDSO victim did not exit cleanly\n");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] VDSO bytes restored and the victim resumed normally");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3 || strcmp(argv[1], "--spawn") != 0) {
        fprintf(stderr, "Usage: %s --spawn <victim-program>\n", argv[0]);
        return EXIT_FAILURE;
    }
    return run_demo(argv[2]);
}
