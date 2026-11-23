#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "demo_protocol.h"

static void usage(const char *program) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --spawn <victim-program>\n"
            "  %s <pid> <remote-address> [value]\n",
            program, program);
}

static int parse_u64(const char *text, uint64_t *value) {
    char *end = NULL;

    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 0;
}

static int read_exact(int fd, void *buffer, size_t length) {
    size_t consumed = 0;

    while (consumed < length) {
        ssize_t result = read(fd, (char *)buffer + consumed, length - consumed);
        if (result == 0) {
            fprintf(stderr, "[-] Victim closed the request pipe early\n");
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read request pipe");
            return -1;
        }
        consumed += (size_t)result;
    }

    return 0;
}

static int write_remote(pid_t pid, uintptr_t remote_address, const void *value,
                        size_t length) {
    struct iovec local = {
        .iov_base = (void *)value,
        .iov_len = length,
    };
    struct iovec remote = {
        .iov_base = (void *)remote_address,
        .iov_len = length,
    };

    errno = 0;
    ssize_t written = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (written < 0) {
        int write_error = errno;
        fprintf(stderr, "process_vm_writev: %s\n", strerror(write_error));
        errno = write_error;
        return -1;
    }
    if ((size_t)written != length) {
        fprintf(stderr, "[-] Partial remote write: %zd of %zu bytes\n", written,
                length);
        errno = EIO;
        return -1;
    }

    printf("[+] Wrote %zu bytes to PID %d at 0x%" PRIxPTR "\n", length,
           pid, remote_address);
    return 0;
}

static int run_spawn_demo(const char *victim_program) {
    int request_pipe[2];
    if (pipe(request_pipe) != 0) {
        perror("pipe");
        return EXIT_FAILURE;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(request_pipe[0]);
        close(request_pipe[1]);
        return EXIT_FAILURE;
    }

    if (child == 0) {
        char fd_text[32];

        close(request_pipe[0]);
        if (snprintf(fd_text, sizeof(fd_text), "%d", request_pipe[1]) < 0 ||
            setenv("PIP_REQUEST_FD", fd_text, 1) != 0) {
            perror("prepare victim environment");
            _exit(127);
        }

        execl(victim_program, victim_program, (char *)NULL);
        perror("exec victim");
        _exit(127);
    }

    close(request_pipe[1]);

    struct pip_demo_request request = {0};
    if (read_exact(request_pipe[0], &request, sizeof(request)) != 0) {
        close(request_pipe[0]);
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
        return EXIT_FAILURE;
    }
    close(request_pipe[0]);

    if (request.magic != PIP_DEMO_MAGIC || request.remote_address == 0 ||
        request.length == 0 || request.length > sizeof(request.value) ||
        (request.flags & ~PIP_EXPECT_DENIED) != 0) {
        fprintf(stderr, "[-] Victim sent an invalid write request\n");
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
        return EXIT_FAILURE;
    }

    printf("[*] Spawned controlled victim PID %d\n", child);
    printf("[*] Victim write address: 0x%" PRIxPTR "\n",
           request.remote_address);
    fflush(stdout);

    int write_result = write_remote(child, request.remote_address, request.value,
                                    request.length);
    if ((request.flags & PIP_EXPECT_DENIED) != 0) {
        int write_error = errno;
        if (kill(child, SIGUSR1) != 0) {
            perror("signal denied-write result");
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
            return EXIT_FAILURE;
        }

        int status = 0;
        if (waitpid(child, &status, 0) < 0) {
            perror("waitpid");
            return EXIT_FAILURE;
        }
        if (write_result == 0) {
            fprintf(stderr,
                    "[-] Write unexpectedly succeeded against a non-dumpable "
                    "victim\n");
            return EXIT_FAILURE;
        }
        if (write_error != EPERM && write_error != EACCES) {
            fprintf(stderr, "[-] Expected an access error, received: %s\n",
                    strerror(write_error));
            return EXIT_FAILURE;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr,
                    "[-] Victim did not confirm unchanged state (status=%d)\n",
                    status);
            return EXIT_FAILURE;
        }

        printf("[+] Kernel denied the write as expected\n");
        printf("[+] Victim confirmed that the marker remained unchanged\n");
        return EXIT_SUCCESS;
    }

    if (write_result != 0) {
        int write_error = errno;
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
        if (write_error == EPERM || write_error == EACCES) {
            fprintf(stderr,
                    "[SKIP] Kernel or sandbox policy denied the controlled "
                    "cross-process write\n");
            return 77;
        }
        return EXIT_FAILURE;
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return EXIT_FAILURE;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Victim did not confirm the marker (status=%d)\n", status);
        return EXIT_FAILURE;
    }

    printf("[+] Victim confirmed the requested behavior\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--spawn") == 0) {
        return run_spawn_demo(argv[2]);
    }

    if (argc != 3 && argc != 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    uint64_t pid_value = 0;
    uint64_t address_value = 0;
    uint64_t marker = PIP_DEMO_MARKER;
    if (parse_u64(argv[1], &pid_value) != 0 || pid_value == 0 ||
        pid_value > INT32_MAX) {
        fprintf(stderr, "[-] Invalid PID: %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    if (parse_u64(argv[2], &address_value) != 0 || address_value == 0) {
        fprintf(stderr, "[-] Invalid remote address: %s\n", argv[2]);
        return EXIT_FAILURE;
    }
    if (argc == 4 && parse_u64(argv[3], &marker) != 0) {
        fprintf(stderr, "[-] Invalid marker value: %s\n", argv[3]);
        return EXIT_FAILURE;
    }

    return write_remote((pid_t)pid_value, (uintptr_t)address_value, &marker,
                        sizeof(marker)) == 0
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
