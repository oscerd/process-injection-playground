#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "demo_protocol.h"

static int read_exact(int fd, void *buffer, size_t length) {
    size_t consumed = 0;

    while (consumed < length) {
        ssize_t result = read(fd, (char *)buffer + consumed, length - consumed);
        if (result == 0) {
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        consumed += (size_t)result;
    }

    return 0;
}

static void terminate_child(pid_t child) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

static int wait_for_success(pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Controlled victim failed (status=%d)\n", status);
        return -1;
    }
    return 0;
}

static int write_proc_mem(int mem_fd, pid_t child,
                          const struct proc_mem_request *request) {
    size_t written = 0;
    while (written < request->length) {
        off_t offset = (off_t)(request->remote_address + written);
        ssize_t result = pwrite(mem_fd, request->value + written,
                                request->length - written, offset);
        if (result < 0) {
            int write_error = errno;
            fprintf(stderr, "pwrite /proc/%d/mem: %s\n", child,
                    strerror(write_error));
            errno = write_error;
            return -1;
        }
        if (result == 0) {
            errno = EIO;
            return -1;
        }
        written += (size_t)result;
    }

    printf("[+] Wrote %zu bytes through /proc/%d/mem at 0x%" PRIxPTR "\n",
           request->length, child, request->remote_address);
    return 0;
}

static int run_demo(const char *victim_program) {
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
            setenv("PROC_MEM_REQUEST_FD", fd_text, 1) != 0) {
            _exit(127);
        }
        execl(victim_program, victim_program, (char *)NULL);
        _exit(127);
    }

    close(request_pipe[1]);
    struct proc_mem_request request = {0};
    if (read_exact(request_pipe[0], &request, sizeof(request)) != 0) {
        close(request_pipe[0]);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    close(request_pipe[0]);

    if (request.magic != PROC_MEM_DEMO_MAGIC || request.remote_address == 0 ||
        request.length == 0 || request.length > sizeof(request.value) ||
        (request.flags & ~PROC_MEM_EXPECT_DENIED) != 0) {
        fprintf(stderr, "[-] Victim sent an invalid write request\n");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    char mem_path[64];
    if (snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", child) < 0) {
        terminate_child(child);
        return EXIT_FAILURE;
    }

    printf("[*] Opening %s for a controlled write\n", mem_path);
    errno = 0;
    int mem_fd = open(mem_path, O_RDWR | O_CLOEXEC);
    int operation_result = -1;
    int operation_error = errno;
    if (mem_fd >= 0) {
        operation_result = write_proc_mem(mem_fd, child, &request);
        operation_error = errno;
        close(mem_fd);
    } else {
        fprintf(stderr, "open %s: %s\n", mem_path, strerror(operation_error));
    }

    if ((request.flags & PROC_MEM_EXPECT_DENIED) != 0) {
        if (kill(child, SIGUSR1) != 0) {
            perror("signal denied-write result");
            terminate_child(child);
            return EXIT_FAILURE;
        }
        if (wait_for_success(child) != 0) {
            return EXIT_FAILURE;
        }
        if (operation_result == 0) {
            fprintf(stderr, "[-] Write unexpectedly succeeded\n");
            return EXIT_FAILURE;
        }
        if (operation_error != EACCES && operation_error != EPERM) {
            fprintf(stderr, "[-] Expected access denial, received: %s\n",
                    strerror(operation_error));
            return EXIT_FAILURE;
        }
        puts("[+] Kernel denied non-dumpable procfs memory access as expected");
        puts("[+] Victim confirmed that the read-only marker was unchanged");
        return EXIT_SUCCESS;
    }

    if (operation_result != 0) {
        terminate_child(child);
        if (operation_error == EPERM || operation_error == EACCES ||
            operation_error == EIO || operation_error == EFAULT) {
            fprintf(stderr,
                    "[SKIP] Kernel or sandbox policy blocked procfs "
                    "memory override\n");
            return 77;
        }
        return EXIT_FAILURE;
    }

    if (wait_for_success(child) != 0) {
        return EXIT_FAILURE;
    }
    puts("[+] Victim observed the marker in its read-only mapping");
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
