#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "demo_protocol.h"

#if !defined(__x86_64__)
#error "This register-redirection lab currently supports x86_64 only"
#endif

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

static int child_result(pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return EXIT_FAILURE;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
        return 77;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Redirected child failed (status=%d)\n", status);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
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
            setenv("PTRACE_TRACEME_FD", fd_text, 1) != 0) {
            _exit(127);
        }
        execl(victim_program, victim_program, (char *)NULL);
        _exit(127);
    }

    close(request_pipe[1]);
    struct redirect_request request = {0};
    if (read_exact(request_pipe[0], &request, sizeof(request)) != 0) {
        close(request_pipe[0]);
        return child_result(child);
    }
    close(request_pipe[0]);

    if (request.magic != REDIRECT_MAGIC || request.target_address == 0) {
        fprintf(stderr, "[-] Victim sent an invalid redirect request\n");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "[-] Victim did not enter its expected stop (status=%d)\n",
                status);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0) {
        perror("PTRACE_SETOPTIONS");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    struct user_regs_struct registers;
    if (ptrace(PTRACE_GETREGS, child, NULL, &registers) != 0) {
        perror("PTRACE_GETREGS");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    printf("[*] Original RIP: 0x%" PRIx64 "\n", (uint64_t)registers.rip);
    printf("[*] Redirect target: 0x%" PRIxPTR "\n",
           request.target_address);
    registers.rip = request.target_address;
    registers.rsp = (registers.rsp & ~UINT64_C(0xf)) - UINT64_C(8);

    if (ptrace(PTRACE_SETREGS, child, NULL, &registers) != 0) {
        perror("PTRACE_SETREGS");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] RIP now points to an existing benign function in the victim");

    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("PTRACE_CONT");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    int result = child_result(child);
    if (result == EXIT_SUCCESS) {
        puts("[+] Victim confirmed PTRACE_TRACEME execution redirection");
    }
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--spawn") != 0) {
        fprintf(stderr, "Usage: %s --spawn <victim-program>\n", argv[0]);
        return EXIT_FAILURE;
    }

    return run_demo(argv[2]);
}
