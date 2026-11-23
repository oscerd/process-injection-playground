#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
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

enum redirect_mode {
    REDIRECT_SETREGS,
    REDIRECT_POKEUSER,
};

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

static int poke_user_register(pid_t child, size_t offset, uint64_t value,
                              const char *register_name) {
    if (ptrace(PTRACE_POKEUSER, child, (void *)(uintptr_t)offset,
               (void *)(uintptr_t)value) != 0) {
        fprintf(stderr, "PTRACE_POKEUSER %s: %s\n", register_name,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int run_demo(const char *victim_program, enum redirect_mode mode) {
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
    uint64_t aligned_stack =
        (registers.rsp & ~UINT64_C(0xf)) - UINT64_C(8);

    if (mode == REDIRECT_SETREGS) {
        registers.rip = request.target_address;
        registers.rsp = aligned_stack;
        if (ptrace(PTRACE_SETREGS, child, NULL, &registers) != 0) {
            perror("PTRACE_SETREGS");
            terminate_child(child);
            return EXIT_FAILURE;
        }
        puts("[+] PTRACE_SETREGS updated RIP and RSP");
    } else {
        size_t rip_offset = offsetof(struct user, regs) +
                            offsetof(struct user_regs_struct, rip);
        size_t rsp_offset = offsetof(struct user, regs) +
                            offsetof(struct user_regs_struct, rsp);
        if (poke_user_register(child, rip_offset, request.target_address,
                               "RIP") != 0 ||
            poke_user_register(child, rsp_offset, aligned_stack, "RSP") != 0) {
            terminate_child(child);
            return EXIT_FAILURE;
        }
        puts("[+] PTRACE_POKEUSER updated RIP and RSP individually");
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
    enum redirect_mode mode = REDIRECT_SETREGS;
    const char *victim_program = NULL;

    if (argc == 3 && strcmp(argv[1], "--spawn") == 0) {
        victim_program = argv[2];
    } else if (argc == 4 && strcmp(argv[1], "--pokeuser") == 0 &&
               strcmp(argv[2], "--spawn") == 0) {
        mode = REDIRECT_POKEUSER;
        victim_program = argv[3];
    } else {
        fprintf(stderr,
                "Usage:\n"
                "  %s --spawn <victim-program>\n"
                "  %s --pokeuser --spawn <victim-program>\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    return run_demo(victim_program, mode);
}
