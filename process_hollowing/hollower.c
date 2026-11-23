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

#if !defined(__x86_64__)
#error "This entry-point stomping lab currently supports x86_64 only"
#endif

/* exit(42), followed by padding that is never executed. */
static const unsigned char benign_entry[16] = {
    0xb8, 0x3c, 0x00, 0x00, 0x00, /* mov $60, %eax */
    0xbf, 0x2a, 0x00, 0x00, 0x00, /* mov $42, %edi */
    0x0f, 0x05,                   /* syscall */
    0x90, 0x90, 0x90, 0x90,
};

static void terminate_child(pid_t child) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

static int poke_bytes(pid_t child, uintptr_t address,
                      const unsigned char *bytes, size_t length) {
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        long word = 0;
        size_t remaining = length - offset;
        size_t copy_length = remaining < sizeof(word) ? remaining : sizeof(word);
        memcpy(&word, bytes + offset, copy_length);
        if (ptrace(PTRACE_POKETEXT, child,
                   (void *)(address + offset), (void *)word) != 0) {
            return -1;
        }
    }
    return 0;
}

static int run_demo(const char *victim_program) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (child == 0) {
        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            int trace_error = errno;
            fprintf(stderr, "PTRACE_TRACEME: %s\n", strerror(trace_error));
            _exit(trace_error == EPERM || trace_error == EACCES ? 77 : 1);
        }
        execl(victim_program, victim_program, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid exec stop");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
        return 77;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[-] Child did not stop after exec (status=%d)\n",
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

    printf("[*] Child stopped immediately after exec at RIP 0x%" PRIx64 "\n",
           (uint64_t)registers.rip);
    if (poke_bytes(child, (uintptr_t)registers.rip, benign_entry,
                   sizeof(benign_entry)) != 0) {
        perror("PTRACE_POKETEXT entry point");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] Replaced 16 entry-point bytes with a benign exit marker");

    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("PTRACE_CONT");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid completion");
        return EXIT_FAILURE;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        fprintf(stderr, "[-] Stomped child did not exit with marker 42 "
                        "(status=%d)\n",
                status);
        return EXIT_FAILURE;
    }

    puts("[+] Entry-point replacement executed and exited with marker 42");
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
