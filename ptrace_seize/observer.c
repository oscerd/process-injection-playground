#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void terminate_child(pid_t child) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

static int wait_until_ready(int fd) {
    unsigned char ready = 0;

    for (;;) {
        ssize_t result = read(fd, &ready, sizeof(ready));
        if (result == (ssize_t)sizeof(ready)) {
            return ready == 1 ? 0 : -1;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
}

static int run_demo(const char *victim_program) {
    int ready_pipe[2];
    if (pipe(ready_pipe) != 0) {
        perror("pipe");
        return EXIT_FAILURE;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return EXIT_FAILURE;
    }

    if (child == 0) {
        char fd_text[32];
        close(ready_pipe[0]);
        if (snprintf(fd_text, sizeof(fd_text), "%d", ready_pipe[1]) < 0 ||
            setenv("PTRACE_READY_FD", fd_text, 1) != 0) {
            perror("prepare victim environment");
            _exit(127);
        }
        execl(victim_program, victim_program, (char *)NULL);
        perror("exec victim");
        _exit(127);
    }

    close(ready_pipe[1]);
    if (wait_until_ready(ready_pipe[0]) != 0) {
        fprintf(stderr, "[-] Victim did not announce readiness\n");
        close(ready_pipe[0]);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    close(ready_pipe[0]);

    printf("[*] Seizing child PID %d without an attach-time SIGSTOP\n", child);
    unsigned long options = PTRACE_O_EXITKILL;
    errno = 0;
    if (ptrace(PTRACE_SEIZE, child, NULL, (void *)(uintptr_t)options) != 0) {
        int seize_error = errno;
        fprintf(stderr, "PTRACE_SEIZE: %s\n", strerror(seize_error));
        terminate_child(child);
        return (seize_error == EPERM || seize_error == EACCES) ? 77
                                                               : EXIT_FAILURE;
    }

    puts("[+] Trace relationship established; requesting an explicit stop");
    if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) != 0) {
        perror("PTRACE_INTERRUPT");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    int status = 0;
    if (waitpid(child, &status, __WALL) < 0) {
        perror("waitpid");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] Tracee did not enter a ptrace stop (status=%d)\n",
                status);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    printf("[+] Tracee stopped with signal %d\n", WSTOPSIG(status));
    if (ptrace(PTRACE_DETACH, child, NULL, NULL) != 0) {
        perror("PTRACE_DETACH");
        terminate_child(child);
        return EXIT_FAILURE;
    }

    puts("[+] Detached cleanly; no memory or registers were modified");
    terminate_child(child);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--spawn") != 0) {
        fprintf(stderr, "Usage: %s --spawn <victim-program>\n", argv[0]);
        return EXIT_FAILURE;
    }

    return run_demo(argv[2]);
}
