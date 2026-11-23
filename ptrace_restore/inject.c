#include "demo_protocol.h"

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
#error "The ptrace restore lab currently supports x86_64 only"
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
                   setenv(RESTORE_DEMO_STATUS_FD, text, 1) != 0
               ? -1
               : 0;
}

static pid_t spawn_victim(const char *program, int *status_fd,
                          struct restore_demo_ready *ready) {
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
        ready->magic != RESTORE_DEMO_MAGIC) {
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

static size_t build_marker_stub(unsigned char *stub, uint64_t marker_address) {
    size_t cursor = 0;
    uint64_t marker = RESTORE_DEMO_MARKER;

    stub[cursor++] = 0x48;
    stub[cursor++] = 0xb8;
    memcpy(stub + cursor, &marker_address, sizeof(marker_address));
    cursor += sizeof(marker_address);

    stub[cursor++] = 0x48;
    stub[cursor++] = 0xba;
    memcpy(stub + cursor, &marker, sizeof(marker));
    cursor += sizeof(marker);

    stub[cursor++] = 0x48;
    stub[cursor++] = 0x89;
    stub[cursor++] = 0x10;
    stub[cursor++] = 0xcc;
    return cursor;
}

static int registers_match(const struct user_regs_struct *left,
                           const struct user_regs_struct *right) {
    return left->r15 == right->r15 && left->r14 == right->r14 &&
           left->r13 == right->r13 && left->r12 == right->r12 &&
           left->rbp == right->rbp && left->rbx == right->rbx &&
           left->r11 == right->r11 && left->r10 == right->r10 &&
           left->r9 == right->r9 && left->r8 == right->r8 &&
           left->rax == right->rax && left->rcx == right->rcx &&
           left->rdx == right->rdx && left->rsi == right->rsi &&
           left->rdi == right->rdi && left->orig_rax == right->orig_rax &&
           left->rip == right->rip && left->cs == right->cs &&
           left->eflags == right->eflags && left->rsp == right->rsp &&
           left->ss == right->ss && left->fs_base == right->fs_base &&
           left->gs_base == right->gs_base && left->ds == right->ds &&
           left->es == right->es && left->fs == right->fs &&
           left->gs == right->gs;
}

static int run_demo(const char *victim_program) {
    struct restore_demo_ready ready;
    int status_fd = -1;
    pid_t child = spawn_victim(victim_program, &status_fd, &ready);
    if (child < 0) {
        return EXIT_FAILURE;
    }

    printf("[*] Attaching to controlled child PID %d\n", child);
    errno = 0;
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        int attach_error = errno;
        fprintf(stderr, "PTRACE_ATTACH: %s\n", strerror(attach_error));
        close(status_fd);
        terminate_child(child);
        return attach_error == EPERM || attach_error == EACCES ? 77
                                                               : EXIT_FAILURE;
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        perror("waitpid attach stop");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0) {
        perror("PTRACE_SETOPTIONS");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    struct user_regs_struct saved_registers;
    unsigned char saved_patch[RESTORE_DEMO_PATCH_SIZE];
    uint64_t saved_marker = 0;
    if (ptrace(PTRACE_GETREGS, child, NULL, &saved_registers) != 0 ||
        read_remote(child, ready.patch_address, saved_patch,
                    sizeof(saved_patch)) != 0 ||
        read_remote(child, ready.marker_address, &saved_marker,
                    sizeof(saved_marker)) != 0) {
        perror("save tracee state");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (saved_marker != 0) {
        fprintf(stderr, "[-] Victim marker did not start at zero\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    unsigned char stub[RESTORE_DEMO_PATCH_SIZE];
    memset(stub, 0x90, sizeof(stub));
    size_t stub_length = build_marker_stub(stub, ready.marker_address);
    if (stub_length > sizeof(stub) ||
        write_remote(child, ready.patch_address, stub, sizeof(stub)) != 0) {
        perror("stage marker stub");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    struct user_regs_struct redirected_registers = saved_registers;
    redirected_registers.rip = ready.patch_address;
    if (ptrace(PTRACE_SETREGS, child, NULL, &redirected_registers) != 0 ||
        ptrace(PTRACE_CONT, child, NULL, NULL) != 0) {
        perror("execute marker stub");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[-] Tracee did not return through INT3\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    uint64_t observed_marker = 0;
    if (read_remote(child, ready.marker_address, &observed_marker,
                    sizeof(observed_marker)) != 0 ||
        observed_marker != RESTORE_DEMO_MARKER) {
        fprintf(stderr, "[-] Benign marker stub did not execute\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    printf("[+] Marker stub executed and stopped through INT3 at 0x%" PRIx64
           "\n",
           ready.patch_address);

    if (write_remote(child, ready.patch_address, saved_patch,
                     sizeof(saved_patch)) != 0 ||
        write_remote(child, ready.marker_address, &saved_marker,
                     sizeof(saved_marker)) != 0 ||
        ptrace(PTRACE_SETREGS, child, NULL, &saved_registers) != 0) {
        perror("restore tracee state");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    unsigned char patch_check[RESTORE_DEMO_PATCH_SIZE];
    uint64_t marker_check = UINT64_MAX;
    struct user_regs_struct register_check;
    if (read_remote(child, ready.patch_address, patch_check,
                    sizeof(patch_check)) != 0 ||
        read_remote(child, ready.marker_address, &marker_check,
                    sizeof(marker_check)) != 0 ||
        ptrace(PTRACE_GETREGS, child, NULL, &register_check) != 0 ||
        memcmp(patch_check, saved_patch, sizeof(patch_check)) != 0 ||
        marker_check != saved_marker ||
        !registers_match(&register_check, &saved_registers)) {
        fprintf(stderr, "[-] State verification failed before detach\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] Code bytes, marker data, and registers match their saved state");

    if (ptrace(PTRACE_DETACH, child, NULL, NULL) != 0) {
        perror("PTRACE_DETACH");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    if (kill(child, SIGUSR1) != 0) {
        perror("signal restored victim");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }

    unsigned char resumed = 0;
    if (read_exact(status_fd, &resumed, sizeof(resumed)) != 0 ||
        resumed != 'R') {
        fprintf(stderr, "[-] Victim did not acknowledge resumed execution\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    close(status_fd);

    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] Restored victim did not exit cleanly\n");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] Restored victim resumed and exited normally");
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
