#include "demo_protocol.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The thread hijack lab currently supports x86_64 only"
#endif

#define MAX_TRACEES 32U

struct tracee_list {
    pid_t tids[MAX_TRACEES];
    size_t count;
};

static void terminate_child(pid_t child) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

static void terminate_traced_child(pid_t child,
                                   const struct tracee_list *list,
                                   size_t seized_count) {
    kill(child, SIGKILL);
    for (size_t index = 0; index < seized_count; ++index) {
        ptrace(PTRACE_CONT, list->tids[index], NULL,
               (void *)(uintptr_t)SIGKILL);
    }
    for (;;) {
        pid_t waited = waitpid(-1, NULL, __WALL);
        if (waited > 0 || (waited < 0 && errno == EINTR)) {
            continue;
        }
        break;
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
                   setenv(THREAD_DEMO_STATUS_FD, text, 1) != 0
               ? -1
               : 0;
}

static pid_t spawn_victim(const char *program, int *status_fd,
                          struct thread_demo_ready *ready) {
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
        ready->magic != THREAD_DEMO_MAGIC) {
        fprintf(stderr, "[-] Victim did not publish a valid protocol record\n");
        close(status_pipe[0]);
        terminate_child(child);
        return -1;
    }
    *status_fd = status_pipe[0];
    return child;
}

static int compare_pids(const void *left, const void *right) {
    pid_t left_pid = *(const pid_t *)left;
    pid_t right_pid = *(const pid_t *)right;
    return (left_pid > right_pid) - (left_pid < right_pid);
}

static int enumerate_threads(pid_t process_id, struct tracee_list *list) {
    char task_path[64];
    int length = snprintf(task_path, sizeof(task_path),
                          "/proc/%d/task", process_id);
    if (length < 0 || (size_t)length >= sizeof(task_path)) {
        return -1;
    }
    DIR *directory = opendir(task_path);
    if (directory == NULL) {
        return -1;
    }

    list->count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        errno = 0;
        long value = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            value <= 0 || value > INT32_MAX) {
            continue;
        }
        if (list->count == MAX_TRACEES) {
            closedir(directory);
            return -1;
        }
        list->tids[list->count++] = (pid_t)value;
    }
    closedir(directory);
    qsort(list->tids, list->count, sizeof(list->tids[0]), compare_pids);
    return list->count > 0 ? 0 : -1;
}

static int list_contains(const struct tracee_list *list, pid_t tid) {
    for (size_t index = 0; index < list->count; ++index) {
        if (list->tids[index] == tid) {
            return 1;
        }
    }
    return 0;
}

static int read_remote(pid_t tid, uint64_t address, void *buffer,
                       size_t length) {
    unsigned char *output = buffer;
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, tid,
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

static int write_remote(pid_t tid, uint64_t address, const void *buffer,
                        size_t length) {
    const unsigned char *input = buffer;
    for (size_t offset = 0; offset < length; offset += sizeof(long)) {
        long word = 0;
        size_t remaining = length - offset;
        size_t amount = remaining < sizeof(word) ? remaining : sizeof(word);
        if (amount != sizeof(word)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, tid,
                          (void *)(uintptr_t)(address + offset), NULL);
            if (errno != 0) {
                return -1;
            }
        }
        memcpy(&word, input + offset, amount);
        if (ptrace(PTRACE_POKEDATA, tid,
                   (void *)(uintptr_t)(address + offset), (void *)word) != 0) {
            return -1;
        }
    }
    return 0;
}

static size_t build_marker_stub(unsigned char *stub, uint64_t marker_address) {
    size_t cursor = 0;
    uint64_t marker = THREAD_DEMO_MARKER;

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

static int seize_and_stop_all(const struct tracee_list *list,
                              size_t *seized_count) {
    *seized_count = 0;
    for (size_t index = 0; index < list->count; ++index) {
        if (ptrace(PTRACE_SEIZE, list->tids[index], NULL,
                   (void *)(uintptr_t)PTRACE_O_EXITKILL) != 0) {
            return -1;
        }
        ++*seized_count;
    }
    for (size_t index = 0; index < list->count; ++index) {
        if (ptrace(PTRACE_INTERRUPT, list->tids[index], NULL, NULL) != 0) {
            return -1;
        }
    }
    for (size_t index = 0; index < list->count; ++index) {
        int status = 0;
        if (waitpid(list->tids[index], &status, __WALL) < 0 ||
            !WIFSTOPPED(status)) {
            return -1;
        }
    }
    return 0;
}

static int detach_all(const struct tracee_list *list) {
    int result = 0;
    for (size_t index = 0; index < list->count; ++index) {
        if (ptrace(PTRACE_DETACH, list->tids[index], NULL, NULL) != 0) {
            result = -1;
        }
    }
    return result;
}

static int signal_workers(const struct thread_demo_ready *ready) {
    for (size_t index = 0; index < THREAD_DEMO_WORKERS; ++index) {
        if (syscall(SYS_tgkill, ready->process_id,
                    ready->worker_tids[index], SIGUSR1) != 0) {
            return -1;
        }
    }
    return 0;
}

static int run_demo(const char *victim_program) {
    struct thread_demo_ready ready;
    int status_fd = -1;
    pid_t child = spawn_victim(victim_program, &status_fd, &ready);
    if (child < 0) {
        return EXIT_FAILURE;
    }

    struct tracee_list tracees;
    if (enumerate_threads(child, &tracees) != 0 ||
        tracees.count != THREAD_DEMO_WORKERS + 1U ||
        !list_contains(&tracees, ready.selected_tid)) {
        fprintf(stderr, "[-] Thread enumeration did not match the victim\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    printf("[*] Enumerated %zu TIDs; selected worker is %d\n",
           tracees.count, ready.selected_tid);

    size_t seized_count = 0;
    errno = 0;
    if (seize_and_stop_all(&tracees, &seized_count) != 0) {
        int seize_error = errno;
        fprintf(stderr, "seize thread group: %s\n", strerror(seize_error));
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return seized_count == 0 &&
                       (seize_error == EPERM || seize_error == EACCES)
                   ? 77
                   : EXIT_FAILURE;
    }
    puts("[+] Every thread entered a ptrace stop");

    pid_t selected = ready.selected_tid;
    struct user_regs_struct saved_registers;
    unsigned char saved_patch[THREAD_DEMO_PATCH_SIZE];
    uint64_t saved_marker = 0;
    if (ptrace(PTRACE_GETREGS, selected, NULL, &saved_registers) != 0 ||
        read_remote(selected, ready.patch_address, saved_patch,
                    sizeof(saved_patch)) != 0 ||
        read_remote(selected, ready.marker_address, &saved_marker,
                    sizeof(saved_marker)) != 0 ||
        saved_marker != 0) {
        perror("save selected thread state");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }

    unsigned char stub[THREAD_DEMO_PATCH_SIZE];
    memset(stub, 0x90, sizeof(stub));
    size_t stub_length = build_marker_stub(stub, ready.marker_address);
    struct user_regs_struct redirected = saved_registers;
    redirected.rip = ready.patch_address;
    redirected.orig_rax = (uint64_t)-1;
    if (stub_length > sizeof(stub) ||
        write_remote(selected, ready.patch_address, stub, sizeof(stub)) != 0 ||
        ptrace(PTRACE_SETREGS, selected, NULL, &redirected) != 0 ||
        ptrace(PTRACE_CONT, selected, NULL, NULL) != 0) {
        perror("redirect selected thread");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }

    int selected_status = 0;
    pid_t waited = waitpid(selected, &selected_status, __WALL);
    if (waited < 0 ||
        !WIFSTOPPED(selected_status) ||
        WSTOPSIG(selected_status) != SIGTRAP) {
        fprintf(stderr,
                "[-] Selected worker did not stop through INT3 "
                "(waited=%d status=%d signal=%d error=%s)\n",
                waited, selected_status,
                WIFSTOPPED(selected_status) ? WSTOPSIG(selected_status) : -1,
                waited < 0 ? strerror(errno) : "none");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }

    uint64_t observed_marker = 0;
    if (read_remote(selected, ready.marker_address, &observed_marker,
                    sizeof(observed_marker)) != 0 ||
        observed_marker != THREAD_DEMO_MARKER) {
        fprintf(stderr, "[-] Selected worker did not execute the marker stub\n");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }
    printf("[+] Only selected TID %d executed the marker stub\n", selected);

    if (write_remote(selected, ready.patch_address, saved_patch,
                     sizeof(saved_patch)) != 0 ||
        write_remote(selected, ready.marker_address, &saved_marker,
                     sizeof(saved_marker)) != 0 ||
        ptrace(PTRACE_SETREGS, selected, NULL, &saved_registers) != 0) {
        perror("restore selected thread state");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }

    unsigned char patch_check[THREAD_DEMO_PATCH_SIZE];
    uint64_t marker_check = UINT64_MAX;
    struct user_regs_struct register_check;
    if (read_remote(selected, ready.patch_address, patch_check,
                    sizeof(patch_check)) != 0 ||
        read_remote(selected, ready.marker_address, &marker_check,
                    sizeof(marker_check)) != 0 ||
        ptrace(PTRACE_GETREGS, selected, NULL, &register_check) != 0 ||
        memcmp(patch_check, saved_patch, sizeof(saved_patch)) != 0 ||
        marker_check != 0 ||
        !registers_match(&register_check, &saved_registers)) {
        fprintf(stderr, "[-] Selected thread restoration verification failed\n");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }

    if (detach_all(&tracees) != 0) {
        perror("detach thread group");
        close(status_fd);
        terminate_traced_child(child, &tracees, seized_count);
        return EXIT_FAILURE;
    }
    puts("[+] Restored selected state and detached every TID");

    if (signal_workers(&ready) != 0) {
        perror("signal worker threads");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    unsigned char marker = 0;
    if (read_exact(status_fd, &marker, sizeof(marker)) != 0 || marker != 'R') {
        fprintf(stderr, "[-] Selected worker did not acknowledge resume\n");
        close(status_fd);
        terminate_child(child);
        return EXIT_FAILURE;
    }
    close(status_fd);

    int process_status = 0;
    if (waitpid(child, &process_status, 0) < 0 ||
        !WIFEXITED(process_status) || WEXITSTATUS(process_status) != 0) {
        fprintf(stderr, "[-] Restored thread group did not exit cleanly\n");
        terminate_child(child);
        return EXIT_FAILURE;
    }
    puts("[+] All workers resumed and the process exited normally");
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
