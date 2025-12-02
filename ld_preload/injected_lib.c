/*
 * LD_PRELOAD Process Injection Example
 *
 * This shared library demonstrates function interposition using LD_PRELOAD.
 * When preloaded, it hijacks common libc functions to execute custom code.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

/*
 * Constructor function - runs automatically when the library is loaded
 * This is executed before main() of the target process
 */
__attribute__((constructor))
static void init(void) {
    fprintf(stderr, "[INJECTED] Library loaded! PID: %d\n", getpid());
    fprintf(stderr, "[INJECTED] This code runs before main()\n");
}

/*
 * Destructor function - runs automatically when the library is unloaded
 */
__attribute__((destructor))
static void fini(void) {
    fprintf(stderr, "[INJECTED] Library unloaded!\n");
}

/*
 * Hijack the printf function
 * Intercepts all printf calls and adds a prefix
 */
int printf(const char *format, ...) {
    /* Get the original printf function */
    int (*original_printf)(const char*, ...) = dlsym(RTLD_NEXT, "printf");

    /* Call our injected code first */
    original_printf("[HIJACKED] ");

    /* Now call the original printf with the original arguments */
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);

    return result;
}

/*
 * Hijack the puts function
 * Intercepts all puts calls
 */
int puts(const char *s) {
    int (*original_puts)(const char*) = dlsym(RTLD_NEXT, "puts");
    original_puts("[HIJACKED] Library injected via LD_PRELOAD!");
    return original_puts(s);
}

/*
 * Hijack the write function
 * Demonstrates low-level syscall interception
 */
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*original_write)(int, const void*, size_t) = dlsym(RTLD_NEXT, "write");

    /* Log the write operation */
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        const char msg[] = "[INJECTED] Intercepted write() call\n";
        original_write(STDERR_FILENO, msg, sizeof(msg) - 1);
    }

    /* Call original write */
    return original_write(fd, buf, count);
}
