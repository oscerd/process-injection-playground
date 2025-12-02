/*
 * Malicious Shared Library
 *
 * This library will be injected into a running process via dlopen.
 * It demonstrates what malicious code can do once loaded.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>

/*
 * This constructor runs automatically when the library is loaded
 */
__attribute__((constructor))
static void on_load(void) {
    pid_t pid = getpid();
    uid_t uid = getuid();
    time_t now = time(NULL);

    fprintf(stderr, "\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  MALICIOUS LIBRARY LOADED!\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "  PID:  %d\n", pid);
    fprintf(stderr, "  UID:  %d\n", uid);
    fprintf(stderr, "  Time: %s", ctime(&now));
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "\n");

    /*
     * In a real attack, this is where malicious code would run:
     * - Establish persistence
     * - Exfiltrate data
     * - Install backdoor
     * - Privilege escalation
     * - Network communication
     * - Keylogging
     * - etc.
     */

    fprintf(stderr, "[MALICIOUS] I could do anything now:\n");
    fprintf(stderr, "[MALICIOUS]   - Steal credentials\n");
    fprintf(stderr, "[MALICIOUS]   - Exfiltrate data\n");
    fprintf(stderr, "[MALICIOUS]   - Install backdoor\n");
    fprintf(stderr, "[MALICIOUS]   - Escalate privileges\n");
    fprintf(stderr, "[MALICIOUS]   - Hook sensitive functions\n");
    fprintf(stderr, "\n");
}

/*
 * Destructor runs when the library is unloaded
 */
__attribute__((destructor))
static void on_unload(void) {
    fprintf(stderr, "[MALICIOUS] Library unloading (this rarely happens in an injection)\n");
}

/*
 * Example of function hooking - hijack printf
 */
int printf(const char *format, ...) {
    static int (*real_printf)(const char*, ...) = NULL;

    /* Get the real printf on first call */
    if (!real_printf) {
        real_printf = dlsym(RTLD_NEXT, "printf");
    }

    /* Add our prefix */
    real_printf("[HIJACKED] ");

    /* Call original printf */
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);

    return ret;
}

/*
 * Public function that can be called from the injector
 */
void malicious_function(void) {
    fprintf(stderr, "[MALICIOUS] malicious_function() called!\n");
}
