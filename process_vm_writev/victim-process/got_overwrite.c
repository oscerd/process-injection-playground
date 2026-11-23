#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../demo_protocol.h"

typedef int (*puts_fn)(const char *);

extern Elf64_Dyn _DYNAMIC[];

static volatile sig_atomic_t write_attempt_finished;

static void handle_write_attempt(int signal_number) {
    (void)signal_number;
    write_attempt_finished = 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, (const char *)buffer + written,
                               length - written);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        written += (size_t)result;
    }

    return 0;
}

static uintptr_t find_plt_slot(const char *wanted_symbol) {
    const char *string_table = NULL;
    const Elf64_Sym *symbol_table = NULL;
    const Elf64_Rela *relocations = NULL;
    size_t relocation_size = 0;
    Elf64_Sxword relocation_type = DT_NULL;

    for (const Elf64_Dyn *entry = _DYNAMIC; entry->d_tag != DT_NULL; ++entry) {
        switch (entry->d_tag) {
        case DT_STRTAB:
            string_table = (const char *)(uintptr_t)entry->d_un.d_ptr;
            break;
        case DT_SYMTAB:
            symbol_table = (const Elf64_Sym *)(uintptr_t)entry->d_un.d_ptr;
            break;
        case DT_JMPREL:
            relocations = (const Elf64_Rela *)(uintptr_t)entry->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            relocation_size = (size_t)entry->d_un.d_val;
            break;
        case DT_PLTREL:
            relocation_type = entry->d_un.d_val;
            break;
        default:
            break;
        }
    }

    if (string_table == NULL || symbol_table == NULL || relocations == NULL ||
        relocation_size == 0 || relocation_type != DT_RELA) {
        return 0;
    }

    size_t relocation_count = relocation_size / sizeof(*relocations);
    for (size_t index = 0; index < relocation_count; ++index) {
        size_t symbol_index = ELF64_R_SYM(relocations[index].r_info);
        const char *symbol_name = string_table + symbol_table[symbol_index].st_name;
        if (strcmp(symbol_name, wanted_symbol) == 0) {
            return (uintptr_t)relocations[index].r_offset;
        }
    }

    return 0;
}

static int redirected_puts(const char *ignored) {
    (void)ignored;
    static const char message[] =
        "[GOT REDIRECTED] Existing benign callback executed\n";
    if (write_exact(STDOUT_FILENO, message, sizeof(message) - 1) != 0) {
        return EOF;
    }
    return 0;
}

__attribute__((noinline)) static int call_puts(const char *text) {
    return puts(text);
}

int main(void) {
    _Static_assert(sizeof(puts_fn) <= PIP_MAX_WRITE_SIZE,
                   "function pointer does not fit the demo protocol");
    _Static_assert(sizeof(puts_fn) <= sizeof(uintptr_t),
                   "function pointer representation is unsupported");
    setvbuf(stdout, NULL, _IONBF, 0);

    struct sigaction action = {
        .sa_handler = handle_write_attempt,
    };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    if (call_puts("[NORMAL] Resolving the original puts binding") == EOF) {
        return EXIT_FAILURE;
    }

    uintptr_t got_slot = find_plt_slot("puts");
    if (got_slot == 0) {
        fprintf(stderr, "Could not locate the puts jump slot\n");
        return EXIT_FAILURE;
    }

    puts_fn replacement = redirected_puts;
#ifdef FULL_RELRO
    uintptr_t original_binding = *(volatile uintptr_t *)got_slot;
#else
    uintptr_t replacement_bits = 0;
    memcpy(&replacement_bits, &replacement, sizeof(replacement));
#endif

    const char *request_fd_text = getenv("PIP_REQUEST_FD");
    if (request_fd_text == NULL) {
        fprintf(stderr, "Run this victim through inject --spawn\n");
        return EXIT_FAILURE;
    }

    char *end = NULL;
    long request_fd = strtol(request_fd_text, &end, 10);
    struct pip_demo_request request = {
        .magic = PIP_DEMO_MAGIC,
        .remote_address = got_slot,
        .length = sizeof(replacement),
#ifdef FULL_RELRO
        .flags = PIP_EXPECT_ERROR,
        .expected_errno = EFAULT,
#endif
    };
    memcpy(request.value, &replacement, sizeof(replacement));

    if (end == request_fd_text || *end != '\0' || request_fd < 0 ||
        write_exact((int)request_fd, &request, sizeof(request)) != 0) {
        perror("announce GOT overwrite request");
        return EXIT_FAILURE;
    }
    close((int)request_fd);

    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        uintptr_t observed = *(volatile uintptr_t *)got_slot;
#ifdef FULL_RELRO
        if (observed != original_binding) {
            fprintf(stderr, "Full RELRO jump slot was unexpectedly modified\n");
            return EXIT_FAILURE;
        }
        if (write_attempt_finished != 0) {
            static const char message[] =
                "[FULL RELRO] puts jump slot remained unchanged\n";
            return write_exact(STDOUT_FILENO, message, sizeof(message) - 1) == 0
                       ? EXIT_SUCCESS
                       : EXIT_FAILURE;
        }
#else
        if (observed == replacement_bits) {
            return call_puts("trigger redirected puts binding") == EOF
                       ? EXIT_FAILURE
                       : EXIT_SUCCESS;
        }
#endif
        nanosleep(&interval, NULL);
    }

    fprintf(stderr, "Timed out waiting for the GOT experiment\n");
    return EXIT_FAILURE;
}
