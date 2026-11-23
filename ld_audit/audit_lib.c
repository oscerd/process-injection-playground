#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

static size_t text_length(const char *text) {
    size_t length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

static void log_message(const char *message) {
    size_t length = text_length(message);
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(STDERR_FILENO, message + written,
                               length - written);
        if (result <= 0) {
            return;
        }
        written += (size_t)result;
    }
}

static int is_puts(const char *symbol_name) {
    return symbol_name[0] == 'p' && symbol_name[1] == 'u' &&
           symbol_name[2] == 't' && symbol_name[3] == 's' &&
           symbol_name[4] == '\0';
}

unsigned int la_version(unsigned int version) {
    (void)version;
    log_message("[LD_AUDIT] audit interface active\n");
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t namespace_id,
                        uintptr_t *cookie) {
    (void)map;
    (void)namespace_id;
    (void)cookie;
    log_message("[LD_AUDIT] object opened\n");
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

uintptr_t la_symbind64(Elf64_Sym *symbol, unsigned int symbol_index,
                       uintptr_t *reference_cookie,
                       uintptr_t *definition_cookie, unsigned int *flags,
                       const char *symbol_name) {
    (void)symbol_index;
    (void)reference_cookie;
    (void)definition_cookie;
    (void)flags;

    if (is_puts(symbol_name)) {
        log_message("[LD_AUDIT] puts binding observed\n");
    }
    return symbol->st_value;
}
