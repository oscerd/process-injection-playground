#include "demo_protocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void announce_load(void) {
    const char *text = getenv(REMOTE_DEMO_MARKER_FD);
    if (text == NULL) {
        return;
    }

    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 ||
        value > INT32_MAX) {
        return;
    }

    const unsigned char marker = 'L';
    ssize_t ignored = write((int)value, &marker, sizeof(marker));
    (void)ignored;
}
