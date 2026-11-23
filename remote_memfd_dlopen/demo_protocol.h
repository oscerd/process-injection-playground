#ifndef REMOTE_MEMFD_DLOPEN_DEMO_PROTOCOL_H
#define REMOTE_MEMFD_DLOPEN_DEMO_PROTOCOL_H

#include <stdint.h>

#define REMOTE_DEMO_MAGIC UINT64_C(0x52444c4f50454e31)
#define REMOTE_DEMO_PATH_CAPACITY 256U
#define REMOTE_DEMO_STACK_SIZE (64U * 1024U)
#define REMOTE_DEMO_PATCH_SIZE 32U

#define REMOTE_DEMO_READY_FD "REMOTE_DLOPEN_READY_FD"
#define REMOTE_DEMO_MARKER_FD "REMOTE_DLOPEN_MARKER_FD"

struct remote_demo_ready {
    uint64_t magic;
    uint64_t patch_address;
    uint64_t path_address;
    uint64_t stack_address;
    uint64_t stack_size;
};

#endif
