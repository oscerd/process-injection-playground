#ifndef VDSO_HIJACK_DEMO_PROTOCOL_H
#define VDSO_HIJACK_DEMO_PROTOCOL_H

#include <stdint.h>

#define VDSO_DEMO_MAGIC UINT64_C(0x5644534f44454d4f)
#define VDSO_DEMO_STATUS_FD "VDSO_DEMO_STATUS_FD"
#define VDSO_DEMO_PATCH_SIZE 8U
#define VDSO_DEMO_RETURN_MARKER 42

struct vdso_demo_ready {
    uint64_t magic;
    uint64_t symbol_address;
    uint64_t result_address;
};

struct vdso_demo_results {
    int patched_result;
    int restored_result;
};

#endif
