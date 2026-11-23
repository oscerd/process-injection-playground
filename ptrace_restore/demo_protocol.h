#ifndef PTRACE_RESTORE_DEMO_PROTOCOL_H
#define PTRACE_RESTORE_DEMO_PROTOCOL_H

#include <stdint.h>

#define RESTORE_DEMO_MAGIC UINT64_C(0x5253544f52453131)
#define RESTORE_DEMO_MARKER UINT64_C(0x524553544f524544)
#define RESTORE_DEMO_PATCH_SIZE 32U
#define RESTORE_DEMO_STATUS_FD "PTRACE_RESTORE_STATUS_FD"

struct restore_demo_ready {
    uint64_t magic;
    uint64_t patch_address;
    uint64_t marker_address;
};

#endif
