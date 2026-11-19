#ifndef PROCESS_VM_WRITEV_DEMO_PROTOCOL_H
#define PROCESS_VM_WRITEV_DEMO_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PIP_DEMO_MAGIC UINT64_C(0x50495044454d4f31)
#define PIP_DEMO_MARKER UINT64_C(0xc0defacecafebeef)
#define PIP_MAX_WRITE_SIZE 16

struct pip_demo_request {
    uint64_t magic;
    uintptr_t remote_address;
    size_t length;
    unsigned char value[PIP_MAX_WRITE_SIZE];
};

#endif
