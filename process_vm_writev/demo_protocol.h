#ifndef PROCESS_VM_WRITEV_DEMO_PROTOCOL_H
#define PROCESS_VM_WRITEV_DEMO_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PIP_DEMO_MAGIC UINT64_C(0x50495044454d4f31)
#define PIP_DEMO_MARKER UINT64_C(0xc0defacecafebeef)
#define PIP_MAX_WRITE_SIZE 16
#define PIP_EXPECT_DENIED UINT32_C(0x00000001)
#define PIP_EXPECT_ERROR UINT32_C(0x00000002)

struct pip_demo_request {
    uint64_t magic;
    uintptr_t remote_address;
    size_t length;
    uint32_t flags;
    uint32_t expected_errno;
    unsigned char value[PIP_MAX_WRITE_SIZE];
};

#endif
