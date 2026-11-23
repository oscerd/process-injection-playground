#ifndef PROC_MEM_DEMO_PROTOCOL_H
#define PROC_MEM_DEMO_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PROC_MEM_DEMO_MAGIC UINT64_C(0x50524f434d454d31)
#define PROC_MEM_DEMO_MARKER UINT64_C(0x70726f636d656d31)
#define PROC_MEM_MAX_WRITE_SIZE 16
#define PROC_MEM_EXPECT_DENIED UINT32_C(0x00000001)

struct proc_mem_request {
    uint64_t magic;
    uintptr_t remote_address;
    size_t length;
    uint32_t flags;
    uint32_t reserved;
    unsigned char value[PROC_MEM_MAX_WRITE_SIZE];
};

#endif
