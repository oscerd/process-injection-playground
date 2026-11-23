#ifndef PTRACE_TRACEME_DEMO_PROTOCOL_H
#define PTRACE_TRACEME_DEMO_PROTOCOL_H

#include <stdint.h>

#define REDIRECT_MAGIC UINT64_C(0x54524143454d4531)

struct redirect_request {
    uint64_t magic;
    uintptr_t target_address;
};

#endif
