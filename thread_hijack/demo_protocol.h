#ifndef THREAD_HIJACK_DEMO_PROTOCOL_H
#define THREAD_HIJACK_DEMO_PROTOCOL_H

#include <stdint.h>

#define THREAD_DEMO_MAGIC UINT64_C(0x5448524541444445)
#define THREAD_DEMO_MARKER UINT64_C(0x5448524541443432)
#define THREAD_DEMO_STATUS_FD "THREAD_HIJACK_STATUS_FD"
#define THREAD_DEMO_WORKERS 3U
#define THREAD_DEMO_PATCH_SIZE 32U

struct thread_demo_ready {
    uint64_t magic;
    uint64_t patch_address;
    uint64_t marker_address;
    int32_t process_id;
    int32_t selected_tid;
    int32_t worker_tids[THREAD_DEMO_WORKERS];
};

#endif
