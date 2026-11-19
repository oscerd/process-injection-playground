#include <stdio.h>

__attribute__((constructor)) static void on_load(void) {
    fputs("[MEMFD_DEMO] Constructor executed from a memory-backed mapping\n",
          stderr);
}

int demo_entry(void) {
    puts("[MEMFD_DEMO] Exported function executed");
    return 42;
}
