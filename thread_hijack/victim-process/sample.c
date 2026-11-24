#include "../demo_protocol.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The thread hijack lab currently supports x86_64 only"
#endif

static pthread_mutex_t ready_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_condition = PTHREAD_COND_INITIALIZER;
static int32_t worker_tids[THREAD_DEMO_WORKERS];
static volatile uint64_t demo_marker;
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t selected_tid;
static int status_fd = -1;

__attribute__((naked, noinline, used, aligned(64)))
static void remote_patch_slot(void) {
    __asm__ volatile(
        ".rept 64\n\t"
        "nop\n\t"
        ".endr\n\t"
        "ret\n\t");
}

static int write_all(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int parse_status_fd(void) {
    const char *text = getenv(THREAD_DEMO_STATUS_FD);
    if (text == NULL) {
        return -1;
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 ||
        value > INT32_MAX) {
        return -1;
    }
    return (int)value;
}

static uintptr_t function_address(void (*function)(void)) {
    uintptr_t address = 0;
    _Static_assert(sizeof(address) == sizeof(function),
                   "function pointers do not fit in uintptr_t");
    memcpy(&address, &function, sizeof(address));
    return address;
}

static void resume_worker(int signal_number) {
    (void)signal_number;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    running = 0;
    if (tid == selected_tid) {
        const unsigned char marker = 'R';
        ssize_t ignored = write(status_fd, &marker, sizeof(marker));
        (void)ignored;
    }
}

static void *worker_main(void *argument) {
    size_t index = *(const size_t *)argument;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    if (pthread_mutex_lock(&ready_lock) != 0) {
        return NULL;
    }
    worker_tids[index] = tid;
    pthread_cond_signal(&ready_condition);
    pthread_mutex_unlock(&ready_lock);

    while (running != 0) {
        pause();
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    status_fd = parse_status_fd();
    if (status_fd < 0) {
        fprintf(stderr, "Run this victim through injector --spawn\n");
        return EXIT_FAILURE;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = resume_worker;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    pthread_t workers[THREAD_DEMO_WORKERS];
    size_t indices[THREAD_DEMO_WORKERS];
    for (size_t index = 0; index < THREAD_DEMO_WORKERS; ++index) {
        indices[index] = index;
        if (pthread_create(&workers[index], NULL, worker_main,
                           &indices[index]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return EXIT_FAILURE;
        }
    }

    if (pthread_mutex_lock(&ready_lock) != 0) {
        return EXIT_FAILURE;
    }
    for (;;) {
        size_t ready_count = 0;
        for (size_t index = 0; index < THREAD_DEMO_WORKERS; ++index) {
            if (worker_tids[index] != 0) {
                ++ready_count;
            }
        }
        if (ready_count == THREAD_DEMO_WORKERS) {
            break;
        }
        pthread_cond_wait(&ready_condition, &ready_lock);
    }
    selected_tid = worker_tids[0];
    pthread_mutex_unlock(&ready_lock);

    void (*slot)(void) = remote_patch_slot;
    struct thread_demo_ready ready = {
        .magic = THREAD_DEMO_MAGIC,
        .patch_address = function_address(slot),
        .marker_address = (uintptr_t)&demo_marker,
        .process_id = getpid(),
        .selected_tid = selected_tid,
    };
    memcpy(ready.worker_tids, worker_tids, sizeof(worker_tids));
    if (write_all(status_fd, &ready, sizeof(ready)) != 0) {
        perror("announce readiness");
        return EXIT_FAILURE;
    }

    printf("Victim PID %d published selected worker TID %d\n",
           ready.process_id, ready.selected_tid);
    for (size_t index = 0; index < THREAD_DEMO_WORKERS; ++index) {
        pthread_join(workers[index], NULL);
    }

    close(status_fd);
    if (demo_marker != 0) {
        fprintf(stderr, "Thread marker was not restored\n");
        return EXIT_FAILURE;
    }
    puts("All workers resumed after thread-scoped state restoration");
    return EXIT_SUCCESS;
}
