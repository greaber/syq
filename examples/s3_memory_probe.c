// Linux/glibc-only diagnostic preload. Not part of the production binary.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int receive_bytes;
static _Atomic unsigned connections;
static _Atomic int observed_receive_bytes;

static void *sample_heap(void *unused) {
    (void)unused;
    FILE *out = fopen("/output/.allocator.csv", "w");
    if (!out) _exit(110);
    fprintf(out, "seconds,arena,uordblks,fordblks,hblkhd,connections,initial_rcvbuf\n");
    struct timespec start, now, interval = {.tv_nsec = 100000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 6000; ++i) {
        struct mallinfo2 m = mallinfo2();
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9;
        fprintf(out, "%.6f,%zu,%zu,%zu,%zu,%u,%d\n", elapsed,
                m.arena, m.uordblks, m.fordblks, m.hblkhd,
                atomic_load(&connections), atomic_load(&observed_receive_bytes));
        fflush(out);
        nanosleep(&interval, NULL);
    }
    fclose(out);
    return NULL;
}

__attribute__((constructor)) static void initialize(void) {
    real_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_connect) _exit(111);
    const char *value = getenv("SYQ_SPIKE_RCVBUF");
    receive_bytes = value ? atoi(value) : 0;
    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) || pthread_attr_setstacksize(&attr, 128 * 1024) ||
        pthread_create(&thread, &attr, sample_heap, NULL)) _exit(112);
    pthread_attr_destroy(&attr);
    pthread_detach(thread);
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (address && (address->sa_family == AF_INET || address->sa_family == AF_INET6)) {
        if (receive_bytes && setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                                       &receive_bytes, sizeof(receive_bytes))) _exit(113);
        int actual = 0;
        socklen_t size = sizeof(actual);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &size)) _exit(114);
        atomic_store(&observed_receive_bytes, actual);
        atomic_fetch_add(&connections, 1);
    }
    return real_connect(fd, address, length);
}
