// Linux/glibc-only diagnostic preload. Not part of the production binary.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/syscall.h>
#include <malloc.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int receive_bytes;
static unsigned long receive_budget;
static pthread_mutex_t sockets_lock = PTHREAD_MUTEX_INITIALIZER;
static int sockets[4096];
static unsigned socket_count;
static _Atomic unsigned tracked_sockets;
static _Atomic unsigned long configured_total;

// Diagnostic Linux policy: split a configured receive-buffer budget between
// open connections. Linux doubles SO_RCVBUF, so divide the allowance by two.
// Idle pooled connections still count; this is not an active-request policy.
static void rebudget(void) {
    unsigned long total = 0;
    if (socket_count) {
        unsigned long allowance = receive_budget / (2 * socket_count);
        if (allowance < 16384) allowance = 16384;
        if (allowance > 64 * 1024 * 1024) allowance = 64 * 1024 * 1024;
        int bytes = (int)allowance;
        for (unsigned i = 0; i < socket_count; ++i) {
            if (setsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes))) _exit(115);
            int actual;
            socklen_t size = sizeof(actual);
            if (getsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &actual, &size)) _exit(116);
            total += actual;
        }
    }
    atomic_store(&tracked_sockets, socket_count);
    atomic_store(&configured_total, total);
}

int close(int fd) {
    // A direct syscall also works during loader setup, before our constructor.
    if (!receive_budget) return (int)syscall(SYS_close, fd);
    int saved_errno = errno;
    pthread_mutex_lock(&sockets_lock);
    for (unsigned i = 0; i < socket_count; ++i) {
        if (sockets[i] == fd) {
            sockets[i] = sockets[--socket_count];
            rebudget();
            break;
        }
    }
    int result = (int)syscall(SYS_close, fd);
    int result_errno = errno;
    pthread_mutex_unlock(&sockets_lock);
    errno = result < 0 ? result_errno : saved_errno;
    return result;
}
static _Atomic unsigned connections;
static _Atomic int observed_receive_bytes;
static _Atomic int last_socket = -1;

static void *sample_heap(void *unused) {
    (void)unused;
    FILE *out = fopen("/output/.allocator.csv", "w");
    if (!out) _exit(110);
    fprintf(out, "seconds,arena,uordblks,fordblks,hblkhd,connections,initial_rcvbuf,rtt_us,current_rcvbuf,tracked_sockets,configured_total\n");
    struct timespec start, now, interval = {.tv_nsec = 100000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 6000; ++i) {
        struct mallinfo2 m = mallinfo2();
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9;
        struct tcp_info info = {0};
        socklen_t info_size = sizeof(info);
        int fd = atomic_load(&last_socket), current_receive = 0;
        socklen_t receive_size = sizeof(current_receive);
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_size)) info.tcpi_rtt = 0;
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &current_receive, &receive_size)) current_receive = 0;
        fprintf(out, "%.6f,%zu,%zu,%zu,%zu,%u,%d,%u,%d,%u,%lu\n", elapsed,
                m.arena, m.uordblks, m.fordblks, m.hblkhd,
                atomic_load(&connections), atomic_load(&observed_receive_bytes),
                info.tcpi_rtt, current_receive, atomic_load(&tracked_sockets),
                atomic_load(&configured_total));
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
    value = getenv("SYQ_SPIKE_RCVBUDGET");
    receive_budget = value ? strtoul(value, NULL, 10) : 0;
    if (receive_budget && receive_bytes) _exit(117);
    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) || pthread_attr_setstacksize(&attr, 128 * 1024) ||
        pthread_create(&thread, &attr, sample_heap, NULL)) _exit(112);
    pthread_attr_destroy(&attr);
    pthread_detach(thread);
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    int inet = address && (address->sa_family == AF_INET || address->sa_family == AF_INET6);
    if (inet) {
        // Negotiate window scaling for later growth before sending the SYN.
        int initial = receive_budget ? 64 * 1024 * 1024 : receive_bytes;
        if (initial && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &initial, sizeof(initial))) _exit(113);
        int actual = 0;
        socklen_t size = sizeof(actual);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &size)) _exit(114);
        atomic_store(&observed_receive_bytes, actual);
        atomic_fetch_add(&connections, 1);
        atomic_store(&last_socket, fd);
    }
    int result = real_connect(fd, address, length);
    int saved_errno = errno;
    if (inet && receive_budget && (result == 0 || saved_errno == EINPROGRESS)) {
        pthread_mutex_lock(&sockets_lock);
        if (socket_count == sizeof(sockets) / sizeof(sockets[0])) _exit(118);
        sockets[socket_count++] = fd;
        rebudget();
        pthread_mutex_unlock(&sockets_lock);
    }
    errno = saved_errno;
    return result;
}
