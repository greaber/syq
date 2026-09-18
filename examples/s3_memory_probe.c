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
static int configured[4096];
static int budget_active_requests;
static int budget_window_clamp;
static int actual_configured[4096];
static _Atomic unsigned active_requests;
static unsigned socket_count;
static _Atomic unsigned tracked_sockets;
static _Atomic unsigned long configured_total;

// Diagnostic Linux policy: split a configured receive-buffer budget between
// open connections. Linux doubles SO_RCVBUF, so divide the allowance by two.
// Optional request hooks change the divisor to active requests. Idle sockets
// then share the same allowance but cannot accumulate response payload. This
// remains a diagnostic policy, not a hard bound on all kernel memory.
static void rebudget(void) {
    unsigned long total = 0;
    if (socket_count) {
        unsigned count = budget_active_requests ? atomic_load(&active_requests) : socket_count;
        // Round concurrency upward by at most 12.5% to avoid touching every
        // socket for each request completion/replacement at high concurrency.
        unsigned step = 1;
        for (unsigned n = count; n > 16; n >>= 1) step <<= 1;
        unsigned divisor = (count + step - 1) / step * step;
        unsigned long allowance = divisor ? receive_budget / (2 * divisor) : 16384;
        if (allowance < 16384) allowance = 16384;
        if (allowance > 64 * 1024 * 1024) allowance = 64 * 1024 * 1024;
        int bytes = (int)allowance;
        for (unsigned i = 0; i < socket_count; ++i) {
            if (configured[i] == bytes) {
                total += actual_configured[i];
                continue;
            }
            if (setsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes))) _exit(115);
            configured[i] = bytes;
            int actual;
            socklen_t size = sizeof(actual);
            if (getsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &actual, &size)) _exit(116);
            actual_configured[i] = actual;
            if (budget_window_clamp && setsockopt(sockets[i], IPPROTO_TCP, TCP_WINDOW_CLAMP,
                                                   &actual, sizeof(actual))) _exit(120);
            total += actual;
        }
    }
    atomic_store(&tracked_sockets, socket_count);
    atomic_store(&configured_total, total);
}

// Called by an RAII guard in the Rust experiment, including cancellation/error
// paths. The guard starts before HTTP dispatch and ends after consuming the body.
void syq_spike_request_delta(int delta) {
    if (!receive_budget || !budget_active_requests) return;
    pthread_mutex_lock(&sockets_lock);
    unsigned current = atomic_load(&active_requests);
    if (delta == 1) ++current;
    else if (delta == -1 && current) --current;
    else _exit(119);
    atomic_store(&active_requests, current);
    rebudget();
    pthread_mutex_unlock(&sockets_lock);
}

int close(int fd) {
    // A direct syscall also works during loader setup, before our constructor.
    if (!receive_budget) return (int)syscall(SYS_close, fd);
    int saved_errno = errno;
    pthread_mutex_lock(&sockets_lock);
    for (unsigned i = 0; i < socket_count; ++i) {
        if (sockets[i] == fd) {
            sockets[i] = sockets[--socket_count];
            configured[i] = configured[socket_count];
            actual_configured[i] = actual_configured[socket_count];
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
    fprintf(out, "seconds,arena,uordblks,fordblks,hblkhd,connections,initial_rcvbuf,rtt_us,current_rcvbuf,tracked_sockets,configured_total,active_requests,window_clamp,rcv_ssthresh\n");
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
        int clamp = 0;
        socklen_t clamp_size = sizeof(clamp);
        if (getsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, &clamp_size)) clamp = 0;
        fprintf(out, "%.6f,%zu,%zu,%zu,%zu,%u,%d,%u,%d,%u,%lu,%u,%d,%u\n", elapsed,
                m.arena, m.uordblks, m.fordblks, m.hblkhd,
                atomic_load(&connections), atomic_load(&observed_receive_bytes),
                info.tcpi_rtt, current_receive, atomic_load(&tracked_sockets),
                atomic_load(&configured_total), atomic_load(&active_requests), clamp, info.tcpi_rcv_ssthresh);
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
    value = getenv("SYQ_SPIKE_BUDGET_ACTIVE");
    budget_active_requests = value && atoi(value);
    value = getenv("SYQ_SPIKE_WINDOW_CLAMP");
    budget_window_clamp = value && atoi(value);
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
        configured[socket_count] = 0;
        sockets[socket_count++] = fd;
        rebudget();
        pthread_mutex_unlock(&sockets_lock);
    }
    errno = saved_errno;
    return result;
}
