// Linux/glibc-only diagnostic preload. Not part of the production binary.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/syscall.h>
#include <malloc.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/sock_diag.h>
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
static int budget_on_pressure;
static int under_pressure;
static int controlled[4096];
static unsigned queued[4096];
static _Atomic unsigned long sampled_socket_memory;
static _Atomic unsigned pressure_entries;
static int actual_configured[4096];
static _Atomic unsigned active_requests;
static unsigned reserved_requests;
static double below_since;
static _Atomic unsigned long resize_calls;

static double monotonic_seconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}
static unsigned rounded_requests(unsigned count) {
    unsigned step = 1;
    for (unsigned n = count; n > 16; n >>= 1) step <<= 1;
    return (count + step - 1) / step * step;
}
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
        unsigned divisor = budget_active_requests ? reserved_requests : socket_count;
        unsigned long allowance = divisor ? receive_budget / (2 * divisor) : 16384;
        if (allowance < 16384) allowance = 16384;
        if (allowance > 64 * 1024 * 1024) allowance = 64 * 1024 * 1024;
        for (unsigned i = 0; i < socket_count; ++i) {
            int bytes = (int)allowance;
            if (budget_on_pressure) {
                if (!under_pressure) {
                    if (!controlled[i]) { total += actual_configured[i]; continue; }
                    bytes = 64 * 1024 * 1024;
                    controlled[i] = 0;
                } else {
                    if (!controlled[i] && queued[i] <= 2 * allowance) {
                        total += actual_configured[i];
                        continue;
                    }
                    controlled[i] = 1;
                }
            }
            if (configured[i] == bytes) {
                total += actual_configured[i];
                continue;
            }
            if (setsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes))) _exit(115);
            configured[i] = bytes;
            atomic_fetch_add(&resize_calls, 1);
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

// Tighten immediately when request concurrency rises; only expand after
// lower concurrency persists for 100 ms. Short request turnover must not cause
// an O(socket_count) series of setsockopt calls at every completion.
static void update_active_budget(int allow_expand) {
    unsigned wanted = rounded_requests(atomic_load(&active_requests));
    if (wanted > reserved_requests) {
        reserved_requests = wanted;
        below_since = 0;
        rebudget();
    } else if (wanted < reserved_requests) {
        double now = monotonic_seconds();
        if (!below_since) below_since = now;
        if (allow_expand && now - below_since >= .1) {
            reserved_requests = wanted;
            below_since = 0;
            rebudget();
        }
    } else {
        below_since = 0;
    }
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
    update_active_budget(0);
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
            controlled[i] = controlled[socket_count];
            queued[i] = queued[socket_count];
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

// Read actual receive allocations, rather than treating a large advertised
// window as allocated memory. This experiment polls only its own TCP sockets.
static void sample_pressure(void) {
    unsigned long total = 0;
    for (unsigned i = 0; i < socket_count; ++i) {
        unsigned info[SK_MEMINFO_VARS] = {0};
        socklen_t length = sizeof(info);
        if (getsockopt(sockets[i], SOL_SOCKET, SO_MEMINFO, info, &length)) _exit(122);
        queued[i] = info[SK_MEMINFO_RMEM_ALLOC];
        actual_configured[i] = info[SK_MEMINFO_RCVBUF];
        total += queued[i];
    }
    atomic_store(&sampled_socket_memory, total);
    if (!under_pressure && total > receive_budget) {
        under_pressure = 1;
        atomic_fetch_add(&pressure_entries, 1);
    } else if (under_pressure && total < receive_budget / 4) {
        under_pressure = 0;
    }
    rebudget();
}

static void *sample_heap(void *unused) {
    (void)unused;
    FILE *out = fopen("/output/.allocator.csv", "w");
    if (!out) _exit(110);
    fprintf(out, "seconds,arena,uordblks,fordblks,hblkhd,connections,initial_rcvbuf,rtt_us,current_rcvbuf,tracked_sockets,configured_total,active_requests,window_clamp,rcv_ssthresh,resize_calls,sampled_socket_memory,pressure_entries\n");
    struct timespec start, now, interval = {.tv_nsec = budget_on_pressure ? 10000000 : 100000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < (budget_on_pressure ? 60000 : 6000); ++i) {
        if (receive_budget && budget_active_requests) {
            pthread_mutex_lock(&sockets_lock);
            update_active_budget(1);
            if (budget_on_pressure) sample_pressure();
            pthread_mutex_unlock(&sockets_lock);
        }
        if (budget_on_pressure && i % 10) {
            nanosleep(&interval, NULL);
            continue;
        }
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
        fprintf(out, "%.6f,%zu,%zu,%zu,%zu,%u,%d,%u,%d,%u,%lu,%u,%d,%u,%lu,%lu,%u\n", elapsed,
                m.arena, m.uordblks, m.fordblks, m.hblkhd,
                atomic_load(&connections), atomic_load(&observed_receive_bytes),
                info.tcpi_rtt, current_receive, atomic_load(&tracked_sockets),
                atomic_load(&configured_total), atomic_load(&active_requests), clamp, info.tcpi_rcv_ssthresh, atomic_load(&resize_calls),
                atomic_load(&sampled_socket_memory), atomic_load(&pressure_entries));
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
    value = getenv("SYQ_SPIKE_ON_PRESSURE");
    budget_on_pressure = value && atoi(value);
    if (budget_on_pressure && (!budget_active_requests || !budget_window_clamp)) _exit(123);
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
        int initial = receive_budget && !budget_on_pressure ? 64 * 1024 * 1024 : receive_bytes;
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
        controlled[socket_count] = 0;
        queued[socket_count] = 0;
        int actual = 0;
        socklen_t size = sizeof(actual);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &size)) _exit(114);
        actual_configured[socket_count] = actual;
        sockets[socket_count++] = fd;
        rebudget();
        pthread_mutex_unlock(&sockets_lock);
    }
    errno = saved_errno;
    return result;
}

__attribute__((destructor)) static void check_request_balance(void) {
    if (receive_budget && budget_active_requests && atomic_load(&active_requests)) _exit(121);
}
