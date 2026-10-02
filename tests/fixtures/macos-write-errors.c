// Interpose at the syscall boundary: unlike the generic error-injection hook,
// this fails only if syq actually asks the selected filesystem to flush.
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int is_destination(int fd) {
    char path[4096];
    const char *root = getenv("SYQ_TEST_FLUSH_DESTINATION");
    return root && fcntl(fd, F_GETPATH, path) == 0 &&
        strncmp(path, root, strlen(root)) == 0 && path[strlen(root)] == '/';
}

static int test_fstatfs(int fd, struct statfs *stats) {
    int result = fstatfs(fd, stats);
    if (result == 0 && is_destination(fd)) {
        const char *kind = getenv("SYQ_TEST_FLUSH_FILESYSTEM");
        if (kind) {
            strlcpy(stats->f_fstypename, kind, sizeof(stats->f_fstypename));
        }
        const char *log = getenv("SYQ_TEST_FLUSH_PROBES");
        if (log) {
            int output = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (output >= 0) {
                (void)write(output, "probe\n", 6);
                close(output);
            }
        }
    }
    return result;
}

static int test_fsync(int fd) {
    if (is_destination(fd)) {
        errno = ENOSPC;
        return -1;
    }
    return fsync(fd);
}

// Calls made inside this library still resolve to the original implementation.
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } hooks[] = {
    { (const void *)test_fstatfs, (const void *)fstatfs },
    { (const void *)test_fsync, (const void *)fsync },
};
