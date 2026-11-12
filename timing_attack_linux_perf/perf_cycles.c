#define _GNU_SOURCE
#include "checker.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Field order matches the kernel's read format below. */
struct cycle_reading {
    uint64_t cycles;
    uint64_t enabled_ns;
    uint64_t running_ns;
};

static volatile unsigned int check_results;

int open_cycle_counter(void)
{
    struct perf_event_attr event = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(event),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        .disabled = 1,
        .pinned = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    };

    /* Count user-space cycles for this thread only, like perf stat -e cycles:u. */
    return syscall(SYS_perf_event_open, &event, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
}

int measure_batch(int counter, int fixed_work, unsigned int batch_size,
                  const char *guess, size_t guess_length,
                  const char *secret, size_t secret_length,
                  struct cycle_reading *reading)
{
    password_check *check = fixed_work ? check_fixed_work : check_early_exit;
    unsigned int accepted = 0;

    if (ioctl(counter, PERF_EVENT_IOC_ENABLE, 0) == -1)
        return -1;

    /* The checker lives in a separate C file so the compiler keeps every call. */
    for (unsigned int i = 0; i < batch_size; i++)
        accepted += check(guess, guess_length, secret, secret_length);

    if (ioctl(counter, PERF_EVENT_IOC_DISABLE, 0) == -1)
        return -1;

    check_results = accepted;

    ssize_t bytes_read = read(counter, reading, sizeof(*reading));
    if (bytes_read == (ssize_t)sizeof(*reading))
        return 0;
    if (bytes_read >= 0)
        errno = EIO;
    return -1;
}
