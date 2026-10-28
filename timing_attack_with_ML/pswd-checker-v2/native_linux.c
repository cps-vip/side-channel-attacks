/* Local x86-64 lab: real early-exit comparisons, no amplification workload. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <x86intrin.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "This backend requires Linux x86-64"
#endif

#define EXPORT __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))

static volatile unsigned char secret_bytes[16];
static size_t secret_length;
static volatile unsigned int sink;
static cpu_set_t original_affinity;
static int restore_affinity, initialized;

typedef struct {
    double wall_ns;
    uint64_t tsc_ticks;
    uint64_t thread_cpu_ns;
    unsigned int aux_start, aux_end;
} Measurement;

EXPORT int lab_close(void) {
    /* Keep the saved mask on failure, so a caller can retry restoration. */
    if (restore_affinity && sched_setaffinity(0, sizeof(original_affinity), &original_affinity))
        return 5;
    restore_affinity = 0;
    initialized = 0;
    secret_length = 0;
    return 0;
}

EXPORT int lab_init(const unsigned char *secret, size_t n, unsigned int work, int cpu) {
    unsigned int a, b, c, d;
    struct timespec probe;
    if (initialized) return 9;
    if (!secret || n < 4 || n > 16) return 1;
    if (work) return 8;
    for (size_t i = 0; i < n; ++i)
        if (!((secret[i] >= 'a' && secret[i] <= 'z') ||
              (secret[i] >= '0' && secret[i] <= '9'))) return 6;
    if (__get_cpuid_max(0x80000000U, NULL) < 0x80000007U) return 2;
    __cpuid(0x80000001U, a, b, c, d);
    if (!(d & (1U << 27))) return 2;
    __cpuid(0x80000007U, a, b, c, d);
    if (!(d & (1U << 8))) return 3;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &probe) ||
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &probe)) return 4;
    if (cpu < -1 || cpu >= CPU_SETSIZE) return 5;
    if (cpu >= 0) {
        cpu_set_t target;
        if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) ||
            !CPU_ISSET(cpu, &original_affinity)) return 5;
        CPU_ZERO(&target);
        CPU_SET(cpu, &target);
        if (sched_setaffinity(0, sizeof(target), &target)) return 5;
        restore_affinity = 1;
    }
    for (size_t i = 0; i < n; ++i) secret_bytes[i] = secret[i];
    secret_length = n;
    initialized = 1;
    return 0;
}

static NOINLINE int vulnerable(const unsigned char *guess, size_t n) {
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; ++i)
        if (guess[i] != secret_bytes[i]) return 0;
    return 1;
}

static NOINLINE int fixed_work(const unsigned char *guess, size_t n) {
    unsigned int difference = 0;
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; ++i) difference |= guess[i] ^ secret_bytes[i];
    return difference == 0;
}

static NOINLINE int empty_check(const unsigned char *guess, size_t n) {
    (void)guess;
    /* Compiler barrier keeps baseline calls; it executes no extra instructions. */
    __asm__ __volatile__("" ::: "memory");
    return (int)(n & 1);
}

EXPORT int lab_check(const unsigned char *guess, size_t n, int mode) {
    if (!initialized || !guess) return -1;
    switch (mode) {
        case 0: return vulnerable(guess, n);
        case 1: return fixed_work(guess, n);
        default: return -1;
    }
}

static uint64_t timestamp(unsigned int *aux) {
    __asm__ __volatile__("" ::: "memory");
    _mm_lfence();
    uint64_t value = __rdtscp(aux);
    _mm_lfence();
    __asm__ __volatile__("" ::: "memory");
    return value;
}

static uint64_t elapsed_ns(struct timespec start, struct timespec end) {
    return (uint64_t)((int64_t)(end.tv_sec - start.tv_sec) * INT64_C(1000000000)
                      + end.tv_nsec - start.tv_nsec);
}

EXPORT int lab_measure(const unsigned char *guess, size_t n, int mode,
                       unsigned int batch, Measurement *out) {
    struct timespec w0, w1, c0, c1;
    uint64_t t0, t1;
    unsigned int a0, a1, accumulator = 0;
    int (*checker)(const unsigned char *, size_t);
    if (!initialized || !guess || !out || !batch || batch > 1000000U) return 1;
    switch (mode) {
        case 0: checker = vulnerable; break;
        case 1: checker = fixed_work; break;
        case 2: checker = empty_check; break;
        default: return 4;
    }
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &w0) ||
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0)) return 2;
    t0 = timestamp(&a0);
    for (unsigned int i = 0; i < batch; ++i) accumulator += (unsigned int)checker(guess, n);
    t1 = timestamp(&a1);
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1) ||
        clock_gettime(CLOCK_MONOTONIC_RAW, &w1)) return 2;
    sink ^= accumulator;
    out->wall_ns = (double)elapsed_ns(w0, w1);
    out->tsc_ticks = t1 - t0;
    out->thread_cpu_ns = elapsed_ns(c0, c1);
    out->aux_start = a0;
    out->aux_end = a1;
    return 0;
}
