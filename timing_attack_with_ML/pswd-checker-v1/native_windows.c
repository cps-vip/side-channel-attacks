/* Intentionally vulnerable local lab. Build for x64 MSVC, /O2, no LTCG. */
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

static volatile unsigned char secret_bytes[256];
static size_t secret_length;
static unsigned int amplification;
static volatile unsigned int sink;
static LARGE_INTEGER frequency;
static DWORD_PTR old_affinity;

typedef struct {
    double wall_ns;
    uint64_t tsc_ticks;
    uint64_t thread_cycles;
    unsigned int aux_start;
    unsigned int aux_end;
} Measurement;

__declspec(dllexport) int lab_init(const unsigned char *secret, size_t n,
                                  unsigned int work, int cpu) {
    int regs[4];
    if (n < 4 || n > 16) return 1;
    for (size_t i = 0; i < n; ++i) {
        if (!((secret[i] >= 'a' && secret[i] <= 'z') ||
              (secret[i] >= '0' && secret[i] <= '9'))) return 6;
    }
    __cpuid(regs, (int)0x80000000);
    if ((unsigned int)regs[0] < 0x80000007U) return 2;
    __cpuid(regs, (int)0x80000001);
    if (!(regs[3] & (1 << 27))) return 2; /* RDTSCP */
    __cpuid(regs, (int)0x80000007);
    if (!(regs[3] & (1 << 8))) return 3; /* invariant TSC */
    if (!QueryPerformanceFrequency(&frequency)) return 4;
    if (cpu >= 0) {
        DWORD_PTR process_mask, system_mask, target;
        if (cpu >= (int)(8 * sizeof(DWORD_PTR))) return 5;
        target = ((DWORD_PTR)1) << cpu;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask)
            || !(process_mask & target)) return 5;
        old_affinity = SetThreadAffinityMask(GetCurrentThread(), target);
        if (!old_affinity) return 5;
    }
    for (size_t i = 0; i < n; ++i) secret_bytes[i] = secret[i];
    secret_length = n;
    amplification = work;
    return 0;
}

__declspec(dllexport) void lab_close(void) {
    if (old_affinity) {
        SetThreadAffinityMask(GetCurrentThread(), old_affinity);
        old_affinity = 0;
    }
}

__declspec(noinline) static int vulnerable(const unsigned char *guess, size_t n) {
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; ++i) {
        if (guess[i] != secret_bytes[i]) return 0;
        /* Volatile operations preserve deliberate teaching amplification. */
        for (unsigned int j = 0; j < amplification; ++j) sink ^= j;
    }
    return 1;
}

__declspec(noinline) static int fixed_work(const unsigned char *guess, size_t n) {
    unsigned int difference = 0;
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; ++i) {
        difference |= guess[i] ^ secret_bytes[i];
        for (unsigned int j = 0; j < amplification; ++j) sink ^= j;
    }
    return difference == 0;
}

__declspec(dllexport) int lab_check(const unsigned char *guess, size_t n, int mode) {
    return mode ? fixed_work(guess, n) : vulnerable(guess, n);
}

static uint64_t timestamp(unsigned int *aux) {
    uint64_t value;
    _ReadWriteBarrier();
    _mm_lfence();
    value = __rdtscp(aux);
    _mm_lfence();
    _ReadWriteBarrier();
    return value;
}

/* mode 2 measures the loop/function-call baseline. Never subtract per sample. */
__declspec(noinline) static int empty_check(const unsigned char *guess, size_t n) {
    (void)guess;
    return (int)(n & 1);
}

__declspec(dllexport) int lab_measure(const unsigned char *guess, size_t n,
                                     int mode, unsigned int batch,
                                     Measurement *out) {
    LARGE_INTEGER q0, q1;
    ULONG64 c0, c1;
    uint64_t t0, t1;
    unsigned int a0, a1;
    int accumulator = 0;
    int (*checker)(const unsigned char *, size_t) =
        mode == 2 ? empty_check : mode ? fixed_work : vulnerable;
    if (!batch || !out) return 1;
    if (!QueryPerformanceCounter(&q0)) return 2;
    if (!QueryThreadCycleTime(GetCurrentThread(), &c0)) return 3;
    t0 = timestamp(&a0);
    for (unsigned int i = 0; i < batch; ++i) accumulator += checker(guess, n);
    t1 = timestamp(&a1);
    if (!QueryThreadCycleTime(GetCurrentThread(), &c1)) return 3;
    if (!QueryPerformanceCounter(&q1)) return 2;
    sink ^= (unsigned int)accumulator;
    out->wall_ns = (double)(q1.QuadPart-q0.QuadPart) * 1e9 / frequency.QuadPart;
    out->tsc_ticks = t1-t0;
    out->thread_cycles = c1-c0;
    out->aux_start = a0;
    out->aux_end = a1;
    return 0;
}
