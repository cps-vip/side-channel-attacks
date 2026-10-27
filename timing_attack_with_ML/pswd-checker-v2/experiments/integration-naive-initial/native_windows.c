/* Intentionally vulnerable local lab. Build for x64 MSVC, /O2, no LTCG. */
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static volatile unsigned char secret_bytes[256];
static size_t secret_length;
static unsigned int amplification;
static volatile unsigned int sink;
static LARGE_INTEGER frequency;
static DWORD_PTR old_affinity;
static unsigned char library_secret[16];
typedef struct TrieNode { struct TrieNode *children[36]; } TrieNode;
static TrieNode nodes[17];
static BCRYPT_ALG_HANDLE sha256;
static unsigned char component_digests[8][32];

static int symbol_index(unsigned char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '0' && c <= '9') return c - '0' + 26;
    return -1;
}

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
    memcpy(library_secret, secret, n);
    memset(nodes, 0, sizeof(nodes));
    for (size_t i = 0; i < n; ++i)
        nodes[i].children[symbol_index(secret[i])] = &nodes[i + 1];
    if (!sha256 && BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 7;
    for (size_t i = 0; i < n; i += 2) {
        ULONG width = (ULONG)(n - i < 2 ? n - i : 2);
        if (BCryptHash(sha256, NULL, 0, (PUCHAR)(secret + i), width,
                       component_digests[i / 2], 32) < 0) return 7;
    }
    return 0;
}

__declspec(dllexport) void lab_close(void) {
    if (sha256) { BCryptCloseAlgorithmProvider(sha256, 0); sha256 = NULL; }
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

__declspec(noinline) static int library_check(const unsigned char *guess, size_t n) {
    return n == secret_length && memcmp(guess, library_secret, n) == 0;
}

__declspec(noinline) static int trie_check(const unsigned char *guess, size_t n) {
    TrieNode *node = &nodes[0];
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; ++i) {
        int symbol = symbol_index(guess[i]);
        if (symbol < 0 || !(node = node->children[symbol])) return 0;
    }
    return node == &nodes[n];
}

/* Deliberately flawed architecture: independently hashed two-byte components.
   SHA-256 does real verification work; this is NOT a password storage scheme. */
__declspec(noinline) static int staged_check(const unsigned char *guess, size_t n) {
    unsigned char result[32];
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; i += 2) {
        ULONG width = (ULONG)(n - i < 2 ? n - i : 2);
        if (BCryptHash(sha256, NULL, 0, (PUCHAR)(guess + i), width, result, 32) < 0)
            return 0;
        if (memcmp(result, component_digests[i / 2], 32)) return 0;
    }
    return 1;
}

__declspec(noinline) static int staged_fixed(const unsigned char *guess, size_t n) {
    unsigned char result[32];
    unsigned int difference = 0;
    if (n != secret_length) return 0;
    for (size_t i = 0; i < n; i += 2) {
        ULONG width = (ULONG)(n - i < 2 ? n - i : 2);
        if (BCryptHash(sha256, NULL, 0, (PUCHAR)(guess + i), width, result, 32) < 0)
            return 0;
        for (size_t j = 0; j < 32; ++j) difference |= result[j] ^ component_digests[i / 2][j];
    }
    return difference == 0;
}

__declspec(dllexport) int lab_check(const unsigned char *guess, size_t n, int mode) {
    switch (mode) {
        case 0: return vulnerable(guess, n);
        case 1: return fixed_work(guess, n);
        case 3: return library_check(guess, n);
        case 4: return trie_check(guess, n);
        case 5: return staged_check(guess, n);
        case 6: return staged_fixed(guess, n);
        default: return 0;
    }
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
    int (*checker)(const unsigned char *, size_t);
    switch (mode) {
        case 0: checker = vulnerable; break;
        case 1: checker = fixed_work; break;
        case 2: checker = empty_check; break;
        case 3: checker = library_check; break;
        case 4: checker = trie_check; break;
        case 5: checker = staged_check; break;
        case 6: checker = staged_fixed; break;
        default: return 4;
    }
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
