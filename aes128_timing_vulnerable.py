"""
AES-128 Vulnerable Implementation - Timing Side-Channel Attack Demo
====================================================================
Educational/Research Use Only

This file contains:
1. A timing-VULNERABLE AES-128 implementation (uses non-constant-time operations)
2. A timing-SECURE AES-128 implementation (for comparison)
3. A timing attack harness that demonstrates key byte recovery

The vulnerability: The vulnerable implementation uses early-exit comparisons
and data-dependent branches during the SubBytes step (S-box lookup simulation),
causing measurable timing differences that leak information about the key.

Real-world context: True AES hardware/software timing attacks target:
- Cache-timing attacks (T-Table / Lookup Table implementations)
- Memory access patterns in S-box lookups
- Branch mispredictions based on key/plaintext XOR values

This demo simulates these effects with artificial but realistic timing variance.
"""

import time
import os
import struct
import statistics
import random
from collections import defaultdict


# ---------------------------------------------------------------------------
# AES Constants
# ---------------------------------------------------------------------------

# AES S-Box (SubBytes substitution table)
SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

# AES MixColumns GF(2^8) multiplication tables
XTIME = [((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF for x in range(256)]

# Round constants for key schedule
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


# ---------------------------------------------------------------------------
# AES Core Operations (shared between vulnerable and secure)
# ---------------------------------------------------------------------------

def sub_word(word):
    return [SBOX[b] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]

def key_expansion(key: bytes) -> list:
    """AES-128 key schedule — produces 11 round keys (each 16 bytes)."""
    assert len(key) == 16
    w = [list(key[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = xor_words(sub_word(rot_word(temp)), [RCON[i//4 - 1], 0, 0, 0])
        w.append(xor_words(w[i-4], temp))
    round_keys = []
    for r in range(11):
        rk = []
        for col in range(4):
            rk.extend(w[r*4 + col])
        round_keys.append(rk)
    return round_keys

def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]

def sub_bytes(state):
    return [SBOX[b] for b in state]

def shift_rows(state):
    # AES state is column-major: index = col*4 + row
    # ShiftRows: row r is cyclically shifted left by r positions
    s = state[:]
    # Row 0 (indices 0,4,8,12):  no shift
    # Row 1 (indices 1,5,9,13):  shift left 1 → [5,9,13,1]
    s[1], s[5], s[9],  s[13] = state[5], state[9],  state[13], state[1]
    # Row 2 (indices 2,6,10,14): shift left 2 → [10,14,2,6]
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    # Row 3 (indices 3,7,11,15): shift left 3 → [15,3,7,11]
    s[3], s[7], s[11], s[15] = state[15], state[3],  state[7], state[11]
    return s

def mix_columns(state):
    result = [0]*16
    for col in range(4):
        s0 = state[col*4]
        s1 = state[col*4+1]
        s2 = state[col*4+2]
        s3 = state[col*4+3]
        result[col*4]   = XTIME[s0] ^ XTIME[s1] ^ s1 ^ s2 ^ s3
        result[col*4+1] = s0 ^ XTIME[s1] ^ XTIME[s2] ^ s2 ^ s3
        result[col*4+2] = s0 ^ s1 ^ XTIME[s2] ^ XTIME[s3] ^ s3
        result[col*4+3] = XTIME[s0] ^ s0 ^ s1 ^ s2 ^ XTIME[s3]
    return result


# ---------------------------------------------------------------------------
# VULNERABLE AES-128 Encryption
# ---------------------------------------------------------------------------
# Vulnerability: The S-box lookup is wrapped in a function that performs
# data-dependent early exits and conditional branches. This simulates the
# cache-timing vulnerability found in T-Table implementations where:
#   - Certain S-box output values cause cache evictions
#   - High-bit S-box outputs cause branch mispredictions
#   - The timing difference is ~nanoseconds in real HW, amplified here for demo

def vulnerable_sbox_lookup(byte_val: int) -> int:
    """
    VULNERABLE: Simulates a non-constant-time S-box lookup.
    
    Injects artificial timing variance proportional to the Hamming weight
    of SBOX[byte_val], mimicking cache-timing effects in real T-Table AES.
    In a real attack, this timing leaks information about (plaintext XOR key).
    """
    result = SBOX[byte_val]
    
    # Simulate cache miss: high Hamming weight outputs are "slower"
    # (In real cache attacks, certain memory rows cause evictions)
    hamming = bin(result).count('1')
    if hamming > 4:
        # Simulate slower path — data-dependent delay
        # In real hardware: this is a cache miss adding ~100-200 cycles
        spin = hamming * hamming  # quadratic to amplify signal
        acc = 0
        for _ in range(spin):
            acc ^= result  # prevent optimization
    
    # Additional branch: high-bit outputs simulate a separate code path
    if result & 0x80:
        dummy = result ^ 0xFF  # extra operation on "slow path"
        _ = dummy
    
    return result


def aes128_encrypt_vulnerable(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-128 encryption — VULNERABLE to timing side-channel attacks.
    Uses non-constant-time S-box lookups in every SubBytes operation.
    """
    assert len(plaintext) == 16 and len(key) == 16
    
    round_keys = key_expansion(key)
    state = list(plaintext)
    
    # Initial round key addition
    state = add_round_key(state, round_keys[0])
    
    # 9 full rounds
    for r in range(1, 10):
        # VULNERABLE SubBytes
        state = [vulnerable_sbox_lookup(b) for b in state]
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    
    # Final round (no MixColumns)
    state = [vulnerable_sbox_lookup(b) for b in state]
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return bytes(state)


# ---------------------------------------------------------------------------
# Timing Oracle: Single-byte leakage model
# ---------------------------------------------------------------------------
# In real cache-timing attacks (Bernstein 2005, Osvik et al. 2006),
# the attack targets ONE specific cache line that is accessed based on
# a specific byte's value. This gives a much cleaner signal.
#
# We model this with a "timing oracle" function that returns the full
# encryption time, but the internal delay depends strongly on one byte position.

def aes128_encrypt_timing_oracle(plaintext: bytes, key: bytes, leak_byte_pos: int = 0) -> tuple[bytes, int]:
    """
    AES-128 encryption that returns (ciphertext, simulated_timing_ns).
    
    The timing leaks information about SBOX[plaintext[leak_byte_pos] XOR key[leak_byte_pos]]
    This models a cache-timing attack where one S-box cache line access pattern
    is measurable from outside (e.g., via Flush+Reload or Prime+Probe).
    
    Returns:
        (ciphertext_bytes, timing_nanoseconds)
    """
    assert len(plaintext) == 16 and len(key) == 16
    
    round_keys = key_expansion(key)
    state = list(plaintext)
    state = add_round_key(state, round_keys[0])
    
    # Compute the leaking byte: SBOX[pt[pos] XOR k[pos]]
    # This is the first-round SubBytes output for the target byte
    leak_input = plaintext[leak_byte_pos] ^ key[leak_byte_pos]
    leak_sbox_out = SBOX[leak_input]
    leak_hw = bin(leak_sbox_out).count('1')
    
    for r in range(1, 10):
        state = [SBOX[b] for b in state]
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    
    state = [SBOX[b] for b in state]
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    ct = bytes(state)
    
    # Simulated timing: base + noise + leak signal
    # The leak is the dominant signal (~30% of variance)
    base_ns = 50_000
    noise_ns = random.gauss(0, 800)              # CPU jitter
    leak_ns  = (leak_hw - 4) * 400              # data-dependent component
    timing   = int(base_ns + noise_ns + leak_ns)
    
    return ct, timing


# ---------------------------------------------------------------------------
# SECURE AES-128 Encryption (constant-time reference)
# ---------------------------------------------------------------------------

def aes128_encrypt_secure(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-128 encryption — constant-time implementation.
    Uses direct array indexing with no data-dependent branches.
    """
    assert len(plaintext) == 16 and len(key) == 16
    
    round_keys = key_expansion(key)
    state = list(plaintext)
    
    state = add_round_key(state, round_keys[0])
    
    for r in range(1, 10):
        state = sub_bytes(state)   # direct SBOX[] — no branches
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return bytes(state)


# ---------------------------------------------------------------------------
# Timing Attack Implementation
# ---------------------------------------------------------------------------
# Attack model: Last-round key recovery (most common AES timing attack)
#
# Theory:
#   In AES, the last round is: SubBytes → ShiftRows → AddRoundKey
#   If we can guess the last round key byte k[i], we can compute:
#       intermediate = SBOX_inv(ciphertext[i] XOR k[i])  ← last round output
#   The timing of the encryption correlates with Hamming weight of SBOX outputs
#   during the last SubBytes call. By correlating timing with HW(SBOX[pt XOR k_guess]),
#   we can identify the correct key guess.

def measure_encryption_time(plaintext: bytes, key: bytes, samples: int = 3) -> float:
    """Measure median encryption time to reduce noise."""
    times = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        aes128_encrypt_vulnerable(plaintext, key)
        end = time.perf_counter_ns()
        times.append(end - start)
    return statistics.median(times)


def timing_attack_recover_key_byte(
    target_key: bytes,
    byte_index: int,
    num_plaintexts: int = 500,
    verbose: bool = True
) -> tuple[int, dict]:
    """
    Recover one byte of the AES-128 key using the timing oracle.
    
    Attack strategy: Correlation Timing Analysis (CTA / CPA)
    - Query the timing oracle with many random plaintexts
    - For each key guess (0-255), compute predicted Hamming weight of SBOX[pt[i] XOR guess]
    - Correlate predicted HW with observed simulated timing
    - The guess with highest correlation is the correct key byte
    
    This models the Bernstein (2005) cache-timing attack on AES.
    
    Args:
        target_key:      The actual AES key (oracle uses this internally)
        byte_index:      Which key byte to recover (0-15)
        num_plaintexts:  Number of random plaintexts to query
        verbose:         Print progress
    
    Returns:
        (recovered_byte, scores_dict)
    """
    if verbose:
        print(f"\n[*] Attacking key byte index {byte_index} "
              f"(true value: 0x{target_key[byte_index]:02X})")
        print(f"[*] Querying timing oracle with {num_plaintexts} plaintexts...")
    
    # Step 1: Collect timing oracle measurements
    plaintexts = []
    timings = []
    
    for i in range(num_plaintexts):
        pt = os.urandom(16)
        _ct, t = aes128_encrypt_timing_oracle(pt, target_key, leak_byte_pos=byte_index)
        plaintexts.append(pt)
        timings.append(t)
        
        if verbose and (i+1) % 100 == 0:
            print(f"    Queried {i+1}/{num_plaintexts} oracle calls...")
    
    # Normalize timings
    t_mean = statistics.mean(timings)
    t_std  = statistics.stdev(timings) or 1
    timings_norm = [(t - t_mean) / t_std for t in timings]
    
    # Step 2: Correlation attack over all 256 key byte guesses
    if verbose:
        print(f"[*] Running Pearson correlation over 256 key byte candidates...")
    
    scores = {}
    
    for guess in range(256):
        # For each plaintext, compute predicted Hamming weight
        # of SBOX[plaintext[byte_index] XOR guess]
        predicted_hw = []
        for pt in plaintexts:
            intermediate = pt[byte_index] ^ guess
            sbox_out = SBOX[intermediate]
            hw = bin(sbox_out).count('1')
            predicted_hw.append(hw)
        
        # Pearson correlation between predicted HW and measured timing
        hw_mean = statistics.mean(predicted_hw)
        hw_std  = statistics.stdev(predicted_hw) or 1
        hw_norm = [(h - hw_mean) / hw_std for h in predicted_hw]
        
        correlation = sum(h * t for h, t in zip(hw_norm, timings_norm)) / len(timings_norm)
        scores[guess] = correlation
    
    # Step 3: Find the highest-scoring guess
    best_guess = max(scores, key=lambda g: scores[g])
    
    if verbose:
        true_byte = target_key[byte_index]
        print(f"[+] Best guess:  0x{best_guess:02X} (correlation: {scores[best_guess]:.4f})")
        print(f"[+] True value:  0x{true_byte:02X} (correlation: {scores[true_byte]:.4f})")
        correct = best_guess == true_byte
        rank = sorted(scores.values(), reverse=True).index(scores[true_byte]) + 1
        print(f"[+] Correct:     {'YES ✓' if correct else 'NO ✗'}  (true key rank: {rank}/256)")
    
    return best_guess, scores


def timing_attack_full_key(
    target_key: bytes,
    num_plaintexts: int = 500,
) -> bytes:
    """
    Attempt to recover all 16 bytes of an AES-128 key via timing analysis.
    
    Each byte is attacked independently (divide-and-conquer).
    Total complexity: 16 × 256 = 4096 guesses (vs 2^128 brute force).
    """
    print("=" * 60)
    print("  AES-128 TIMING SIDE-CHANNEL ATTACK")
    print("  Full Key Recovery Demo")
    print("=" * 60)
    print(f"  Target key: {target_key.hex()}")
    print(f"  Plaintexts per byte: {num_plaintexts}")
    print("=" * 60)
    
    recovered = []
    correct_count = 0
    
    for byte_idx in range(16):
        guess, scores = timing_attack_recover_key_byte(
            target_key, byte_idx,
            num_plaintexts=num_plaintexts,
            verbose=True
        )
        recovered.append(guess)
        if guess == target_key[byte_idx]:
            correct_count += 1
    
    recovered_key = bytes(recovered)
    
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  True key:      {target_key.hex()}")
    print(f"  Recovered key: {recovered_key.hex()}")
    print(f"  Bytes correct: {correct_count}/16")
    
    match = recovered_key == target_key
    print(f"  Full key match: {'YES — attack succeeded!' if match else 'NO — partial recovery'}")
    print("=" * 60)
    
    return recovered_key


def demo_timing_difference():
    """
    Demonstrate that timing oracle signal is measurable and correlated
    with the Hamming weight of SBOX[pt[i] XOR key[i]].
    """
    print("\n" + "=" * 60)
    print("  TIMING ORACLE SIGNAL DEMONSTRATION")
    print("=" * 60)
    
    key = os.urandom(16)
    n = 500
    
    # Group oracle timings by Hamming weight of SBOX output for byte 0
    hw_groups = {hw: [] for hw in range(9)}
    
    for _ in range(n):
        pt = os.urandom(16)
        _ct, t = aes128_encrypt_timing_oracle(pt, key, leak_byte_pos=0)
        leak_input = pt[0] ^ key[0]
        sbox_out = SBOX[leak_input]
        hw = bin(sbox_out).count('1')
        hw_groups[hw].append(t)
    
    print(f"\n  Oracle timing grouped by HW(SBOX[pt[0] XOR key[0]]):")
    print(f"  {'HW':>4}  {'Count':>6}  {'Mean timing (ns)':>17}  {'StdDev':>8}")
    print(f"  {'-'*44}")
    for hw in range(9):
        grp = hw_groups[hw]
        if grp:
            print(f"  {hw:>4}  {len(grp):>6}  {statistics.mean(grp):>17.0f}  "
                  f"{(statistics.stdev(grp) if len(grp)>1 else 0):>8.0f}")
    
    all_times = [t for g in hw_groups.values() for t in g]
    print(f"\n  Overall std: {statistics.stdev(all_times):.0f} ns")
    print("  Monotonically increasing mean vs HW = exploitable timing leak!")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\nAES-128 Timing Side-Channel Attack — Educational Demo")
    print("=" * 60)
    
    # Correctness check against NIST FIPS-197 Appendix B
    test_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    test_pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    
    ct_vuln   = aes128_encrypt_vulnerable(test_pt, test_key)
    ct_secure = aes128_encrypt_secure(test_pt, test_key)
    
    print(f"\nCorrectness check (NIST FIPS-197 Appendix B):")
    print(f"  Expected:         {expected.hex()}")
    print(f"  Vulnerable impl:  {ct_vuln.hex()}  {'✓' if ct_vuln == expected else '✗'}")
    print(f"  Secure impl:      {ct_secure.hex()}  {'✓' if ct_secure == expected else '✗'}")
    
    # Demo 1: Show timing oracle leakage signal
    demo_timing_difference()
    
    # Demo 2: Attack a single key byte via correlation timing analysis
    print("\n\n--- Single Byte Attack Demo (Correlation Timing Analysis) ---")
    secret_key = os.urandom(16)
    print(f"Secret key: {secret_key.hex()}")
    guess, scores = timing_attack_recover_key_byte(
        secret_key,
        byte_index=0,
        num_plaintexts=500,
        verbose=True
    )
    
    # Demo 3: Full key recovery — uncomment to run all 16 bytes
    # print("\n\n--- Full Key Recovery ---")
    # recovered = timing_attack_full_key(secret_key, num_plaintexts=500)
    
    print("\n[!] To run full key recovery, uncomment the Demo 3 block above.")
    print("[!] Runtime: ~30s for all 16 bytes.\n")
