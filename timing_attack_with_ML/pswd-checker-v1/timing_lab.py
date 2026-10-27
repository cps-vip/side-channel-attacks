"""Local, intentionally vulnerable timing lab. No network service or dependencies."""
import argparse
import csv
import gc
import hashlib
import hmac
import json
import os
import platform
import random
import statistics
import time
from pathlib import Path
from lab_config import DEFAULT_ALPHABET, validate_secret, validate_alphabet


def vulnerable_check(candidate, secret, work=0):
    if len(candidate) != len(secret):
        return False
    for actual, expected in zip(candidate, secret):
        if actual != expected:
            return False
        # Explicit teaching amplification; use --work 0 for the natural leak.
        value = 0
        for i in range(work):
            value ^= i
    return True


def constant_check(candidate, secret, work=0):
    # Fixed-length digests also avoid exposing input length through comparison.
    return hmac.compare_digest(hashlib.sha256(candidate).digest(),
                               hashlib.sha256(secret).digest())


def make_oracle(secret, mode, work):
    """Attack code receives this callable, never the secret itself."""
    validate_secret(secret)
    checker = vulnerable_check if mode == 'vulnerable' else constant_check
    return lambda candidate: checker(candidate, secret, work)


def measure(oracle, candidate, batch):
    wall = time.perf_counter_ns()
    cpu = time.thread_time_ns()
    for _ in range(batch):
        oracle(candidate)
    cpu = time.thread_time_ns() - cpu
    wall = time.perf_counter_ns() - wall
    return wall / batch, cpu / batch


def attack(oracle, alphabet, length, samples, batch, rng, writer):
    prefix = b''
    trace = []
    # A sentinel outside the alphabet prevents an accidental matching suffix.
    sentinel = next(bytes([i]) for i in range(256) if i not in alphabet)
    for position in range(length):
        candidates = {c: prefix + bytes([c]) + sentinel * (length-position-1)
                      for c in alphabet}
        timings = {c: [] for c in alphabet}
        for candidate in candidates.values():
            for _ in range(5):
                oracle(candidate)
        for sample in range(samples):
            order = list(alphabet)
            rng.shuffle(order)
            for c in order:
                wall, cpu = measure(oracle, candidates[c], batch)
                timings[c].append(wall)
                writer.writerow([position, sample, candidates[c].hex(), chr(c),
                                 wall, cpu])
        ranking = sorted(alphabet, key=lambda c: statistics.median(timings[c]),
                         reverse=True)
        scores = [{"character": chr(c),
                   "median_wall_ns": statistics.median(timings[c]),
                   "samples": len(timings[c])} for c in ranking]
        prefix += bytes([ranking[0]])
        trace.append({"position": position, "ranking": scores})
        print(f'Position {position}: chose {chr(ranking[0])!r}; '
              f'top medians {scores[0]["median_wall_ns"]:.0f} / '
              f'{scores[1]["median_wall_ns"]:.0f} ns')
    return prefix, trace


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['vulnerable', 'constant'], default='vulnerable')
    parser.add_argument('--secret', default='cabd', help='synthetic lab password only')
    parser.add_argument('--alphabet', default=DEFAULT_ALPHABET)
    parser.add_argument('--samples', type=positive, default=40)
    parser.add_argument('--batch', type=positive, default=10)
    parser.add_argument('--work', type=int, default=2000)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--cpu', type=int, help='Linux logical CPU affinity, when supported')
    parser.add_argument('--output', default='results')
    args = parser.parse_args()
    try:
        secret = args.secret.encode('ascii')
        alphabet = args.alphabet.encode('ascii')
    except UnicodeEncodeError:
        parser.error('use ASCII synthetic passwords and alphabet')
    try:
        validate_secret(secret)
        validate_alphabet(alphabet)
    except ValueError as error:
        parser.error(str(error))
    if any(c not in alphabet for c in secret) or args.work < 0:
        parser.error('secret must use the selected alphabet; work must be >= 0')
    if args.cpu is not None:
        if not hasattr(os, 'sched_setaffinity'):
            parser.error('--cpu requires OS support for sched_setaffinity')
        os.sched_setaffinity(0, {args.cpu})
    root = Path(__file__).resolve().parent
    output = (root / args.output).resolve()
    if not output.is_relative_to(root):
        parser.error('output must stay inside VIP')
    output.mkdir(parents=True, exist_ok=True)
    oracle = make_oracle(secret, args.mode, args.work)
    metadata = {
        'platform': platform.platform(), 'python': platform.python_version(),
        'mode': args.mode, 'work': args.work, 'samples': args.samples,
        'batch': args.batch, 'seed': args.seed, 'length': len(secret),
        'alphabet': args.alphabet, 'requested_cpu': args.cpu,
        'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
        'clock': vars(time.get_clock_info('perf_counter')),
        'measurement': 'nanoseconds per call; not hardware CPU cycles',
    }
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        with (output / 'measurements.csv').open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['position', 'sample', 'candidate_hex', 'tested_character',
                             'wall_ns_per_call', 'thread_cpu_ns_per_call'])
            guess, trace = attack(oracle, alphabet, len(secret), args.samples,
                                  args.batch, random.Random(args.seed), writer)
    finally:
        if was_enabled:
            gc.enable()
    metadata.update(guess=guess.decode('ascii'), success=oracle(guess), trace=trace)
    (output / 'summary.json').write_text(json.dumps(metadata, indent=2))
    print(f'Guess: {metadata["guess"]}; verified: {metadata["success"]}')
    print(f'Results: {output}')


if __name__ == '__main__':
    main()
