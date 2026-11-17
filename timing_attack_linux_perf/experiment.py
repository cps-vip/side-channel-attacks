"""Run a local password-checking experiment with Linux perf CPU cycles."""

import argparse
from contextlib import closing
import csv
import ctypes
import os
from pathlib import Path
import random
import secrets
from statistics import median
import string
import sys


ALPHABET = string.ascii_lowercase + string.digits
FILLER = "!"
CSV_COLUMNS = (
    "checker", "position", "round", "candidate", "guess", "comparisons",
    "cycles", "enabled_ns", "running_ns", "core_type",
)

# Hybrid Intel CPUs expose two PMUs with different microarchitectures. Pinning to
# a single CPU keeps every measurement on one of them; these let us name and
# verify which, so cycle counts are never silently mixed across core types.
HYBRID_CPU_LISTS = {
    "performance": "/sys/devices/cpu_core/cpus",
    "efficiency": "/sys/devices/cpu_atom/cpus",
}
PMU_NAMES = {"performance": "cpu_core", "efficiency": "cpu_atom"}


def parse_cpu_list(text):
    """Turn a sysfs CPU list such as '0-15' or '16,18-20' into a set of ints."""
    cpus = set()
    for part in text.strip().split(","):
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-")
            cpus.update(range(int(low), int(high) + 1))
        else:
            cpus.add(int(part))
    return cpus


def hybrid_core_sets():
    """Map each core type to its CPUs, or return {} on a non-hybrid machine."""
    core_sets = {}
    for core_type, path in HYBRID_CPU_LISTS.items():
        try:
            core_sets[core_type] = parse_cpu_list(Path(path).read_text())
        except OSError:
            return {}
    return core_sets


def classify_cpu(cpu, core_sets):
    """Name the core type a CPU belongs to, or None if it is not listed."""
    for core_type, cpus in core_sets.items():
        if cpu in cpus:
            return core_type
    return None


class CycleReading(ctypes.Structure):
    _fields_ = [
        ("cycles", ctypes.c_uint64),
        ("enabled_ns", ctypes.c_uint64),
        ("running_ns", ctypes.c_uint64),
    ]


class CycleCounter:
    def __init__(self, secret, writer, core_type):
        library_path = Path(__file__).with_name("libchecker.so").resolve()
        native = ctypes.CDLL(str(library_path), use_errno=True)
        guess_and_secret = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ]
        self.checkers = {"early": native.check_early_exit, "fixed": native.check_fixed_work}
        for check in self.checkers.values():
            check.argtypes = guess_and_secret
            check.restype = ctypes.c_int

        self.measure_batch = native.measure_batch
        self.measure_batch.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint,
            *guess_and_secret, ctypes.POINTER(CycleReading),
        ]
        self.measure_batch.restype = ctypes.c_int
        native.open_cycle_counter.argtypes = []
        native.open_cycle_counter.restype = ctypes.c_int
        self.fd = native.open_cycle_counter()
        if self.fd < 0:
            reason = os.strerror(ctypes.get_errno())
            raise OSError(f"Could not open perf cycles:u ({reason}). Try perf stat -e cycles:u -- true.")

        self.secret = secret.encode("ascii")
        self.writer = writer
        self.core_type = core_type
        self.previous = CycleReading()
        self.queries = 0

    def close(self):
        os.close(self.fd)

    def sample(self, checker, guess, comparisons, position, round_number, candidate):
        guess_bytes = guess.encode("ascii")
        current = CycleReading()
        result = self.measure_batch(
            self.fd, int(checker == "fixed"), comparisons,
            guess_bytes, len(guess_bytes), self.secret, len(self.secret),
            ctypes.byref(current),
        )
        if result != 0:
            reason = os.strerror(ctypes.get_errno())
            raise OSError(f"Could not measure the batch with perf ({reason}).")

        # perf returns cumulative totals. Subtract the previous batch's reading.
        cycles = current.cycles - self.previous.cycles
        enabled = current.enabled_ns - self.previous.enabled_ns
        running = current.running_ns - self.previous.running_ns
        self.previous = current
        self.queries += comparisons
        self.writer.writerow([
            checker, position, round_number, candidate, guess, comparisons,
            cycles, enabled, running, self.core_type,
        ])
        if cycles <= 0 or running <= 0 or running != enabled:
            raise RuntimeError(
                "perf did not count for the whole batch. See the last CSV row "
                f"(enabled {enabled} ns, running {running} ns, cycles {cycles})."
            )
        return cycles

    def verify(self, checker, guess):
        guess_bytes = guess.encode("ascii")
        self.queries += 1
        return bool(self.checkers[checker](
            guess_bytes, len(guess_bytes), self.secret, len(self.secret),
        ))


def measure_rounds(counter, checker, guesses, position, args, rng):
    samples = {candidate: [] for candidate in guesses}
    order = list(guesses)
    for round_number in range(1, args.rounds + 1):
        # Every candidate gets one batch per round, in a fresh order.
        rng.shuffle(order)
        for candidate in order:
            cycles = counter.sample(
                checker, guesses[candidate], args.batch, position, round_number, candidate,
            )
            samples[candidate].append(cycles)
    return samples


def diagnose(counter, checker, secret, args, rng):
    # Use the known secret to vary just the length of the matching prefix.
    guesses = {n: secret[:n] + FILLER * (len(secret) - n) for n in range(len(secret))}
    samples = measure_rounds(counter, checker, guesses, "", args, rng)
    print("Matching bytes | Median cycles per batch | Median change vs. 0")
    for prefix, cycles in samples.items():
        change = median(value - baseline for value, baseline in zip(cycles, samples[0]))
        print(f"{prefix:14} | {median(cycles):23.1f} | {change:+19.1f}")


def recover(counter, checker, length, args, rng):
    prefix = ""
    for position in range(length - 1):
        padding = FILLER * (length - position - 1)
        guesses = {char: prefix + char + padding for char in ALPHABET}
        samples = measure_rounds(counter, checker, guesses, position, args, rng)
        ranking = sorted(ALPHABET, key=lambda char: median(samples[char]), reverse=True)
        winner, runner_up = ranking[:2]
        gap = median(samples[winner]) - median(samples[runner_up])
        prefix += winner
        print(f"Byte {position + 1}: {winner!r}, median lead {gap:.1f} cycles per batch")

    # A final-byte match and mismatch both reach the same comparison.
    # Try the whole alphabet to give both checkers the same query budget.
    accepted = [prefix + char for char in ALPHABET if counter.verify(checker, prefix + char)]
    if accepted:
        print(f"Recovered and verified {accepted[0]!r}.")
    else:
        print(f"No match after trying every final byte for prefix {prefix!r}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("diagnose", "recover"))
    parser.add_argument("--checker", choices=("early", "fixed", "both"), default="both")
    parser.add_argument("--secret", help="synthetic lab secret using a-z and 0-9")
    parser.add_argument("--rounds", type=int, default=100, help="batches per candidate")
    parser.add_argument("--batch", type=int, default=1000, help="comparisons per batch")
    parser.add_argument("--cpu", type=int, help="CPU to pin to (default: first allowed CPU)")
    parser.add_argument(
        "--core-type", choices=("performance", "efficiency"),
        help="on a hybrid P-core/E-core CPU, pick a default CPU of this type",
    )
    parser.add_argument("--seed", type=int, default=42, help="seed for candidate order")
    parser.add_argument("--output", type=Path, help="new CSV path (default: MODE.csv)")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        parser.error("the perf counter requires Linux")
    if args.rounds < 1 or not 1 <= args.batch <= 1_000_000:
        parser.error("use positive rounds and a batch size between 1 and 1,000,000")

    secret = args.secret
    if secret is None:
        secret = "a7b2k9" if args.mode == "diagnose" else "".join(
            secrets.choice(ALPHABET) for _ in range(4)
        )
    if not 2 <= len(secret) <= 64 or any(char not in ALPHABET for char in secret):
        parser.error("use a lab secret of 2 to 64 lowercase letters or digits")

    allowed_cpus = os.sched_getaffinity(0)
    core_sets = hybrid_core_sets()
    if args.core_type is not None and not core_sets:
        parser.error("this machine has no P-core/E-core split, so --core-type does not apply")

    if args.cpu is not None:
        cpu = args.cpu
    elif args.core_type is not None:
        candidates = sorted(core_sets[args.core_type] & allowed_cpus)
        if not candidates:
            parser.error(f"no allowed {args.core_type} CPU is available")
        cpu = candidates[0]
    else:
        # Standardize on performance cores on hybrid CPUs; fall back to the
        # lowest allowed CPU on a non-hybrid machine.
        performance = core_sets.get("performance", set()) & allowed_cpus
        cpu = min(performance) if performance else min(allowed_cpus)

    if cpu not in allowed_cpus:
        parser.error(f"CPU {cpu} is outside the allowed affinity mask")

    # Keep every run on a single, named core type so cycle counts stay comparable.
    if core_sets:
        core_type = classify_cpu(cpu, core_sets)
        if core_type is None:
            parser.error(
                f"CPU {cpu} is not listed under cpu_core or cpu_atom, so its core type "
                "cannot be confirmed; pass --core-type or a CPU from those lists"
            )
        if args.core_type is not None and core_type != args.core_type:
            parser.error(
                f"CPU {cpu} is a {core_type} core but --core-type {args.core_type} was "
                "requested; pick a CPU of that type or drop --cpu"
            )
    else:
        core_type = "standard"
    pmu = PMU_NAMES.get(core_type, "cpu")

    checkers = ("early", "fixed") if args.checker == "both" else (args.checker,)
    output = args.output if args.output is not None else Path(f"{args.mode}.csv")
    try:
        os.sched_setaffinity(0, {cpu})
        with output.open("x", newline="", encoding="utf-8") as raw:
            writer = csv.writer(raw)
            writer.writerow(CSV_COLUMNS)
            with closing(CycleCounter(secret, writer, core_type)) as counter:
                print(
                    f"CPU {cpu} ({core_type} core, PMU {pmu}), {args.rounds} rounds, "
                    f"{args.batch} comparisons per batch"
                )
                for checker in checkers:
                    print(f"\n{checker} checker")
                    start = counter.queries
                    rng = random.Random(args.seed)
                    if args.mode == "diagnose":
                        diagnose(counter, checker, secret, args, rng)
                    else:
                        recover(counter, checker, len(secret), args, rng)
                    print(f"Total checker calls: {counter.queries - start:,}")
    except (OSError, RuntimeError) as error:
        print(f"Experiment stopped: {error}", file=sys.stderr)
        return 1

    print(f"\nLab secret: {secret!r}")
    print(f"Batch measurements: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
