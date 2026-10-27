"""Python orchestrates; checker and timed batches execute entirely in C."""
import argparse
import ctypes as ct
import csv
import json
import platform
import random
import statistics
from pathlib import Path
from lab_config import DEFAULT_ALPHABET, validate_secret, validate_alphabet


class Measurement(ct.Structure):
    _fields_ = [('wall_ns', ct.c_double), ('tsc_ticks', ct.c_uint64),
                ('thread_cycles', ct.c_uint64), ('aux_start', ct.c_uint),
                ('aux_end', ct.c_uint)]


class NativeLab:
    def __init__(self, secret, work=0, cpu=-1):
        validate_secret(secret)
        self.dll = ct.CDLL(str(Path(__file__).with_name('native_windows.dll')))
        self.dll.lab_init.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_uint, ct.c_int]
        self.dll.lab_init.restype = ct.c_int
        self.dll.lab_check.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int]
        self.dll.lab_check.restype = ct.c_int
        self.dll.lab_measure.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int,
                                        ct.c_uint, ct.POINTER(Measurement)]
        self.dll.lab_measure.restype = ct.c_int
        self.dll.lab_close.argtypes = []
        self.dll.lab_close.restype = None
        status = self.dll.lab_init(secret, len(secret), work, cpu)
        if status:
            raise RuntimeError(f'Native initialization failed ({status}): '
                               '1=length, 2=RDTSCP, 3=invariant TSC, 4=QPC, 5=affinity, 6=password alphabet')

    def check(self, guess, mode):
        return bool(self.dll.lab_check(guess, len(guess), mode))

    def measure(self, guess, mode, batch):
        result = Measurement()
        status = self.dll.lab_measure(guess, len(guess), mode, batch, ct.byref(result))
        if status:
            raise RuntimeError(f'Native measurement failed ({status})')
        return result

    def close(self):
        self.dll.lab_close()


def recover(measure, alphabet, length, samples, batch, rng, metric, writer):
    prefix = b''
    sentinel = next(bytes([i]) for i in range(256) if i not in alphabet)
    trace = []
    for position in range(length):
        guesses = {c: prefix + bytes([c]) + sentinel*(length-position-1) for c in alphabet}
        scores = {c: [] for c in alphabet}
        for guess in guesses.values():
            for _ in range(20):
                measure(guess, batch)
        for sample in range(samples):
            order = list(alphabet)
            rng.shuffle(order)
            for c in order:
                result = measure(guesses[c], batch)
                migrated = result.aux_start != result.aux_end
                writer.writerow([position, sample, guesses[c].hex(), chr(c), batch,
                                 result.wall_ns, result.tsc_ticks, result.thread_cycles,
                                 result.aux_start, result.aux_end, int(migrated)])
                if not migrated:
                    scores[c].append(getattr(result, metric)/batch)
        if any(not values for values in scores.values()):
            raise RuntimeError('No usable measurements for a candidate; inspect migration flags')
        ranking = sorted(alphabet, key=lambda c: statistics.median(scores[c]), reverse=True)
        trace.append({chr(c): statistics.median(scores[c]) for c in ranking})
        prefix += bytes([ranking[0]])
        print(f'Position {position}: {chr(ranking[0])!r}; median {trace[-1][chr(ranking[0])]:.2f} {metric}/call')
    return prefix, trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secret', default='cabd')
    parser.add_argument('--alphabet', default=DEFAULT_ALPHABET)
    parser.add_argument('--mode', choices=['vulnerable', 'constant'], default='vulnerable')
    parser.add_argument('--work', type=int, default=0)
    parser.add_argument('--samples', type=int, default=200)
    parser.add_argument('--batch', type=int, default=1000)
    parser.add_argument('--cpu', type=int, default=-1, help='logical CPU in current Windows processor group; -1 leaves affinity unchanged')
    parser.add_argument('--metric', choices=['tsc_ticks', 'wall_ns', 'thread_cycles'], default='tsc_ticks')
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--output', default='results/native')
    args = parser.parse_args()
    try:
        secret, alphabet = args.secret.encode('ascii'), args.alphabet.encode('ascii')
    except UnicodeEncodeError:
        parser.error('use ASCII')
    try:
        validate_secret(secret)
        validate_alphabet(alphabet)
    except ValueError as error:
        parser.error(str(error))
    if (any(c not in alphabet for c in secret) or
            not 0 <= args.work <= 1000000 or not 1 <= args.batch <= 1000000 or
            args.samples < 1 or args.cpu < -1):
        parser.error('invalid secret/alphabet or measurement parameters')
    root = Path(__file__).resolve().parent
    output = (root / args.output).resolve()
    if not output.is_relative_to(root):
        parser.error('output must stay inside VIP')
    output.mkdir(parents=True, exist_ok=True)
    lab = NativeLab(secret, args.work, args.cpu)
    mode = int(args.mode == 'constant')
    try:
        # Baseline is reported separately, never blindly subtracted.
        baselines = [lab.measure(secret, 2, args.batch) for _ in range(100)]
        with (output / 'measurements.csv').open('w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['position', 'sample', 'candidate_hex', 'tested_character',
                             'batch', 'wall_ns_total', 'tsc_ticks_total', 'thread_cycles_total',
                             'aux_start', 'aux_end', 'endpoint_migration'])
            guess, trace = recover(lambda guess, batch: lab.measure(guess, mode, batch),
                                   alphabet, len(secret), args.samples, args.batch,
                                   random.Random(args.seed), args.metric, writer)
        summary = {**vars(args), 'secret': '[synthetic secret omitted]',
                   'platform': platform.platform(), 'python': platform.python_version(),
                   'guess': guess.decode('ascii'), 'success': lab.check(guess, mode),
                   'median_scores_per_call': trace,
                   'baseline': [{name: getattr(r, name) for name, _ in Measurement._fields_}
                                for r in baselines]}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2))
        print(f'Guess: {summary["guess"]}; verified: {summary["success"]}')
    finally:
        lab.close()


if __name__ == '__main__':
    main()
