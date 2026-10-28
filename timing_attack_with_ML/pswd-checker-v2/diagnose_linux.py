"""Known-prefix diagnostic, not a blind attack or an automatic leakage verdict."""
import argparse
import csv
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time

from experiment_schema import LINUX, native_backend, schema_for
from research_pipeline import digest, now, output_path, save, schema_metadata, sources
from timing_model import quantile

SECRET = b'a0z9b1y8'
MODES = {'naive': 0, 'control': 1, 'empty': 2}


def draw_distributions(observations, output, length):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    schema = schema_for(LINUX)
    labels = ('TSC reference ticks / call', 'Elapsed ns / call', 'Thread CPU ns / call')
    fig, axes = plt.subplots(3, 3, figsize=(14, 10), constrained_layout=True)
    for row, mode in enumerate(MODES):
        for column, metric in enumerate(schema['metrics']):
            ax = axes[row, column]
            values = [[r[metric] for r in observations if r['mode'] == mode and r['prefix'] == p]
                      for p in range(length + 1)]
            ax.boxplot(values, positions=list(range(length + 1)), showfliers=True)
            ax.set(title=f'{mode}: {labels[column]}', xlabel='Matching prefix length', ylabel=labels[column])
            if metric == 'wall_ns':
                # Keep scheduler outliers visible without flattening the central distribution.
                ax.set_yscale('log')
                ax.set_ylabel(labels[column] + ' (log scale)')
            ax.grid(axis='y', alpha=.25)
    fig.suptitle('Equal-length known-prefix diagnostic; observations are batch averages\n'
                 'Boxes show retained rounds; endpoint migrations are kept in raw.csv and excluded here.')
    fig.savefig(output / 'distributions.svg')
    fig.savefig(output / 'distributions.png', dpi=150)
    plt.close(fig)


def diagnose(args):
    if native_backend() != LINUX:
        raise RuntimeError('Run this diagnostic on Linux x86-64.')
    if args.rounds < 4 or not 1 <= args.batch <= 1000000 or args.cpu < -1:
        raise ValueError('require rounds >= 4, batch 1–1000000, cpu >= -1')
    # Fail before making any observations if the plotting dependency is missing.
    try:
        import matplotlib  # noqa: F401
    except ImportError as error:
        raise RuntimeError('Plots require matplotlib. In your project venv run: '
                           'python3 -m pip install matplotlib') from error
    from native_attack import NativeLab
    output = output_path(args.output)
    if output.exists():
        raise ValueError('choose a new diagnostic output directory; previous runs are preserved')
    schema = schema_for(LINUX)
    hashes = {**sources(), 'diagnose_linux.py': digest(Path(__file__))}
    allowed = sorted(os.sched_getaffinity(0))
    lab = NativeLab(SECRET, 0, args.cpu)
    observations, counts = [], {'timed_checker_calls': 0, 'warmup_checker_calls': 0,
                                'verification_calls': 0, 'excluded_checker_calls': 0}
    rng = random.Random(args.seed)
    guesses = [SECRET[:p] + b'!' * (len(SECRET) - p) for p in range(len(SECRET) + 1)]
    started = time.perf_counter()
    try:
        output.mkdir(parents=True)
        config = {**schema_metadata(schema), 'created_utc': now(), 'hostname': platform.node(),
                  'platform': platform.platform(), 'python': platform.python_version(),
                  'matplotlib': matplotlib.__version__,
                  'cpu': args.cpu, 'allowed_cpus_before': allowed,
                  'affinity_during': sorted(os.sched_getaffinity(0)),
                  'rounds': args.rounds, 'batch': args.batch, 'seed': args.seed, 'work': 0,
                  'known_diagnostic_secret': SECRET.decode(), 'source_sha256': hashes,
                  'clock_resolution_ns': {
                      'wall': time.clock_getres(time.CLOCK_MONOTONIC_RAW) * 1e9,
                      'thread_cpu': time.clock_getres(time.CLOCK_THREAD_CPUTIME_ID) * 1e9}}
        save(output / 'config.json', config)
        for mode in (0, 1):
            candidates = [(SECRET, True)] + [(g, False) for g in guesses[:-1]]
            candidates += [(SECRET[:-1], False), (SECRET + b'a', False)]
            for guess, expected in candidates:
                counts['verification_calls'] += 1
                if lab.check(guess, mode) != expected:
                    raise RuntimeError(f'functional check failed: mode={mode}, guess={guess!r}')
        with (output / 'raw.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(['kind', 'round', 'mode', 'matching_prefix', 'candidate_hex', 'batch',
                             'wall_ns_total', 'tsc_ticks_total', 'thread_cpu_ns_total',
                             'aux_start', 'aux_end', 'endpoint_migration', 'status'])
            for round_id in range(-1, args.rounds):
                tasks = [(mode, p) for mode in MODES for p in range(len(guesses))]
                rng.shuffle(tasks)
                for mode, prefix in tasks:
                    kind = 'warmup' if round_id == -1 else 'timed'
                    counts['warmup_checker_calls' if round_id == -1 else 'timed_checker_calls'] += args.batch
                    try:
                        reading = lab.measure(guesses[prefix], MODES[mode], args.batch)
                    except RuntimeError as error:
                        writer.writerow([kind, round_id, mode, prefix, guesses[prefix].hex(), args.batch,
                                         '', '', '', '', '', '', str(error)])
                        raise
                    migrated = reading.aux_start != reading.aux_end
                    writer.writerow([kind, round_id, mode, prefix, guesses[prefix].hex(), args.batch,
                                     reading.wall_ns, reading.tsc_ticks, reading.thread_cpu_ns,
                                     reading.aux_start, reading.aux_end, int(migrated), 'ok'])
                    if migrated:
                        counts['excluded_checker_calls'] += args.batch
                    if round_id >= 0 and not migrated:
                        observations.append({'round': round_id, 'mode': mode, 'prefix': prefix,
                                             **{m: getattr(reading, m) / args.batch for m in schema['metrics']}})
    finally:
        lab.close()
    counts['total_checker_calls'] = sum(counts[k] for k in
                                       ('timed_checker_calls', 'warmup_checker_calls', 'verification_calls'))
    grouped = []
    for mode in MODES:
        for prefix in range(len(guesses)):
            rows = [r for r in observations if r['mode'] == mode and r['prefix'] == prefix]
            group = {'mode': mode, 'matching_prefix': prefix, 'retained_rounds': len(rows)}
            if rows:
                group.update({m: {'q10': quantile([r[m] for r in rows], .1),
                                  'median': statistics.median(r[m] for r in rows),
                                  'q90': quantile([r[m] for r in rows], .9)}
                              for m in schema['metrics']})
            grouped.append(group)
    report = {**config, 'finished_utc': now(), 'elapsed_seconds': time.perf_counter() - started,
              'functional_checks_passed': True, 'affinity_restored': sorted(os.sched_getaffinity(0)) == allowed,
              'counts': counts, 'summary': grouped, 'raw_sha256': digest(output / 'raw.csv'),
              'interpretation': 'Inspect distributions across fresh runs; no automatic claim of leakage or constant time.'}
    save(output / 'report.json', report)
    draw_distributions(observations, output, len(SECRET))
    try:
        assembly = subprocess.check_output(['objdump', '-d', '--no-show-raw-insn',
                                           str(Path(__file__).with_name('native_linux.so'))], text=True)
        (output / 'disassembly.txt').write_text(assembly, encoding='utf-8')
    except (OSError, subprocess.CalledProcessError):
        assembly = None
    lines = ['# Linux known-prefix diagnostic', '',
             f'Host: `{platform.node()}`; CPU: `{args.cpu}`; batch: `{args.batch}`; rounds: `{args.rounds}`.',
             f'Functional checks passed. Original affinity restored: **{report["affinity_restored"]}**.',
             f'Total checker calls: **{counts["total_checker_calls"]:,}**, including warmup, empty baseline and checks.',
             f'Endpoint-migration calls retained in raw data but excluded from features: **{counts["excluded_checker_calls"]:,}**.', '',
             '![Known-prefix distributions](distributions.svg)', '',
             '## Read before training', '',
             '- Every guess has eight bytes. Prefix 8 is the complete correct guess; prefix 7 mismatches at the last byte.',
             '- Each plotted point summarizes one batch, not 1,000 independent observations.',
             '- Compare repeated prefix-dependent changes in the naive checker against the control and empty baseline.',
             '- TSC reference ticks, wall time and thread CPU time measure different intervals and include different overhead.',
             '- Volatile secret reads preserve the inherited lab comparator; this is not a claim about ordinary production comparisons.',
             '- Equal endpoint signatures cannot exclude migration away and back. Affinity does not eliminate interrupts or SMT interference.',
             '- Repeat with a fresh directory and seed. Weak or inconsistent separation is a result to investigate, not a reason to add delay.',
             '- Review compiled `vulnerable`, `fixed_work`, and `lab_measure`: early exit, fixed loop, repeated native calls, and no added workload.',
             '- Proceed to the integration pilot only after reviewing both diagnostic runs.', '',
             f'Assembly: {"`disassembly.txt`" if assembly else "run objdump -d native_linux.so manually"}.',
             'Return `REPORT.md`, `report.json`, `distributions.png`, and both runs’ output paths. Keep `raw.csv` and `config.json`.']
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Report: {output / "REPORT.md"}; total checker calls={counts["total_checker_calls"]:,}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--rounds', type=int, default=100)
    parser.add_argument('--batch', type=int, default=1000)
    parser.add_argument('--cpu', type=int, default=-1)
    parser.add_argument('--seed', type=int, default=20261027)
    args = parser.parse_args()
    try:
        diagnose(args)
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()
